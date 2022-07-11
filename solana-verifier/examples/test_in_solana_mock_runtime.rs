use log::Level;
use plonky2::{
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs, circuit_data::{VerifierOnlyCircuitData, CommonCircuitData, CircuitConfig}, circuit_builder::CircuitBuilder, prover::prove},
    buffer_verifier::{
        verifier::verify,
        circuit_buf::CircuitBuf,
        proof_buf::ProofBuf, serialization::{serialize_circuit_data, serialize_proof_with_pis},
    }, gates::noop::NoopGate, iop::witness::PartialWitness, util::timing::TimingTree
};
use plonky2_field::goldilocks_field::GoldilocksField;
use solana_program::{instruction::{AccountMeta, Instruction}};
use solana_sdk::{
	rent::Rent,
    account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
	account_info::{next_account_info, AccountInfo},
	entrypoint::ProgramResult,
	msg,
	program_error::ProgramError,
	pubkey::Pubkey,
	clock::Epoch, transaction::Transaction, signer::Signer,
	system_instruction,
	system_program, signature::Keypair,
};
use anyhow::{Result, anyhow};
use solana_program_test::{processor, ProgramTest, tokio};

use solana_verifier::process_instruction;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;


type ProofTuple<F, C, const D: usize> = (
	ProofWithPublicInputs<F, C, D>,
	VerifierOnlyCircuitData<C, D>,
	CommonCircuitData<F, C, D>,
);

/// Creates a dummy proof which should have `2 ** log2_size` rows.
fn dummy_proof(
	config: &CircuitConfig,
	log2_size: usize,
) -> Result<ProofTuple<F, C, D>>
{
	// 'size' is in degree, but we want number of noop gates. A non-zero amount of padding will be added and size will be rounded to the next power of two. To hit our target size, we go just under the previous power of two and hope padding is less than half the proof.
	let num_dummy_gates = match log2_size {
		0 => return Err(anyhow!("size must be at least 1")),
		1 => 0,
		2 => 1,
		n => (1 << (n - 1)) + 1,
	};
	
	let mut builder = CircuitBuilder::<F, D>::new(config.clone());
	for _ in 0..num_dummy_gates {
		builder.add_gate(NoopGate, vec![]);
	}
	builder.print_gate_counts(0);

	let data = builder.build::<C>();
	let inputs = PartialWitness::new();

	let mut timing = TimingTree::new("prove", Level::Debug);
	let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
	timing.print();
	data.verify(proof.clone())?;

	Ok((proof, data.verifier_only, data.common))
}

const CIRCUIT_ACCOUNT_LEN: usize = 3000;
const PROOF_ACCOUNT_LEN: usize = 200_000;

#[tokio::main]
async fn main() {
	let program_id = Pubkey::new_unique();
	let mut test_env = ProgramTest::new(
		"solana-plonky2-verifier",
		program_id,
		processor!(process_instruction),
	);
	let (proof, verifier_only_data, common_data) = dummy_proof(&CircuitConfig::default(), 10).unwrap();

	let mut context = test_env.start_with_context().await;

	let mut circuit_bytes = vec![0; CIRCUIT_ACCOUNT_LEN];
	serialize_circuit_data(circuit_bytes.as_mut_slice(), &common_data, &verifier_only_data).expect("failed to serialize circuit data!");
	 
	let mut proof_bytes = vec![0; PROOF_ACCOUNT_LEN];
	serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof).expect("failed to serialize proof!");
	
	let rent = context.banks_client.get_rent().await.unwrap();

	let circuit_account_lamports = rent.minimum_balance(CIRCUIT_ACCOUNT_LEN);
	let proof_account_lamports = rent.minimum_balance(PROOF_ACCOUNT_LEN);

	let circuit_signer = Keypair::new();
	let proof_signer = Keypair::new();

	let circuit_address = circuit_signer.pubkey();
	let proof_address = proof_signer.pubkey();
	// assign ownership over proof account to program
	let insns = vec![
		system_instruction::create_account(
			&context.payer.pubkey(),
			&circuit_address,
			circuit_account_lamports,
			CIRCUIT_ACCOUNT_LEN as u64,
			&program_id
		),
		system_instruction::create_account(
			&context.payer.pubkey(),
			&proof_address,
			proof_account_lamports,
			PROOF_ACCOUNT_LEN as u64,
			&program_id
		),
		system_instruction::assign(
			&circuit_address,
			&program_id,
		),
		system_instruction::assign(
			&proof_address,
			&program_id,
		)
	];

	let blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

	let tx = Transaction::new_signed_with_payer(
		&insns,
		Some(&context.payer.pubkey()),
		&[&context.payer, &proof_signer, &circuit_signer],
		blockhash
	);

	context.banks_client.process_transaction(tx).await.unwrap();

	let proof_account = context.banks_client.get_account(proof_address).await.unwrap().unwrap();
	assert_eq!(proof_account.owner, program_id);

	let circuit_account_data = AccountSharedData::create(
		circuit_account_lamports,
		circuit_bytes,
		program_id,
		false,
		Epoch::default()
	);
	let proof_account_data = AccountSharedData::create(
		proof_account_lamports,
		proof_bytes,
		program_id,
		false,
		Epoch::default()
	);

	context.set_account(&circuit_address, &circuit_account_data);
	context.set_account(&proof_address, &proof_account_data);

	let blockhash = context.banks_client.get_latest_blockhash().await.unwrap();

	// verify proof
	let insns = vec![
		Instruction::new_with_bytes(
			program_id,
			&[0],
			vec![
				AccountMeta::new_readonly(circuit_address, false),
				AccountMeta::new(proof_address, false), 
			]
		)
	];

	let tx = Transaction::new_signed_with_payer(
		&insns,
		Some(&context.payer.pubkey()),
		&[&context.payer],
		blockhash	
	);

	context.banks_client.process_transaction(tx).await.unwrap();
}
