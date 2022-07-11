use plonky2::{
    plonk::config::PoseidonGoldilocksConfig,
    buffer_verifier::{
        verifier::verify,
        circuit_buf::CircuitBuf,
        proof_buf::ProofBuf,
    }
};
use plonky2_field::goldilocks_field::GoldilocksField;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey, log::sol_log_compute_units,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// Declare and export the program's entrypoint
entrypoint!(process_instruction);

const INVALID_PROOF_ERRNO: u32 = 1;

// Program entrypoint's implementation
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    msg!("solana plonky2 verifier program entrypoint");
    sol_log_compute_units();

    let accounts_iter = &mut accounts.iter();

    // get circuit data account
    let circuit_data_account = next_account_info(accounts_iter)?;

    // The circuit data account must be owned by the program
    if circuit_data_account.owner != program_id {
        msg!("circuit data account is not owned by the program!");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Get proof account
    let proof_account = next_account_info(accounts_iter)?;

    // The proof account must be owned by the progra
    if proof_account.owner != program_id {
        msg!("proof account is not owned by the program!");
        return Err(ProgramError::IncorrectProgramId);
    }

    // make lazy deserialization buffers
    let circuit_data_slice = circuit_data_account.data.borrow();
    let mut circuit_buf = CircuitBuf::<C, &[u8], D>::new(circuit_data_slice.as_ref()).map_err(|e| {
        msg!("failed to construct circuit data deserializer: {}", e);
        ProgramError::InvalidAccountData
    })?;

    let mut proof_slice = proof_account.data.borrow_mut();
    let mut proof_buf = ProofBuf::<C, &mut [u8], D>::new(proof_slice.as_mut()).map_err(|e| {
        msg!("failed to construct proof deserializer: {}", e);
        ProgramError::InvalidAccountData
    })?;


    // verify the proof
    verify(&mut proof_buf, &mut circuit_buf).map_err(|e| {
        msg!("proof verifier rejected: {}", e);
        ProgramError::Custom(INVALID_PROOF_ERRNO)
    })?;

    sol_log_compute_units();
    msg!("proof verifier accepted");

    Ok(())
}

// Sanity tests
#[cfg(test)]
mod test {
    use std::mem;
    use anyhow::{anyhow, Result};
    use log::{info, Level};
    use plonky2::{buffer_verifier::serialization::{serialize_proof_with_pis, serialize_circuit_data}, plonk::{proof::ProofWithPublicInputs, circuit_data::{VerifierOnlyCircuitData, CommonCircuitData, CircuitConfig}, config::GenericConfig, circuit_builder::CircuitBuilder, prover::prove}, hash::hash_types::RichField, gates::noop::NoopGate, iop::witness::PartialWitness, util::timing::TimingTree}; 
    use solana_program::clock::Epoch;


    use super::*;


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


    #[test]
    fn test_sanity() {
        let (proof, verifier_only_data, common_data) = dummy_proof(&CircuitConfig::default(), 10).unwrap();

        let mut circuit_bytes = vec![0; 3000];
        serialize_circuit_data(circuit_bytes.as_mut_slice(), &common_data, &verifier_only_data).expect("failed to serialize circuit data!");
         
        let mut proof_bytes = vec![0; 200_000];
        serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof).expect("failed to serialize proof!");


        let program_id = Pubkey::default();

        let circuit_account_key = Pubkey::default();
        let mut lamports = 0;
        let circuit_account = AccountInfo::new(
            &circuit_account_key,
            false,
            true,
            &mut lamports,
            circuit_bytes.as_mut_slice(),
            &program_id,
            false,
            Epoch::default(),
        );

        let proof_account_key = Pubkey::default();
        let mut lamports = 0;
        let proof_account = AccountInfo::new(
            &proof_account_key,
            false,
            true,
            &mut lamports,
            proof_bytes.as_mut_slice(),
            &program_id,
            false,
            Epoch::default(),
        );

        let instruction_data: Vec<u8> = Vec::new();
        let accounts = vec![circuit_account, proof_account];
        process_instruction(&program_id, &accounts, &instruction_data).unwrap();
    }
}
