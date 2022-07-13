// HACK: Ideally this would live in `benches/`, but `cargo bench` doesn't allow
// custom CLI argument parsing (even with harness disabled). We could also have
// put it in `src/bin/`, but then we wouldn't have access to
// `[dev-dependencies]`.

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::{fs::File, num::ParseIntError, ops::RangeInclusive, str::FromStr};

use anyhow::{anyhow, Context as _, Result};
use log::{info, Level, LevelFilter};
use plonky2::{
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, Witness},
	fri::reduction_strategies::FriReductionStrategy,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig, KeccakGoldilocksConfig, KeccakSpongeSha256GoldilocksConfig},
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
        prover::prove,
    },
    util::timing::TimingTree, buffer_verifier::{proof_buf::ProofBuf, serialization::serialize_proof_with_pis}, fri::FriConfig,
};
use plonky2_field::extension::Extendable;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use structopt::StructOpt;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, C, D>,
);

/// Creates a dummy proof which should have `2 ** log2_size` rows.
fn dummy_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
) -> Result<ProofTuple<F, C, D>>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    // 'size' is in degree, but we want number of noop gates. A non-zero amount of padding will be added and size will be rounded to the next power of two. To hit our target size, we go just under the previous power of two and hope padding is less than half the proof.
    let num_dummy_gates = (1 << (14 - 1)) + 1;

    info!("Constructing inner proof with {} gates", num_dummy_gates);
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

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner: &ProofTuple<F, InnerC, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let (inner_proof, inner_vd, inner_cd) = inner;
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    let pt = builder.add_virtual_proof_with_pis(inner_cd);
    pw.set_proof_with_pis_target(&pt, inner_proof);

    let inner_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
    };
    pw.set_cap_target(
        &inner_data.constants_sigmas_cap,
        &inner_vd.constants_sigmas_cap,
    );

    builder.verify_proof(pt, &inner_data, inner_cd);
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type OuterC = KeccakSpongeSha256GoldilocksConfig;

    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
	builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;

    let inner_config = CircuitConfig::standard_recursion_config();
	let mut outer_config = CircuitConfig::standard_recursion_config();
	outer_config.security_bits = 96;
	outer_config.fri_config = FriConfig {
		reduction_strategy: FriReductionStrategy::MinSize(None),
		num_query_rounds: 11,
		rate_bits: 7,
		cap_height: 4,
		proof_of_work_bits: 19,
	};

    let (proof, _, common_data)= dummy_proof::<F, C, D>(&outer_config)?;
	let mut proof_bytes = vec![0; 200_000];
	serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof)?;

	let mut proof_buf = ProofBuf::<C, &[u8], D>::new(proof_bytes.as_slice())?;
	info!("Serialized proof: {} bytes", proof_buf.len());

    Ok(())
}
