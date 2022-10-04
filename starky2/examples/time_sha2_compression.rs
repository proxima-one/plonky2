#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]

use log::{Level, LevelFilter, debug};
use anyhow::Result;
use plonky2_field::extension::Extendable;
use starky2::{
    config::StarkConfig,
    prover::prove_no_ctl,
    table_lib::sha2_compression::{Sha2CompressionStark, Sha2StarkCompressor, util::to_u32_array_be},
    verifier::verify_stark_proof_no_ctl, stark::Stark, proof::StarkProofWithPublicInputs,
    recursive_verifier::{add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target, verify_stark_proof_circuit}
};
use plonky2::{hash::hash_types::{BytesHash, RichField}, plonk::{config::{Hasher, AlgebraicHasher},  circuit_data::CircuitConfig, circuit_builder::CircuitBuilder}, iop::witness::PartialWitness, timed};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

const NUM_HASHES: usize = 126;

fn main() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    let mut compressor = Sha2StarkCompressor::new();
    for _ in 0..NUM_HASHES {
        let left = BytesHash::<32>::rand().0;
        let right = BytesHash::<32>::rand().0;

        compressor.add_instance(to_u32_array_be::<8>(left), to_u32_array_be::<8>(right));
    }

    let trace = compressor.generate();

    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.cap_height = 4;

    let stark = S::new();
    let mut timing = TimingTree::new(format!("prove (cols: {}, rate: {})", trace.len(), 1 << config.fri_config.rate_bits).as_str(), Level::Debug);
    let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing).unwrap();
    timing.print();

    verify_stark_proof_no_ctl(&stark, &proof, &config).unwrap();

    recursive_proof::<F, C, S, C, D>(stark, proof, &config).unwrap(); 
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D> + Copy,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    stark: S,
    inner_proof: StarkProofWithPublicInputs<F, InnerC, D>,
    inner_config: &StarkConfig,
) -> Result<()>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
    [(); C::Hasher::HASH_SIZE]:,
{
    let circuit_config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
    let mut pw = PartialWitness::new();
    let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
    let pt = add_virtual_stark_proof_with_pis(&mut builder, stark, inner_config, degree_bits);

    let zero = builder.zero();
    set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof, zero);

    verify_stark_proof_circuit::<F, InnerC, S, D>(&mut builder, stark, pt, inner_config);
    debug!("Recursive circuit size:");
    builder.print_gate_counts(0);

    let mut timing = TimingTree::new("build recursive circuit", Level::Debug);
    let data = timed!(
        timing,
        "build",
        builder.build::<C>()
    );
    timing.print();

    let mut timing = TimingTree::new("prove recursive circuit", Level::Debug);
    let proof = timed!(
        timing,
        "prove",
        data.prove(pw)?
    );
    timing.print();

    data.verify(proof)
}

fn init_logger() {
    let _ = env_logger::builder().format_timestamp(None).try_init();
}