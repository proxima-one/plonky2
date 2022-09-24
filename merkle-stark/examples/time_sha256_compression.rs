use log::{Level, LevelFilter, debug};
use merkle_stark::{
    config::StarkConfig,
    prover::prove,
    sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor},
    verifier::verify_stark_proof, util::to_u32_array_be, stark::Stark,
};
use plonky2::hash::hash_types::BytesHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

const NUM_HASHES: usize = 63;

fn main() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    let mut compressor = Sha2StarkCompressor::new();
    for _ in 0..NUM_HASHES {
        let left = to_u32_array_be::<8>(BytesHash::<32>::rand().0);
        let right = to_u32_array_be::<8>(BytesHash::<32>::rand().0);

        compressor.add_instance(left, right);
    }

    let trace = compressor.generate();

    let config = StarkConfig::standard_fast_config();

    debug!("Num Columns: {}", S::COLUMNS);
    let stark = S::new();
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    verify_stark_proof(stark, proof, &config).unwrap();
    timing.print();
}

