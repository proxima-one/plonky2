#[cfg(target_arch = "x86_64")]
use jemallocator::Jemalloc;
use log::{Level, LevelFilter};
use plonky2::hash::hash_types::BytesHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use starky2::{
    config::StarkConfig,
    prover::prove_no_ctl,
    starky2lib::sha2_compression::{Sha2CompressionStark, Sha2StarkCompressor},
    util::to_u32_array_be,
    verifier::verify_stark_proof_no_ctl,
};

#[cfg(target_arch = "x86_64")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

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
    // config.fri_config.cap_height = 4;
    // config.fri_config.rate_bits = 3;
    // config.fri_config.num_query_rounds = 30;

    let stark = S::new();
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing).unwrap();
    timing.print();

    let proof_bytes = serde_json::to_vec(&proof.proof.opening_proof).unwrap();
    println!("Proof size: {} bytes", proof_bytes.len());

    verify_stark_proof_no_ctl(&stark, &proof, &config).unwrap();
}
