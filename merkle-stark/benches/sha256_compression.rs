use log::{Level, LevelFilter};
use merkle_stark::{
    config::StarkConfig,
    prover::prove,
    sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor},
    verifier::verify_stark_proof,
};
use plonky2::hash::hash_types::BytesHash;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = Sha2CompressionStark<F, D>;

const NUM_HASHES: usize = 15;

fn bench_sha256_x16(c: &mut Criterion) {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    let mut compressor = Sha2StarkCompressor::new();
    for _ in 0..NUM_HASHES {
        let left = BytesHash::<32>::rand().0;
        let right = BytesHash::<32>::rand().0;

        compressor.add_instance(left, right);
    }

    let trace = compressor.generate();

    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.cap_height = 4;

    let stark = S::new();

    let mut timing = TimingTree::default();
	c.bench_function("sha256_compress_x16", |b| {
		b.iter_batched(|| trace.clone(), |trace| {
			prove::<F, C, S, D>(stark, &config, trace, [], &mut timing).unwrap();
		}, criterion::BatchSize::LargeInput);
	});
}

criterion_group!(benches, bench_sha256_x16);
criterion_main!(benches);
