use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merkle_stark::{prover::prove, verifier::verify_stark_proof, config::StarkConfig, stark::Stark, vars::{StarkEvaluationVars, StarkEvaluationTargets}, constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer}, sha256_stark::{Sha2CompressionStark, Sha2StarkCompressor}};
use plonky2::{field::{extension::{Extendable, FieldExtension}, packed::PackedField}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, util::timing::TimingTree};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::hash_types::BytesHash;

pub(crate) fn bench_sha256_compression_stark_prove(c: &mut Criterion) {
	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;
	type S = Sha2CompressionStark<F, D>;

    let mut group = c.benchmark_group(&format!(
		"sha256_compression",
    ));

    group.sample_size(10);
	for num_hashes in [1, 7, 15, 31, 63, 127] {
		group.bench_with_input(BenchmarkId::from_parameter(num_hashes), &num_hashes, |b, _| {
			let mut compressor = Sha2StarkCompressor::new();
			for _ in 0..num_hashes {
				let left = BytesHash::<32>::rand().0;
				let right = BytesHash::<32>::rand().0;

				compressor.add_instance(left, right);
			}

			let trace = compressor.generate();
			let config = StarkConfig::standard_fast_config();
			let stark = S::new();

			b.iter(|| {
				prove::<F, C, S, D>(stark.clone(), &config, trace.clone(), [], &mut TimingTree::default()).unwrap();
			})
		});
	}
}

fn criterion_benchmark(c: &mut Criterion) {
	bench_sha256_compression_stark_prove(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
