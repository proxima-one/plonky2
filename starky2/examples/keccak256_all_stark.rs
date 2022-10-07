#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]

use std::collections::HashSet;
/// Example of a STARK that does keccak256 Hashes using cross-tables lookup between the following sub-starks:
///   - `keccak_f` STARK
///   - `keccak256_sponge` STARK
///   - `xor` STARK
use std::marker::PhantomData;

use anyhow::Result;
use arrayref::array_ref;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky2::all_stark::{AllProof, AllStark, CtlStark};
use starky2::config::StarkConfig;
use starky2::cross_table_lookup::{
    get_ctl_data, verify_cross_table_lookups, CtlCheckVars, CtlColumn, CtlDescriptor, TableID,
};
use starky2::get_challenges::{get_ctl_challenges, start_all_proof_challenger};
use starky2::prover::{prove_single_table, start_all_proof};
use starky2::stark::Stark;
use starky2::starky2lib::keccak256_sponge::generation::Keccak256SpongeGenerator;
use starky2::starky2lib::keccak256_sponge::layout::KECCAK_WIDTH_U32S;
use starky2::starky2lib::keccak256_sponge::{
	layout::KECCAK_RATE_U32S, layout as sponge_layout, Keccak256SpongeStark,
};
use starky2::starky2lib::keccak_f::{
	keccak_stark::KeccakStark, layout as permutation_layout
};
use starky2::starky2lib::xor::layout::XorLayout;
use starky2::starky2lib::xor::{
    XorStark, generation::XorGenerator,
};
use starky2::verifier::verify_stark_proof_with_ctl;

const SPONGE_TID: TableID = TableID(0);
const PERMUTATION_TID: TableID = TableID(1);
const XOR_TID: TableID = TableID(2);

/// A STARK that performs keccak256 hashes
struct  Keccak256Stark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	_phantom: PhantomData<(F, C)>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
	Keccak256Stark<F, C, D>
{
	fn new() -> Self {
		Keccak256Stark {
			_phantom: PhantomData,
		}
	}
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
	CtlStark<F> for Keccak256Stark<F, C, D>
// where
// 	[(); 3 + 2 * KECCAK_RATE_U32S]:,
{
	// TODO: perhaps use GATs in the trait defn so we can borrow data here
	type GenData = Vec<Vec<u8>>;

	fn num_tables(&self) -> usize {
		3
	}

	fn get_ctl_descriptor(&self) -> CtlDescriptor {
		// sponge looks up inputs and output from xor
		let instances = sponge_layout::xor_ctl_cols_a(SPONGE_TID).zip(XorLayout::<F, KECCAK_RATE_U32S>::ctl_cols_a(XOR_TID));
		let instances = instances.chain(
			sponge_layout::xor_ctl_cols_b(SPONGE_TID).zip(XorLayout::<F, KECCAK_RATE_U32S>::ctl_cols_b(XOR_TID))
		);
		let instances = instances.chain(
			sponge_layout::xor_ctl_cols_output(SPONGE_TID).zip(XorLayout::<F, KECCAK_RATE_U32S>::ctl_cols_output(XOR_TID))
		);

		// sponge looks up xored state from permutation
		let instances = instances.chain(
			sponge_layout::keccak_ctl_col_input(SPONGE_TID).zip(
				(0..KECCAK_RATE_U32S).map(|i| {
					CtlColumn::new(
						PERMUTATION_TID,
						permutation_layout::reg_input_limb(i),
						Some(permutation_layout::reg_step(0)),
					)
				})
			)
		);

		// sponge looks up output from permutation
		let instances = instances.chain(
			sponge_layout::keccak_ctl_col_input(SPONGE_TID).zip(
				(0..KECCAK_RATE_U32S).map(|i| {
					CtlColumn::new(
						PERMUTATION_TID,
						permutation_layout::reg_output_limb(i),
						Some(permutation_layout::reg_step(23)),
					)
				})
			)
		).collect();

		CtlDescriptor::from_instances(instances)
	}

	fn generate(
		&self,
		datas: Self::GenData
    ) -> Result<(Vec<Vec<F>>, Vec<Vec<PolynomialValues<F>>>)> {
		let mut sponge_generator = Keccak256SpongeGenerator::<F>::new();
		let mut xor_pairs_seen = HashSet::new();
		let mut keccak_f_inputs = Vec::new();
		for data in datas.iter() {
			let (_id, _hash, state_trace, xored_rate_trace) = sponge_generator.gen_hash_with_trace(data);
		
			let xor_pairs = state_trace.iter().map(|x| *array_ref![x, 0, KECCAK_RATE_U32S]).take(xored_rate_trace.len()).zip(xored_rate_trace.iter().copied());
			xor_pairs_seen.extend(xor_pairs);

			let xored_extended =  xored_rate_trace.into_iter().chain(std::iter::repeat([0u32; KECCAK_RATE_U32S]));
			let keccak_inputs_u64 = state_trace.into_iter().zip(xored_extended).map(|(mut state, xored_rate)| {
				state[..KECCAK_RATE_U32S].copy_from_slice(&xored_rate);

				let mut res = [0u64; sponge_layout::KECCAK_WIDTH_U32S / 2];
				for (i, chunk) in state.chunks_exact(2).enumerate() {
					res[i] = chunk[0] as u64 | ((chunk[1] as u64) << 32);
				}
				res
			});

			keccak_f_inputs.extend(keccak_inputs_u64);
		}

		// rust doesn't like me using the KECCAK_RATE_U32S const here, idk why
		let mut xor_generator = XorGenerator::<F, 34>::new();
		for (a, b) in xor_pairs_seen {
			for i in 0..KECCAK_RATE_U32S {
				xor_generator.gen_op(a[i] as u64, b[i] as u64);
			}
		}

		let permutation_generator = KeccakStark::<F, D>::new();

		let mut timing = TimingTree::default();
		let permutation_trace = permutation_generator.generate_trace(keccak_f_inputs, &mut timing);
		let sponge_trace = sponge_generator.into_polynomial_values();
		let xor_trace = xor_generator.into_polynomial_values();
		
		Ok((Vec::new(), vec![sponge_trace, permutation_trace, xor_trace]))
	}
}

impl<F, C, const D: usize> AllStark<F, C, D> for Keccak256Stark<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); Keccak256SpongeStark::<F, D>::COLUMNS]:,
    [(); Keccak256SpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakStark::<F, D>::COLUMNS]:,
    [(); KeccakStark::<F, D>::PUBLIC_INPUTS]:,
	// why doesn't rust like it when I use the KECCAK_RATE_U32S const here?
    [(); XorStark::<F, D, 34>::COLUMNS]:,
    [(); XorStark::<F, D, 34>::PUBLIC_INPUTS]:,
{
	type Starks = (Keccak256SpongeStark<F, D>, KeccakStark<F, D>, XorStark<F, D, 34>);

	fn get_starks(&self, _config: &StarkConfig) -> Self::Starks {
		let sponge_stark = Keccak256SpongeStark::<F, D>::new();
		let permutation_stark = KeccakStark::<F, D>::new();
		let xor_stark = XorStark::<F, D, 34>::new();
		(sponge_stark, permutation_stark, xor_stark)
	}

	fn prove(
		&self,
		starks: &Self::Starks,
		config: &StarkConfig,
		trace_poly_valueses: &[Vec<PolynomialValues<F>>],
		_public_inputses: &[Vec<F>],
		timing: &mut TimingTree,
	) -> Result<AllProof<F, C, D>> {
		let (trace_commitments, mut challenger)	= start_all_proof::<F, C, D>(config, trace_poly_valueses, timing)?;

        let ctl_descriptor = self.get_ctl_descriptor();
        let ctl_data = timed!(
            timing,
            "get ctl data",
            get_ctl_data::<F, C, D>(
                config,
                trace_poly_valueses,
                &ctl_descriptor,
                &mut challenger,
            )
        );

        let mut proofs = Vec::with_capacity(trace_poly_valueses.len());

		timing.push("prove sponge STARK", Level::Debug);
		let stark = &starks.0;
		let proof = prove_single_table(
			stark,
			config,
			&trace_poly_valueses[SPONGE_TID.0],
			&trace_commitments[SPONGE_TID.0],
			Some(&ctl_data.by_table[SPONGE_TID.0]),
			[],
			&mut challenger,
			timing
		)?;
		proofs.push(proof);

		timing.push("prove permutation STARK", Level::Debug);
		let stark = &starks.1;
		let proof = prove_single_table(
			stark,
			config,
			&trace_poly_valueses[PERMUTATION_TID.0],
			&trace_commitments[PERMUTATION_TID.0],
			Some(&ctl_data.by_table[PERMUTATION_TID.0]),
			[],
			&mut challenger,
			timing
		)?;
		proofs.push(proof);

		timing.push("prove xor STARK", Level::Debug);
		let stark = &starks.2;
		let proof = prove_single_table(
			stark,
			config,
			&trace_poly_valueses[XOR_TID.0],
			&trace_commitments[XOR_TID.0],
			Some(&ctl_data.by_table[XOR_TID.0]),
			[],
			&mut challenger,
			timing
		)?;
		proofs.push(proof);
	
		Ok(AllProof { proofs })
	}

	fn verify(
		&self,
		starks: &Self::Starks,
		config: &StarkConfig,
		all_proof: &AllProof<F, C, D>,
	) -> Result<()> {
		let mut challenger = start_all_proof_challenger::<F, C, _, D>(
			all_proof.proofs.iter().map(|proof| &proof.proof.trace_cap)
		);

		let num_challenges = config.num_challenges;

		let ctl_descriptor = self.get_ctl_descriptor();
		let ctl_challenges = get_ctl_challenges::<F, C, D>(&mut challenger, &ctl_descriptor, num_challenges);
		let ctl_vars = CtlCheckVars::from_proofs(&all_proof.proofs, &ctl_descriptor, &ctl_challenges);

		let stark = &starks.0;
		let proof = &all_proof.proofs[SPONGE_TID.0];
		verify_stark_proof_with_ctl(stark, proof, &ctl_vars[SPONGE_TID.0], &mut challenger, config)?;

		let stark = &starks.1;
		let proof = &all_proof.proofs[PERMUTATION_TID.0];
		verify_stark_proof_with_ctl(stark, proof, &ctl_vars[PERMUTATION_TID.0], &mut challenger, config)?;

		let stark = &starks.2;
		let proof = &all_proof.proofs[XOR_TID.0];
		verify_stark_proof_with_ctl(stark, proof, &ctl_vars[XOR_TID.0], &mut challenger, config)?;

		verify_cross_table_lookups(&ctl_vars, all_proof.proofs.iter().map(|p| &p.proof))?;

		Ok(())
	}

}

fn main() -> Result<()> {
	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

	init_logger();

	let datas = vec![
		// a few single-block ones
		b"i realize the screaming pain".to_vec(),
		b"hearing loud in my brain".to_vec(),
		b"but i'm going straight ahead, with the scar".to_vec(),
		// one multi-block one
		b"Wasurete shimaeba ii yo kanji-naku nacchae-ba ii
			Surimuita kokoro ni futa o shitanda
			Kizutsuitatte heikidayo mou itami wa nai kara ne
			Sono ashi o hikizuri nagara mo
			Miushinatta, jibun jishin ga
			Oto o tatete, kuzureteitta
			Kizukeba kaze no oto dake ga".to_vec()
	];

	let all_stark = Keccak256Stark::<F, C, D>::new();	
	let (public_inputses, trace_poly_valueses) = all_stark.generate(datas)?;

	let config = StarkConfig::standard_fast_config();
	let starks = all_stark.get_starks(&config);

	let mut timing = TimingTree::new("prove", Level::Debug);
	let proof = all_stark.prove(
		&starks,
		&config,
		&trace_poly_valueses,
		&public_inputses,
		&mut timing
	)?;
	timing.print();

	all_stark.verify(&starks, &config, &proof)
}

fn init_logger() {
	let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}