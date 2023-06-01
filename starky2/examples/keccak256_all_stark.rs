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
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::types::Field;
use starky2::all_stark::{AllProof, AllStark};
use starky2::config::StarkConfig;
use starky2::cross_table_lookup::{
    get_ctl_data, verify_cross_table_lookups, CtlCheckVars, CtlColSet, CtlDescriptor, TableID,
};
use starky2::get_challenges::{get_ctl_challenges_by_table, start_all_proof_challenger};
use starky2::prover::{prove_single_table, start_all_proof};
use starky2::starky2lib::keccak256_sponge::generation::Keccak256SpongeGenerator;
use starky2::starky2lib::keccak256_sponge::layout::{
    curr_state_capacity_start_col, curr_state_rate_start_col, input_block_start_col,
    new_state_start_col, xored_state_rate_start_col,
};
use starky2::starky2lib::keccak256_sponge::{
    layout as sponge_layout, layout::KECCAK_CAPACITY_U32S, layout::KECCAK_RATE_U32S,
    layout::KECCAK_WIDTH_U32S, Keccak256SpongeStark,
};
use starky2::starky2lib::keccak_f::{keccak_stark::KeccakStark, layout as permutation_layout};
use starky2::starky2lib::xor::layout::XorLayout;
use starky2::starky2lib::xor::{generation::XorGenerator, XorStark};
use starky2::verifier::verify_stark_proof_with_ctl;

const SPONGE_TID: TableID = TableID(0);
const PERMUTATION_TID: TableID = TableID(1);
const XOR_TID: TableID = TableID(2);

/// A STARK that performs keccak256 hashes
struct Keccak256Stark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
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

struct KeccakAllStarkWitness<F: Field> {
    traces: Vec<Vec<PolynomialValues<F>>>,
    // ! no public inputs here
}

fn generate<F: RichField + Extendable<D>, const D: usize>(
    messages: Vec<Vec<u8>>,
) -> Result<KeccakAllStarkWitness<F>> {
    let mut sponge_generator = Keccak256SpongeGenerator::<F>::new();
    let mut xor_generator = XorGenerator::<F, 32, 34>::new();
    let mut keccak_f_inputs = Vec::new();
    for msg in messages.iter() {
        let (_id, _hash, permutation_trace, xor_trace) = sponge_generator.gen_hash_with_trace(msg);

        for [block, state_rate] in xor_trace {
            for i in 0..KECCAK_RATE_U32S {
                xor_generator.gen_op(block[i] as u64, state_rate[i] as u64, i);
            }
        }

        let permutation_inputs_u64 = permutation_trace.into_iter().map(|input_u32s| {
            let mut input = [0u64; KECCAK_WIDTH_U32S / 2];
            for (i, chunk) in input_u32s.chunks_exact(2).enumerate() {
                let lo = chunk[0] as u64;
                let hi = chunk[1] as u64;
                input[i] = lo | (hi << 32);
            }

            input
        });

        keccak_f_inputs.extend(permutation_inputs_u64)
    }

    let permutation_generator = KeccakStark::<F, D>::new();

    let mut timing = TimingTree::default();
    let sponge_trace = sponge_generator.into_polynomial_values();
    let permutation_trace = permutation_generator.generate_trace(keccak_f_inputs, &mut timing);
    let xor_trace = xor_generator.into_polynomial_values();

    Ok(KeccakAllStarkWitness {
        traces: vec![sponge_trace, permutation_trace, xor_trace],
    })
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> AllStark<F, C, D>
    for Keccak256Stark<F, C, D>
{
    fn num_starks() -> usize {
        3
    }

    fn get_ctl_descriptor(&self) -> CtlDescriptor {
        // sponge looks up inputs and output from xor
        let instances = sponge_layout::xor_ctl_cols_a(SPONGE_TID)
            .zip(XorLayout::<F, 32, 34>::ctl_cols_a(XOR_TID));
        let instances = instances.chain(
            sponge_layout::xor_ctl_cols_b(SPONGE_TID)
                .zip(XorLayout::<F, 32, 34>::ctl_cols_b(XOR_TID)),
        );
        let instances = instances.chain(
            sponge_layout::xor_ctl_cols_output(SPONGE_TID)
                .zip(XorLayout::<F, 32, 34>::ctl_cols_output(XOR_TID)),
        );

        // sponge looks up xored state from permutation
        let permutation_input_cols = (0..KECCAK_WIDTH_U32S)
            .map(|i| permutation_layout::reg_input_limb(i))
            .collect();
        let instances = instances.chain(sponge_layout::keccak_ctl_col_input(SPONGE_TID).zip(
            std::iter::once(CtlColSet::new(
                PERMUTATION_TID,
                permutation_input_cols,
                Some(permutation_layout::REG_INPUT_FILTER),
            )),
        ));

        // sponge looks up output from permutation
        let permutation_output_cols = (0..KECCAK_WIDTH_U32S)
            .map(|i| permutation_layout::reg_output_limb(i))
            .collect();
        let instances = instances.chain(sponge_layout::keccak_ctl_col_output(SPONGE_TID).zip(
            std::iter::once(CtlColSet::new(
                PERMUTATION_TID,
                permutation_output_cols,
                Some(permutation_layout::REG_OUTPUT_FILTER),
            )),
        ));

        CtlDescriptor::from_instances(instances.collect(), Self::num_starks())
    }

    fn prove(
        &self,
        config: &StarkConfig,
        trace_poly_valueses: &[Vec<PolynomialValues<F>>],
        _public_inputses: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        let (trace_commitments, mut challenger) =
            start_all_proof::<F, C, D>(config, trace_poly_valueses, timing)?;

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
        let proof = prove_single_table(
            &Keccak256SpongeStark::new(),
            config,
            &trace_poly_valueses[SPONGE_TID.0],
            &trace_commitments[SPONGE_TID.0],
            Some(&ctl_data.by_table[SPONGE_TID.0]),
            &[],
            &mut challenger,
            timing,
        )?;
        proofs.push(proof);

        timing.push("prove permutation STARK", Level::Debug);
        let proof = prove_single_table(
            &KeccakStark::new(),
            config,
            &trace_poly_valueses[PERMUTATION_TID.0],
            &trace_commitments[PERMUTATION_TID.0],
            Some(&ctl_data.by_table[PERMUTATION_TID.0]),
            &[],
            &mut challenger,
            timing,
        )?;
        proofs.push(proof);

        timing.push("prove xor STARK", Level::Debug);
        let proof = prove_single_table(
            &XorStark::<F, D, 32, 34>::new(),
            config,
            &trace_poly_valueses[XOR_TID.0],
            &trace_commitments[XOR_TID.0],
            Some(&ctl_data.by_table[XOR_TID.0]),
            &[],
            &mut challenger,
            timing,
        )?;
        proofs.push(proof);

        Ok(AllProof { proofs })
    }

    fn verify(&self, config: &StarkConfig, all_proof: &AllProof<F, C, D>) -> Result<()>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        let mut challenger = start_all_proof_challenger::<F, C, _, D>(
            all_proof.proofs.iter().map(|proof| &proof.proof.trace_cap),
        );

        let num_challenges = config.num_challenges;

        let ctl_descriptor = self.get_ctl_descriptor();
        let (linear_comb_challenges, ctl_challenges) = get_ctl_challenges_by_table::<F, C, D>(
            &mut challenger,
            &ctl_descriptor,
            num_challenges,
        );
        let ctl_vars = CtlCheckVars::from_proofs(
            &all_proof.proofs,
            &ctl_descriptor,
            &linear_comb_challenges,
            &ctl_challenges,
        );

        let proof = &all_proof.proofs[SPONGE_TID.0];
        verify_stark_proof_with_ctl(
            &Keccak256SpongeStark::new(),
            proof,
            &ctl_vars[SPONGE_TID.0],
            &mut challenger,
            config,
        )?;

        let proof = &all_proof.proofs[PERMUTATION_TID.0];
        verify_stark_proof_with_ctl(
            &KeccakStark::new(),
            proof,
            &ctl_vars[PERMUTATION_TID.0],
            &mut challenger,
            config,
        )?;

        let proof = &all_proof.proofs[XOR_TID.0];
        verify_stark_proof_with_ctl(
            &XorStark::<F, D, 32, 34>::new(),
            proof,
            &ctl_vars[XOR_TID.0],
            &mut challenger,
            config,
        )?;

        verify_cross_table_lookups(
            all_proof.proofs.iter().map(|p| &p.proof),
            &ctl_descriptor,
            num_challenges,
        )?;

        Ok(())
    }
}

fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    init_logger();

    // test messages to hash
    let messages = vec![
        // a few single-block ones
        b"i realize the screaming pain".to_vec(),
        // b"hearing loud in my brain".to_vec(),
        // b"but i'm going straight ahead, with the scar".to_vec(),
        // // one multi-block one
        // b"Wasurete shimaeba ii yo kanji-naku nacchae-ba ii
		// 	Surimuita kokoro ni futa o shitanda
		// 	Kizutsuitatte heikidayo mou itami wa nai kara ne
		// 	Sono ashi o hikizuri nagara mo
		// 	Miushinatta, jibun jishin ga
		// 	Oto o tatete, kuzureteitta
		// 	Kizukeba kaze no oto dake ga"
        //     .to_vec(),
    ];


    // make all stark
    let all_stark = Keccak256Stark::<F, C, D>::new();

    // generate witness (traces)
    let KeccakAllStarkWitness { traces } = generate::<F, D>(messages)?;

    // make PI input vector
    // we have 3 starks: sponge, permutation, and XOR
    // sponge has 8 public inputs
    // TODO: compute hash of message encoded as 8 32-bit chunks
    let hash: [F; 8] = todo!();
    let public_inputs = vec![hash.to_vec(), vec![], vec![]];

    // make config and timing tree
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", Level::Debug);

    // prove
    let proof = all_stark.prove(&config, &traces, &public_inputs, &mut timing)?;
    timing.print();

    // verify
    all_stark.verify(&config, &proof)?;
    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}
