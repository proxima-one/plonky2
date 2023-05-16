#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]

/// Example of a STARK that builds a depth-5 merkle tree using cross-table lookups
use std::marker::PhantomData;

use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::{BytesHash, RichField};
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
use starky2::starky2lib::depth_5_merkle_tree::{
    generation::Tree5TraceGenerator, layout as tree_layout, Tree5Stark,
};
use starky2::starky2lib::sha2_compression::{
    layout as sha2_layout, util::compress, Sha2CompressionStark, Sha2StarkCompressor,
};
use starky2::util::to_u32_array_be;
use starky2::verifier::verify_stark_proof_with_ctl;

const TREE_TID: TableID = TableID(0);
const HASH_TID: TableID = TableID(1);

/// A stark that computes a depth-5 Merkle Tree.
struct Merkle5Stark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    _phantom: PhantomData<(F, C)>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    Merkle5Stark<F, C, D>
{
    fn new() -> Self {
        Merkle5Stark {
            _phantom: PhantomData,
        }
    }
}

struct TreeStarkWitness<F: Field> {
    traces: Vec<Vec<PolynomialValues<F>>>,
    public_inputs: Vec<F>,
}

// trace generator
// returns (pis, traces)
fn generate<F: RichField + Extendable<D>, const D: usize>(
    leaves: [[u32; 8]; tree_layout::TREE_WIDTH],
) -> Result<TreeStarkWitness<F>> {
    let mut generator = Tree5TraceGenerator::<F>::new(16, leaves);
    let (_root, root_pis, hash_trace) = generator.gen_with_hash_trace(compress);
    let tree_trace = generator.into_polynomial_values();

    let mut compressor = Sha2StarkCompressor::new();
    for ([left, right], _) in hash_trace {
        compressor.add_instance(left, right)
    }
    let hash_trace = compressor.generate();

    Ok(TreeStarkWitness {
        traces: vec![tree_trace, hash_trace],
        public_inputs: root_pis.to_vec(),
    })
}

impl<F, C, const D: usize> AllStark<F, C, D> for Merkle5Stark<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn num_starks() -> usize {
        2
    }

    fn get_ctl_descriptor(&self) -> CtlDescriptor {
        let mut instances = Vec::new();
        let tree_output_cols = (0..8).map(|i| tree_layout::hash_output_word(i)).collect();
        let sha2_output_cols = (0..8).map(|i| sha2_layout::output_i(i)).collect();

        instances.push((
            CtlColSet::new(TREE_TID, tree_output_cols, Some(tree_layout::OUTPUT_FILTER)),
            CtlColSet::new(HASH_TID, sha2_output_cols, Some(sha2_layout::OUTPUT_FILTER)),
        ));

        let hash_input_cols = (0..16).map(|i| sha2_layout::input_i(i)).collect();
        let tree_input_cols = (0..8)
            .map(|i| tree_layout::hash_input_0_word(i))
            .chain((0..8).map(|i| tree_layout::hash_input_1_word(i)))
            .collect();
        instances.push((
            CtlColSet::new(HASH_TID, hash_input_cols, Some(sha2_layout::INPUT_FILTER)),
            CtlColSet::new(TREE_TID, tree_input_cols, Some(tree_layout::INPUT_FILTER)),
        ));

        CtlDescriptor::from_instances(instances, Self::num_starks())
    }

    fn prove(
        &self,
        config: &StarkConfig,
        traces_evals: &[Vec<PolynomialValues<F>>],
        public_inputs: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        let (trace_commitments, mut challenger) =
            start_all_proof::<F, C, D>(config, traces_evals, timing)?;

        let ctl_descriptor = self.get_ctl_descriptor();

        let ctl_data = timed!(
            timing,
            "get ctl data",
            get_ctl_data::<F, C, D>(config, traces_evals, &ctl_descriptor, &mut challenger,)
        );

        let tree_proof = prove_single_table(
            &Tree5Stark::new(),
            config,
            &traces_evals[TREE_TID.0],
            &trace_commitments[TREE_TID.0],
            Some(&ctl_data.by_table[TREE_TID.0]),
            &public_inputs[TREE_TID.0],
            &mut challenger,
            timing,
        )?;

        let hash_proof = prove_single_table(
            &Sha2CompressionStark::new(),
            config,
            &traces_evals[HASH_TID.0],
            &trace_commitments[HASH_TID.0],
            Some(&ctl_data.by_table[HASH_TID.0]),
            &public_inputs[HASH_TID.0],
            &mut challenger,
            timing,
        )?;

        let proofs = vec![tree_proof, hash_proof];

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

        verify_stark_proof_with_ctl(
            &Tree5Stark::new(),
            &all_proof.proofs[TREE_TID.0],
            &ctl_vars[TREE_TID.0],
            &mut challenger,
            config,
        )?;
        verify_stark_proof_with_ctl(
            &Sha2CompressionStark::new(),
            &all_proof.proofs[HASH_TID.0],
            &ctl_vars[HASH_TID.0],
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

    // setup logs
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    // make all stark
    let all_stark = Merkle5Stark::<F, C, D>::new();

    // get leaves
    let leaves = [(); 16].map(|_| to_u32_array_be(BytesHash::<32>::rand().0));

    // generate witness
    let TreeStarkWitness {
        public_inputs,
        traces,
    } = generate::<F, D>(leaves)?;

    // convert PIs into required format, a vec whose ith element is an inner vec containing PIs for the ith stark
    // tree has PIs, hash doesn't
    let public_inputs = vec![public_inputs.clone(), vec![]];

    // make config and timing tree
    let config = StarkConfig::standard_fast_config();
    let mut timing = TimingTree::new("prove", Level::Debug);

    // prove
    let proof = all_stark.prove(&config, &traces, &public_inputs, &mut timing)?;
    timing.print();

    // verify
    all_stark.verify(&config, &proof)
}
