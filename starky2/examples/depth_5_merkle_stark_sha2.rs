#![feature(generic_const_exprs)]

/// Example of a STARK that builds a depth-5 merkle tree using cross-table lookups

use std::marker::PhantomData;

use anyhow::{anyhow, Result};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::{BytesHash, RichField};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use starky2::all_stark::{AllProof, AllStark, CtlStark};
use starky2::config::StarkConfig;
use starky2::cross_table_lookup::{
    get_ctl_data, verify_cross_table_lookups, CtlCheckVars, CtlColumn, CtlDescriptor, TableID,
};
use starky2::get_challenges::{start_all_proof_challenger, get_ctl_challenges};
use starky2::prover::{prove_single_table, start_all_proof};
use starky2::table_lib::sha2_compression::{layout as sha2_layout, Sha2StarkCompressor, Sha2CompressionStark, util::{compress, to_u32_array_be}};
use starky2::stark::Stark;
use starky2::table_lib::depth_5_merkle_tree::{
    generation::Tree5TraceGenerator,
    layout as tree_layout,
    Tree5Stark, 
};
use starky2::verifier::verify_stark_proof_with_ctl;

const TREE_TID: TableID = TableID(0);
const HASH_TID: TableID = TableID(1);

/// A stark that computes a depth-5 Merkle Tree.
struct Merkle5Stark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    _phantom: PhantomData<(F, C)>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> Merkle5Stark<F, C, D> {
    fn new() -> Self {
        Merkle5Stark {
            _phantom: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> CtlStark<F> for Merkle5Stark<F, C, D> {
    type GenData = [[u32; 8]; tree_layout::TREE_WIDTH];

    fn num_tables(&self) -> usize {
        2
    }

    fn get_ctl_descriptor(&self) -> CtlDescriptor {
        let instances = (0..8).map(|i| {
            (
                CtlColumn::new(
                    TREE_TID,
                    tree_layout::hash_output_word(i),
                    Some(tree_layout::OUTPUT_FILTER),
                ),
                CtlColumn::new(
                    HASH_TID,
                    sha2_layout::output_i(i),
                    Some(sha2_layout::OUTPUT_FILTER),
                ),
            )
        });

        let instances = instances
            .chain((0..16).map(|i| {
                (
                    CtlColumn::new(
                        HASH_TID,
                        sha2_layout::input_i(i),
                        Some(sha2_layout::INPUT_FILTER),
                    ),
                    if i < 8 {
                        CtlColumn::new(
                            TREE_TID,
                            tree_layout::hash_input_0_word(i),
                            Some(tree_layout::INPUT_FILTER),
                        )
                    } else {
                        CtlColumn::new(
                            TREE_TID,
                            tree_layout::hash_input_1_word(i - 8),
                            Some(tree_layout::INPUT_FILTER),
                        )
                    },
                )
            }))
            .collect();

        CtlDescriptor::from_instances(instances)
    }

    fn generate(&self, leaves: Self::GenData) -> Result<(Vec<Vec<F>>, Vec<Vec<PolynomialValues<F>>>)> {
        let mut generator = Tree5TraceGenerator::<F>::new(16, leaves);
        let (_root, root_pis, hash_trace) = generator.gen_with_hash_trace(compress);
        let tree_trace = generator.into_polynomial_values();

        let mut compressor = Sha2StarkCompressor::new();
        for ([left, right], _) in hash_trace {
            compressor.add_instance(left, right)
        }
        let hash_trace = compressor.generate();
        
        Ok((vec![root_pis.to_vec(), vec![]], vec![tree_trace, hash_trace]))
    }
}

impl<F, C, const D: usize> AllStark<F, C, D> for Merkle5Stark<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); Tree5Stark::<F, D>::COLUMNS]:,
    [(); Tree5Stark::<F, D>::PUBLIC_INPUTS]:,
    [(); Sha2CompressionStark::<F, D>::COLUMNS]:,
    [(); Sha2CompressionStark::<F, D>::PUBLIC_INPUTS]:,
{
    type Starks = (Tree5Stark<F, D>, Sha2CompressionStark<F, D>);

    fn get_starks(&self, _config: &StarkConfig) -> Self::Starks {
        let tree_stark = Tree5Stark::<F, D>::new();
        let sha2_stark = Sha2CompressionStark::<F, D>::new();
        (tree_stark, sha2_stark)
    }

    // challenger order:
    // observe trace caps 
    // get ctl challenges
    // get permutation challenges
    // observe permutation zs cap
    // obsreve ctl zs cap
    // sample alphas

    fn prove(
        &self,
        starks: &Self::Starks,
        config: &starky2::config::StarkConfig,
        trace_poly_valueses: &[Vec<PolynomialValues<F>>],
        public_inputses: &[Vec<F>],
        timing: &mut plonky2::util::timing::TimingTree,
    ) -> Result<AllProof<F, C, D>> {
        let (trace_commitments, mut challenger) =
            start_all_proof::<F, C, D>(config, trace_poly_valueses, timing)?;

        let ctl_descriptor = self.get_ctl_descriptor();
        let ctl_data = get_ctl_data::<F, C, D>(
            config,
            trace_poly_valueses,
            &ctl_descriptor,
            &mut challenger,
        );

        let mut proofs = Vec::with_capacity(trace_poly_valueses.len());

        let stark = &starks.0;
        let pis = public_inputses[TREE_TID.0]
            .clone()
            .try_into()
            .map_err(|v: Vec<F>| {
                anyhow!(
                    "tree stark expected {} public inputs, got {} instead",
                    Tree5Stark::<F, D>::PUBLIC_INPUTS,
                    v.len()
                )
            })?;
        
        let proof = prove_single_table(
            stark,
            config,
            &trace_poly_valueses[TREE_TID.0],
            &trace_commitments[TREE_TID.0],
            Some(&ctl_data.by_table[TREE_TID.0]),
            pis,
            &mut challenger,
            timing,
        )?;
        proofs.push(proof);

        let stark = &starks.1;
        let pis = public_inputses[HASH_TID.0]
            .clone()
            .try_into()
            .map_err(|v: Vec<F>| {
                anyhow!(
                    "hash stark expected {} public inputs, got {} instead",
                    Sha2CompressionStark::<F, D>::PUBLIC_INPUTS,
                    v.len()
                )
            })?;
        let proof = prove_single_table(
            stark,
            config,
            &trace_poly_valueses[HASH_TID.0],
            &trace_commitments[HASH_TID.0],
            Some(&ctl_data.by_table[HASH_TID.0]),
            pis,
            &mut challenger,
            timing,
        )?;
        proofs.push(proof);

        Ok(AllProof { proofs })
    }

    fn verify(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        all_proof: &AllProof<F, C, D>,
    ) -> anyhow::Result<()> {
        let mut challenger = start_all_proof_challenger::<F, C, _, D>(
            all_proof.proofs.iter().map(|proof| &proof.proof.trace_cap),
        );

        let num_tables = self.num_tables();
        let num_challenges = config.num_challenges;

        let ctl_descriptor = self.get_ctl_descriptor();
        let ctl_challenges = get_ctl_challenges::<F, C, D>(
            &mut challenger,
            &ctl_descriptor,
            num_challenges,
        );

        let ctl_vars =
            CtlCheckVars::from_proofs(&all_proof.proofs, &ctl_descriptor, &ctl_challenges);

        let stark = &starks.0;
        let proof = &all_proof.proofs[TREE_TID.0];
        verify_stark_proof_with_ctl(stark, proof, &ctl_vars[TREE_TID.0], &mut challenger, config)?;

        let stark = &starks.1;
        let proof = &all_proof.proofs[HASH_TID.0];
        verify_stark_proof_with_ctl(stark, proof, &ctl_vars[HASH_TID.0], &mut challenger, config)?;

        verify_cross_table_lookups(&ctl_vars, all_proof.proofs.iter().map(|p| &p.proof))?;

        Ok(())
    }
}


fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let leaves = [(); 16].map(|_| {
        to_u32_array_be(BytesHash::<32>::rand().0)
    });

    let all_stark = Merkle5Stark::<F, C, D>::new();
    let (public_inputses, trace_poly_valueses) = all_stark.generate(leaves)?;

    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.cap_height = 0;
    let starks = all_stark.get_starks(&config);

    let mut timing = TimingTree::default();
    let proof = all_stark.prove(&starks, &config, &trace_poly_valueses, &public_inputses, &mut timing)?;

    all_stark.verify(&starks, &config, &proof)
}
