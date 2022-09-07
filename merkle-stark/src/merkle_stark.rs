use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::field::polynomial::PolynomialValues;
use anyhow::{anyhow, Result};

use crate::config::StarkConfig;
use crate::get_challenges::{start_all_proof_challenger, get_ctl_challenges_by_table};
use crate::stark::Stark;
use crate::all_stark::{AllProof, AllStark, CtlStark};
use crate::cross_table_lookup::{CtlDescriptor, TableID, CtlColumn, get_ctl_data};
use crate::prover::{start_all_proof, prove_single_table};
use crate::tree_stark::Tree5Stark;
use crate::tree_stark::layout as tree_layout;
use crate::sha256_stark::Sha2CompressionStark;
use crate::sha256_stark::layout as sha2_layout;

pub const TREE_TID: TableID = TableID(0);
pub const HASH_TID: TableID = TableID(1);


/// A stark that computes a depth-5 Merkle Tree.
pub struct Merkle5Stark<F: RichField + Extendable<D>, const D: usize> {
	tree_stark: Tree5Stark<F, D>,
	sha2_stark: Sha2CompressionStark<F, D>,
}

impl<F: RichField + Extendable<D>, const D: usize> CtlStark for Merkle5Stark<F, D> {
	fn new() -> Self {
		let tree_stark = Tree5Stark::new();
		let sha2_stark = Sha2CompressionStark::new();
		Merkle5Stark { tree_stark, sha2_stark }
	}

	fn num_tables(&self) -> usize {
		2
	}

	fn get_ctl_descriptor(&self) -> CtlDescriptor {
		let instances = (0..8).map(|i| (
			CtlColumn::new(TREE_TID, tree_layout::hash_output_word(i), Some(tree_layout::OUTPUT_FILTER)),
			CtlColumn::new(HASH_TID, sha2_layout::output_i(i), Some(sha2_layout::OUTPUT_FILTER)),
		));

		let instances = instances.chain(
			(0..16).map(|i| (
				CtlColumn::new(HASH_TID, sha2_layout::input_i(i), Some(sha2_layout::INPUT_FILTER)),
				if i < 8 {
					CtlColumn::new(TREE_TID, tree_layout::hash_input_0_word(i), Some(tree_layout::INPUT_FILTER))
				} else {
					CtlColumn::new(TREE_TID, tree_layout::hash_input_1_word(i - 8), Some(tree_layout::INPUT_FILTER))
				}
			))
		).collect();

		CtlDescriptor::from_instances(instances)
	}
}

impl<F, C, const D: usize> AllStark<F, C, D> for Merkle5Stark<F, D>
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

	fn prove(&self, starks: &Self::Starks, config: &crate::config::StarkConfig, trace_poly_valueses: &[Vec<PolynomialValues<F>>], public_inputses: &[Vec<F>], timing: &mut plonky2::util::timing::TimingTree) -> Result<AllProof<F, C, D>> {
		debug_assert!(public_inputses.len() == self.num_tables(), "public_inputses must have the same length as the number of tables");
		debug_assert!(trace_poly_valueses.len() == self.num_tables(), "trace_poly_valueses must have the same length as the number of tables");

		let (trace_commitments, mut challenger) = start_all_proof::<F, C, D>(config, trace_poly_valueses, timing)?;

		let ctl_descriptor = self.get_ctl_descriptor();
		let ctl_data = get_ctl_data::<F, C, D>(config, trace_poly_valueses, &ctl_descriptor, &mut challenger);

		let mut proofs = Vec::with_capacity(trace_poly_valueses.len());

		let stark = &starks.0;
		let pis = public_inputses[0].clone().try_into().map_err(|v: Vec<F>| anyhow!("tree stark expected {} public inputs, got {} instead", Tree5Stark::<F, D>::PUBLIC_INPUTS, v.len()))?;
		let proof = prove_single_table(stark, config, &trace_poly_valueses[0], &trace_commitments[0], Some(&ctl_data.by_table[0]), pis, &mut challenger, timing)?;
		proofs.push(proof);

		let stark = &starks.1;
		let pis = public_inputses[1].clone().try_into().map_err(|v: Vec<F>| anyhow!("tree stark expected {} public inputs, got {} instead", Tree5Stark::<F, D>::PUBLIC_INPUTS, v.len()))?;
		let proof = prove_single_table(stark, config, &trace_poly_valueses[1], &trace_commitments[1], Some(&ctl_data.by_table[1]), pis, &mut challenger, timing)?;
		proofs.push(proof);

		Ok(AllProof { proofs })
	}

	fn verify(&self, starks: &Self::Starks, config: &StarkConfig, proof: &AllProof<F, C, D>) -> anyhow::Result<()> {
		let mut challenger = start_all_proof_challenger::<F, C, _, D>(
			proof.proofs.iter().map(|proof| &proof.proof.trace_cap)
		);

		let num_tables = self.num_tables();
		let num_challenges = config.num_challenges;

		let ctl_descriptor = self.get_ctl_descriptor();
		let ctl_challenges = get_ctl_challenges_by_table::<F, C, D>(&mut challenger, ctl_descriptor, num_tables, num_challenges);

		// TODO: CtlCheckVars::from_proofs
		// TODO: verify_single_table
		todo!()
	}
}