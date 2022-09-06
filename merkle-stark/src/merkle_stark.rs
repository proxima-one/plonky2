use plonky2::hash::hash_types::RichField;
use plonky2::field::extension::Extendable;

use crate::all_stark::{AllProof, AllStark, CtlStark};
use crate::cross_table_lookup::{CtlDescriptor, TableID, CtlColumn};
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
