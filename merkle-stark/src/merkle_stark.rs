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

// impl<F: RichField + Extendable<D>, const D: usize> CtlStark for Merkle5Stark<F, D> {
// 	fn new() -> Self {
// 		let tree_stark = Tree5Stark::new();
// 		let sha2_stark = Sha2CompressionStark::new();
// 		Merkle5Stark { tree_stark, sha2_stark }
// 	}

// 	fn num_tables(&self) -> usize {
// 		2
// 	}

// 	fn get_table_descriptors(&self) -> Vec<CtlTableDescriptor> {
// 		let hash_ctl_descriptor = CtlTableDescriptor {
// 			tid: HASH_TID,
// 			looked_cols: (0..8).map(|out_word_idx| CtlColumn::new(
				
// 			)
// 				col: sha2_layout::output_i(out_word_idx),
// 				filter_col: Some(sha2_layout::OUTPUT_FILTER),
// 			}).collect(),
// 			looking_cols: (0..16).map(|input_word_idx| CtlColumn {
// 				col: sha2_layout::input_i(input_word_idx),
// 				filter_col: Some(sha2_layout::INPUT_FILTER),
// 			}).collect(),
// 			looking_
// 		};

// 	}
// }