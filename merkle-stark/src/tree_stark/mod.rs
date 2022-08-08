use std::marker::PhantomData;
use plonky2::field::{polynomial::PolynomialValues, types::Field};
use plonky2::{
    field::{
        extension::{Extendable, FieldExtension},
        packed::PackedField,
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use crate::{
    constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer},
    stark::Stark,
    vars::{StarkEvaluationTargets, StarkEvaluationVars},
};

// pub mod generation;
pub mod layout;

use layout::*;

#[derive(Copy, Clone)]
pub struct MerkleTree5STARK<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> MerkleTree5STARK<F, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}


impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for MerkleTree5STARK<F, D> {
    const COLUMNS: usize = NUM_COLS;
    const PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
		let curr_row = vars.local_values;
		let next_row = vars.next_values;
		let pis = vars.public_inputs;

		// load leaves in at first row
		for i in 0..TREE_WIDTH {
			for word in 0..WORDS_PER_HASH {
				yield_constr.constraint_first_row(
					curr_row[val_i_word(i, word)] - pis[i * WORDS_PER_HASH + word]
				);
			}
		}

		// set depth counter to 0 first row
		yield_constr.constraint_first_row(curr_row[DEPTH_CTR]);

		// compress leftmost two hashes, rotate words left, by two, and 
		
	}


    fn eval_ext_circuit(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
        _vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        _yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}