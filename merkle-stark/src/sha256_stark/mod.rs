use std::marker::PhantomData;

use plonky2::{field::{extension::{Extendable, FieldExtension}, packed::PackedField}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};

use crate::{stark::Stark, vars::{StarkEvaluationVars, StarkEvaluationTargets}, constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer}};

pub mod constants;
pub mod layout;
pub mod constraints;
pub mod generation;

use constraints::{eval_phase_0, eval_phase_1, eval_phase_2, eval_phase_3, eval_msg_schedule, eval_round_fn, eval_phase_transitions, eval_shift_wis, eval_bits_are_bits};
use layout::NUM_COLS;

pub struct Sha2CompressionStark<F: RichField + Extendable<D>, const D: usize>{
	_phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for Sha2CompressionStark<F, D> {
    const COLUMNS: usize = NUM_COLS;
    const PUBLIC_INPUTS: usize = 0;

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

        eval_phase_0(curr_row, next_row, yield_constr);
		eval_phase_1(curr_row, next_row, yield_constr);
		eval_phase_2(curr_row, next_row, yield_constr);
		eval_phase_3(curr_row, next_row, yield_constr);

		eval_phase_transitions(curr_row, next_row, yield_constr);

		eval_msg_schedule(curr_row, next_row, yield_constr);
		eval_round_fn(curr_row, next_row, yield_constr);

		eval_shift_wis(curr_row, next_row, yield_constr);
		eval_bits_are_bits(curr_row, next_row, yield_constr);
    }

	fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
		todo!()
	}

	fn constraint_degree(&self) -> usize {
        3
    }
}