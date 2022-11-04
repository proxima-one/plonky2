mod layout;
mod generation;

use plonky2::field::{
	types::PrimeField64,
	polynomial::PolynomialValues,
	extension::{Extendable, FieldExtension}
};
use plonky2::hash::hash_types::RichField;
use core::marker::PhantomData;
use core::borrow::Borrow;
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

pub struct SliceCheckStark<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize> {
	_phantom: PhantomData<F>
}


impl<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize> SliceCheckStark<F, D, NUM_CHANNELS> {
	pub fn new() -> SliceCheckStark<F, D, NUM_CHANNELS> {
		SliceCheckStark {
			_phantom: PhantomData
		}
	}
}

macro_rules! impl_slice_check_stark_n_channels {
	($n:expr) => {
		impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for SliceCheckStark<F, D, $n> {
			const COLUMNS: usize = SLICE_CHECK_NUM_COLS_BASE + $n;
			const PUBLIC_INPUTS: usize = 0;
		
			
            fn eval_packed_generic<FE, P, const D2: usize>(
                &self,
                vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut ConstraintConsumer<P>,
            ) where
                FE: FieldExtension<D2, BaseField = F>,
                P: PackedField<Scalar = FE>,
            {
				let mut curr_row: &SliceCheckRow<P> = vars.local_values.borrow();
				let mut next_row: &SliceCheckRow<P> = vars.next_local_values.borrow();

				// count starts at 0
				yield_constr.constraint_first_row(curr_row.count);

				// slice filters are binary and mutually exclusive
				yield_constr.mutually_exclusive_binary_check(&curr_row.slice_filters);

				// addresses increment by 1 each row unless one of the filters is set next row
				let filter = next_row.slice_filters.iter().sum::<P>();
				yield_constr.constraint_transition_filtered(next_row.left_addr - curr_row.left_addr - P::ONES, filter);
				yield_constr.constraint_transition_filtered(next_row.right_addr - curr_row.right_addr - P::ONES, filter);
			}

            fn eval_ext_circuit(
                &self,
                builder: &mut CircuitBuilder<F, D>,
                vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut RecursiveConstraintConsumer<F, D>,
            ) {
				let mut curr_row: &SliceCheckRow<ExtensionTarget<D>> = vars.local_values.borrow();
				let mut next_row: &SliceCheckRow<ExtensionTarget<D>> = vars.next_local_values.borrow();

				// count starts at 0
				yield_constr.constraint_first_row(&mut builder, curr_row.count);

				// slice filters are binary and mutually exclusive
				yield_constr.mutually_exclusive_binary_check(&mut builder, &curr_row.slice_filters);

				// addresses increment by 1 each row unless one of the filters is set next row
				let filter = next_row.slice_filters.iter().sum::<ExtensionTarget<D>>();
				yield_constr.constraint_transition_filtered(&mut builder, next_row.left_addr - curr_row.left_addr - ExtensionTarget::<D>::ONES, filter);
				yield_constr.constraint_transition_filtered(&mut builder, next_row.right_addr - curr_row.right_addr - ExtensionTarget::<D>::ONES, filter);
			}

			fn constraint_degree() -> usize {
				3
			}
		}
	};
}

