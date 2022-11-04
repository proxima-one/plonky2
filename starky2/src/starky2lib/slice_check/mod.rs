mod layout;
mod generation;

use plonky2::field::{
	types::PrimeField64,
	polynomial::PolynomialValues,
	extension::{Extendable, FieldExtension},
	packed::{PackedField},
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::ext_target::ExtensionTarget;
use core::marker::PhantomData;
use core::borrow::Borrow;

use layout::*;
use crate::stark::Stark;
use crate::starky2lib::gadgets::{ConstraintConsumerFiltered, RecursiveConstraintConsumerFiltered, Starky2ConstraintConsumer, RecursiveStarky2ConstraintConsumer};
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
				let mut curr_row: &SliceCheckRow<P, $n> = vars.local_values.borrow();
				let mut next_row: &SliceCheckRow<P, $n> = vars.next_values.borrow();

				// count starts at 0
				yield_constr.constraint_first_row(curr_row.count);

				// slice filters are binary and mutually exclusive
				yield_constr.mutually_exclusive_binary_check(&curr_row.slice_filters);

				// addresses increment by 1 each row unless one of the filters is set next row
				let filter = next_row.slice_filters.iter().copied().sum::<P>();
				yield_constr.constraint_transition_filtered(next_row.left_addr - curr_row.left_addr - P::ONES, filter);
				yield_constr.constraint_transition_filtered(next_row.right_addr - curr_row.right_addr - P::ONES, filter);
			}

            fn eval_ext_circuit(
                &self,
                builder: &mut CircuitBuilder<F, D>,
                vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut RecursiveConstraintConsumer<F, D>,
            ) {
				let mut curr_row: &SliceCheckRow<ExtensionTarget<D>, $n> = vars.local_values.borrow();
				let mut next_row: &SliceCheckRow<ExtensionTarget<D>, $n> = vars.next_values.borrow();

				// count starts at 0
				yield_constr.constraint_first_row(builder, curr_row.count);

				// slice filters are binary and mutually exclusive
				yield_constr.mutually_exclusive_binary_check(builder, &curr_row.slice_filters);

				// addresses increment by 1 each row unless one of the filters is set next row
				let filter = next_row.slice_filters.iter().fold(builder.one_extension(), |acc, &c| builder.add_extension(acc, c));

				let one = builder.one_extension();
				let c = builder.sub_extension(next_row.left_addr, curr_row.left_addr);
				let c = builder.sub_extension(c, one);
				yield_constr.constraint_transition_filtered(builder, c, filter);

				let c = builder.sub_extension(next_row.right_addr, curr_row.right_addr);
				let c = builder.sub_extension(c, one);
				yield_constr.constraint_transition_filtered(builder, c, filter);
			}

			fn constraint_degree(&self) -> usize {
				3
			}
		}
	};
}

impl_slice_check_stark_n_channels!(1);