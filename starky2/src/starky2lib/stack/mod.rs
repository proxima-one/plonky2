/// STARK that checks the access trace of a stack
/// this can be thought of as a form of "offline memory checking"

use std::borrow::Borrow;
use std::marker::PhantomData;

use plonky2::field::{
    extension::{Extendable, FieldExtension},
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub mod generation;
pub mod layout;

use layout::*;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::lookup::eval_lookups;
use crate::permutation::PermutationPair;
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

pub struct StackStark<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize>
    StackStark<F, D, NUM_CHANNELS>
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

macro_rules! impl_stack_stark_for_n_channels {
    ($channels:expr) => {
        impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D>
            for StackStark<F, D, $channels>
        {
            const COLUMNS: usize = STACK_NUM_COLS_BASE + $channels;
            const PUBLIC_INPUTS: usize = 0;

            fn eval_packed_generic<FE, P, const D2: usize>(
                &self,
                vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut ConstraintConsumer<P>,
            ) where
                FE: FieldExtension<D2, BaseField = F>,
                P: PackedField<Scalar = FE>,
            {
                let curr_row: &StackRow<P, $channels> = vars.local_values.borrow();
                let next_row: &StackRow<P, $channels> = vars.next_values.borrow();

                // MEMORY SEMANTICS

                // check sorted addresses are monotonic, continuous, and start at 0
                // we do this by ensuring either the sorted address increases by 0 or 1 at each curr_row and at the first curr_row, the sorted addr is 0
                // degree 2
                yield_constr.constraint_transition(
                    (next_row.addr_sorted - curr_row.addr_sorted)
                        * (next_row.addr_sorted - curr_row.addr_sorted - P::ONES),
                );
                // degree 1
                yield_constr.constraint_first_row(curr_row.addr_sorted);

                // check timestamps are increasing using a range check
                // this works as follows:
                // 1. we range check every timestamp to be in [1..num_rows].
                // 2. we range check the *difference* between the current and next timestamp to be in [1..num_rows] if address hasn't changed (i.e. we only care about timestamps for a particular address)
                // 3. this is enough. Let x, y be subsequent timestamps for a given address. x, y, and y - x are all in [1..num_rows]. Suppose "x > y" in the field. Then y - x > num_rows -><-
                // this argument works as long as the number of rows is less than half of the field order, which is very true for this library because we can only use up to 2^TWO_ADICITY rows and this is usually far below the field size.
                // we do this by enforcing the "unsorted" timestamps start at 1 and increment by 1 each row. Then we apply a lookup against that col to check that the timestamp diffs are in [1..num_rows]
                // since timestamp_sorted is a permutation of timestamp, timestamp_sorted is guaranteed to be in that range
                // lookups are applied at the end of this function
                let address_changed = next_row.addr_sorted - curr_row.addr_sorted;
                // degree 1
                // degree 2
                yield_constr.constraint_transition(
                    (P::ONES - address_changed)
                        * (next_row.timestamp_sorted_diff
                            - (next_row.timestamp_sorted - curr_row.timestamp_sorted)),
                );
                // set the timestamp difference to 1 if the address changed as a dummy to indicate we don't care (our range check doesn't include 0 because timestamps have to be unique)
                // degree 2
                yield_constr.constraint_transition(
                    address_changed * (next_row.timestamp_sorted_diff - P::ONES),
                );

                // check that is_write is binary
                yield_constr.constraint(curr_row.is_write * (P::ONES - curr_row.is_write));
                yield_constr
                    .constraint(curr_row.is_write_sorted * (P::ONES - curr_row.is_write_sorted));

                // check that "unsorted" timestamps start at 1 and increment by 1 each curr_row
                yield_constr.constraint_first_row(curr_row.timestamp - P::ONES);
                yield_constr
                    .constraint_transition(next_row.timestamp - curr_row.timestamp - P::ONES);

                // check that the sorted memory trace is valid
                // to do this, we check the following at each step;
                // 1. if the address has changed, the memory trace is valid at this step
                // 2. if the address has not changed and the current operation is a write, the memory trace is valid at this step
                // 3. if the address has not changed and the current operation is a read, the memory trace is valid at this step iff the value is the same
                yield_constr.constraint_transition(
                    (P::ONES - address_changed)
                        * (P::ONES - next_row.is_write_sorted)
                        * (next_row.value_sorted - curr_row.value_sorted),
                );

                // STACK SEMANTICS

                // check SP starts at 0
                yield_constr.constraint_first_row(curr_row.sp);

                // check that is_pop is binary (only operations are pop and push)
                yield_constr.constraint(curr_row.is_pop * (P::ONES - curr_row.is_pop));

                // if the current operation is a pop, the following should be true:
                // 1. addr should be sp - 1
                // 2. next sp should be sp - 1
                // 3. is_write should be 0
                // a corrolary of this is stack underflows (pop when sp is 0) can't happen since then the addresses wouldn't satisfy the continuity requirement.
                yield_constr.constraint(curr_row.is_pop * (curr_row.addr - curr_row.sp + P::ONES));
                yield_constr
                    .constraint_transition(curr_row.is_pop * (next_row.sp - curr_row.sp + P::ONES));
                yield_constr.constraint(curr_row.is_pop * curr_row.is_write);

                // if the current operation is a push, the following should be true:
                // 1. addr should be sp
                // 2. next sp should be sp + 1
                // 3. is_write should be 1
                yield_constr
                    .constraint((P::ONES - curr_row.is_pop) * (curr_row.addr - curr_row.sp));
                yield_constr.constraint_transition(
                    (P::ONES - curr_row.is_pop) * (next_row.sp - curr_row.sp - P::ONES),
                );
                yield_constr
                    .constraint((P::ONES - curr_row.is_pop) * (P::ONES - curr_row.is_write));

                // apply all of the lookups
                let lookup_pairs = lookup_permutation_sets()
                    .into_iter()
                    .map(|(_, _, input, table)| (input, table));
                for (input, table) in lookup_pairs {
                    eval_lookups(&vars, yield_constr, input, table);
                }
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

            fn permutation_pairs(&self) -> Vec<PermutationPair> {
                vec![PermutationPair {
                    column_pairs: sorted_access_permutation_pairs(),
                }]
            }
        }
    };
}

impl_stack_stark_for_n_channels!(1);

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use rand::Rng;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::stark_testing::test_stark_low_degree;
    use crate::starky2lib::stack::generation::StackGenerator;
    use crate::verifier::verify_stark_proof_no_ctl;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = StackStark<F, D, 1>;

        let stark = S::new();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_random_trace() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = StackStark<F, D, 1>;

        let mut generator = StackGenerator::<F, 1>::new();
        let mut rng = rand::thread_rng();
        let mut height = 0;
        for i in 0..500 {
            let is_pop = if height == 0 {
                false
            } else {
                rng.gen_range(0..2) == 1
            };

            if is_pop {
                height -= 1;
                generator.gen_pop(&[]);
            } else {
                height += 1;
                let value = F::rand_from_rng(&mut rng);
                generator.gen_push(value, &[]);
            }
        }

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)?;

        Ok(())
    }
}
