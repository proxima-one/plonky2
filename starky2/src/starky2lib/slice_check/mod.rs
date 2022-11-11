/// STARK that checks two slices of two different memories have the same contents

pub mod generation;
pub mod layout;

use core::borrow::Borrow;
use core::marker::PhantomData;

use layout::*;
use plonky2::field::{
    extension::{Extendable, FieldExtension},
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::stark::Stark;
use crate::starky2lib::gadgets::{
    ConstraintConsumerFiltered,
    Starky2ConstraintConsumer,
};
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

pub struct SliceCheckStark<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize>
{
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize>
    SliceCheckStark<F, D, NUM_CHANNELS>
{
    pub fn new() -> SliceCheckStark<F, D, NUM_CHANNELS> {
        SliceCheckStark {
            _phantom: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Default
    for SliceCheckStark<F, D, 0>
{
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! impl_slice_check_stark_n_channels {
    ($n:expr) => {
        impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D>
            for SliceCheckStark<F, D, $n>
        {
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
                let curr_row: &SliceCheckRow<P, $n> = vars.local_values.borrow();
                let next_row: &SliceCheckRow<P, $n> = vars.next_values.borrow();

                // slice filters are binary and mutually exclusive
                yield_constr.mutually_exclusive_binary_check(&curr_row.slice_filters);

                // first row is not padding
                yield_constr.constraint_first_row(curr_row.is_padding_row);

                // if current row is padding, next row is padding
                yield_constr.constraint_transition_filtered(
                    P::ONES - next_row.is_padding_row,
                    curr_row.is_padding_row,
                );

                // can only transition to padding row if remaining_len is zero
                yield_constr.constraint_transition_filtered(
                    curr_row.remaining_len,
                    (P::ONES - curr_row.is_padding_row) * next_row.is_padding_row,
                );

                // addresses increment by 1 each row unless we're done with the input
                yield_constr.constraint_transition_filtered(
                    next_row.left_addr - curr_row.left_addr - P::ONES,
                    P::ONES - curr_row.done,
                );
                yield_constr.constraint_transition_filtered(
                    next_row.right_addr - curr_row.right_addr - P::ONES,
                    P::ONES - curr_row.done,
                );

                // remaining_len decrements by 1 each row unles we're done with the input
                yield_constr.constraint_transition_filtered(
                    next_row.remaining_len - (curr_row.remaining_len - P::ONES),
                    P::ONES - curr_row.done,
                );

                // remaining_len is zero if it's a padding row
                yield_constr.constraint_filtered(curr_row.remaining_len, curr_row.is_padding_row);

                // we're done with the input if remaining_len is zero
                yield_constr.inv_check(
                    curr_row.remaining_len,
                    curr_row.remaining_len_inv,
                    curr_row.done,
                );

                // one of the filters should be set next row iff we're done with the input and next row isn't padding
                let filter = next_row.slice_filters.iter().copied().sum::<P>();
                yield_constr
                    .constraint(filter - curr_row.done * (P::ONES - next_row.is_padding_row));
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
    };
}

impl_slice_check_stark_n_channels!(1);
impl_slice_check_stark_n_channels!(2);
impl_slice_check_stark_n_channels!(3);
impl_slice_check_stark_n_channels!(4);

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
    use crate::starky2lib::slice_check::generation::SliceCheckRowGenerator;
    use crate::verifier::verify_stark_proof_no_ctl;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = SliceCheckStark<F, D, 1>;

        let stark = S::new();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_slice_check() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = SliceCheckStark<F, D, 1>;

        let mut rng = rand::thread_rng();

        let mut slice_values = Vec::new();
        for _ in 0..5 {
            let slice_len = rng.gen_range(1..10);
            let slice_value = (0..slice_len)
                .map(|_| rng.gen())
                .map(F::from_canonical_u32)
                .collect::<Vec<F>>();
            slice_values.push(slice_value);
        }

        let mut left_memory = (0..1000)
            .map(|_| rng.gen())
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>();
        let mut right_memory = (0..600)
            .map(|_| rng.gen())
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>();

        let mut slices = Vec::new();
        for (i, slice) in slice_values.into_iter().enumerate() {
            let left_offset = rng.gen_range(i * 100..(i + 1) * 100);
            let right_offset = rng.gen_range(i * 60..(i + 1) * 60);

            left_memory[left_offset..left_offset + slice.len()].copy_from_slice(&slice);
            right_memory[right_offset..right_offset + slice.len()].copy_from_slice(&slice);

            slices.push((left_offset, right_offset, slice.len()))
        }

        let mut generator = SliceCheckRowGenerator::<F, 1>::new(&left_memory, &right_memory);

        for (left_start, right_start, len) in slices {
            generator.gen_slice_check(left_start, right_start, len, 0);
        }

        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let config = StarkConfig::standard_fast_config();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl::<F, C, S, D>(&stark, &proof, &config)?;

        Ok(())
    }
}
