/// STARK that does keccak256 by looking up keccak-f. Does not check padding - padding must be applied by the 'calling' STARK

pub mod layout;
pub mod generation;

use std::borrow::Borrow;
use std::marker::PhantomData;

use layout::*;
use plonky2::hash::hash_types::RichField;
use plonky2::field::{extension::{Extendable, FieldExtension}, packed::PackedField};

use crate::{vars::StarkEvaluationVars, constraint_consumer::ConstraintConsumer, stark::Stark, lookup::eval_lookups};

pub struct Keccak256SpongeStark<F: RichField + Extendable<D>, const D: usize> {
	_phantom: PhantomData<F>
}

impl<F: RichField + Extendable<D>, const D: usize> Keccak256SpongeStark<F, D> {
	fn new() -> Self {
		Self {
			_phantom: PhantomData
		}
	}
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for Keccak256SpongeStark<F, D> {
    const COLUMNS: usize = KECCAK_256_NUM_COLS;
    const PUBLIC_INPUTS: usize = KECCAK_256_NUM_PIS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let curr_row: &Keccak256SpongeRow<P> = vars.local_values.borrow();
        let next_row: &Keccak256SpongeRow<P> = vars.next_values.borrow();

		// assert mode bits are binary
		// degree 2
		yield_constr.constraint(curr_row.mode_bits[0] * (P::ONES - curr_row.mode_bits[0]));
		yield_constr.constraint(curr_row.mode_bits[1] * (P::ONES - curr_row.mode_bits[1]));

		// assert filters are binary
		// degree 2
		yield_constr.constraint(curr_row.input_filter * (P::ONES - curr_row.input_filter));
		yield_constr.constraint(curr_row.output_filter * (P::ONES - curr_row.output_filter));

		// assert mode bits are one of valid values by asserting their sum is 0 or 1
		let mode_bit_sum: P = curr_row.mode_bits.iter().copied().sum();
		// degree 2
		yield_constr.constraint(mode_bit_sum * (P::ONES - mode_bit_sum));

		// assert padding row is always followed by another padding row
		let curr_is_padding_row = P::ONES - curr_row.mode_bits[0] - curr_row.mode_bits[1];
		let next_is_padding_row = P::ONES - next_row.mode_bits[0] - next_row.mode_bits[1];
		// degree 2
		yield_constr.constraint_transition(curr_is_padding_row * (curr_is_padding_row - next_is_padding_row));

		// assert next block idx is zero if starting a new sponge or the next row is padding and incremented otherwise`
		// we start a new sponge whenever we go from squeeze mode to absorb mode
		let next_is_new_sponge = next_row.mode_bits[0] * curr_row.mode_bits[1];
		let curr_block_idx = curr_row.block_idx_bytes[0] + curr_row.block_idx_bytes[1] * FE::from_canonical_u16(1 << 8);
		let next_block_idx = next_row.block_idx_bytes[1] + next_row.block_idx_bytes[1] * FE::from_canonical_u16(1 << 8);
		// degree 3
		yield_constr.constraint_transition((next_is_padding_row + next_is_new_sponge) * next_block_idx);
		yield_constr.constraint_transition((P::ONES - next_is_padding_row - next_is_new_sponge) * (next_block_idx - curr_block_idx - P::ONES));

		// assert hash idx increments whenever next is new sponge and stays the same otherwise
		let curr_hash_idx = curr_row.hash_idx_bytes[0] + curr_row.hash_idx_bytes[1] * FE::from_canonical_u16(1 << 8);
		let next_hash_idx = next_row.hash_idx_bytes[0] + next_row.hash_idx_bytes[1] * FE::from_canonical_u16(1 << 8);
		// degree 3
		yield_constr.constraint_transition(next_is_new_sponge * (next_hash_idx - curr_hash_idx - P::ONES));
		yield_constr.constraint_transition((P::ONES - next_is_new_sponge) * (next_hash_idx - curr_hash_idx));

		// assert LUT bits are binary
		for bit in 0..8 {
			// degree 2
			yield_constr.constraint(curr_row.u8_lookup_bits[bit] * (P::ONES - curr_row.u8_lookup_bits[bit]));
		}

		// check LUT bits against LUTs
		let bits_u8: P = (0..8).map(|i| curr_row.u8_lookup_bits[i] * FE::from_canonical_u8(1 << i)).sum();
		let bits_u7: P = (0..7).map(|i| curr_row.u8_lookup_bits[i] * FE::from_canonical_u8(1 << i)).sum();
	
		// degree 2
		yield_constr.constraint(curr_row.u8_lookup - bits_u8);
		yield_constr.constraint(curr_row.u7_lookup - bits_u7);

		// evaluate the lookups
		// degree 2
		eval_lookups(&vars, yield_constr, block_idx_bytes_start_col(), u8_lut_col());
		eval_lookups(&vars, yield_constr, block_idx_bytes_start_col() + 1, u7_lut_col());
		eval_lookups(&vars, yield_constr, hash_idx_bytes_start_col(), u8_lut_col());
		eval_lookups(&vars, yield_constr, hash_idx_bytes_start_col() + 1, u8_lut_col());
	
		// check input block encoding
		for i in 0..KECCAK_RATE_U32S {
			let encoded_word = curr_row.input_block_encoded[i];
			let word = curr_row.input_block[i];

			// degree 2
			yield_constr.constraint(encoded_word - (word + (curr_hash_idx * FE::from_canonical_u64(1 << 32)) + (curr_block_idx * FE::from_canonical_u64(1 << 48))));
		}

		// set curr_state_rate and curr_state_capacity to 0 at the beginning of each sponge instance. otherwise copy new_state to the nxet row
		for i in 0..KECCAK_RATE_U32S {
			// degree 1
			yield_constr.constraint_first_row(curr_row.curr_state_rate[i]);
			// degree 3
			yield_constr.constraint_transition((P::ONES - next_is_new_sponge) * next_row.curr_state_rate[i]);
			// degree 3
			yield_constr.constraint_transition(next_is_new_sponge * (next_row.curr_state_rate[i] - curr_row.new_state[i]));
		}
		for i in 0..KECCAK_CAPACITY_U32S {
			// degree 1
			yield_constr.constraint_first_row(curr_row.curr_state_capacity[i]);
			// degree 3
			yield_constr.constraint_transition((P::ONES - next_is_new_sponge) * next_row.curr_state_capacity[i]);
			// degree 3
			yield_constr.constraint_transition(next_is_new_sponge * (next_row.curr_state_capacity[i] - curr_row.new_state[KECCAK_RATE_U32S + i]));
		}

		// xored_state_rate is assumed to be checked via CTL to the xor STARK when in absorb mode. CTLs are set up in an `AllStark` implementation
		// see the `keccak_256_hash` example for what this looks like in practice
		// when not in absorb mode, it's simply a copy of the current state
		for i in 0..KECCAK_RATE_U32S {
			// degree 3
			yield_constr.constraint((P::ONES - curr_row.mode_bits[0]) * (curr_row.xored_state_rate[i] - curr_row.curr_state_rate[i]))
		}

		// new_state is assumed to be checked via CTL to the Keccak STARK when `invoke_permutation_filter` is set. CTLs are set up in an `AllStark` implementation
		// see the `keccak_256_hash` example for what this looks like in practice
		// when `invoke_permutation_filter` is not set, assert new_state is zero
		for i in 0..KECCAK_WIDTH_U32S {
			// degree 3
			yield_constr.constraint((P::ONES - curr_row.invoke_permutation_filter) * curr_row.new_state[i]);
		}

		// assert invoke_permutation_filter is set to 1 unless we're in a padding row, 0 otherwise
		// degree 2
		yield_constr.constraint(curr_is_padding_row * (P::ONES - curr_row.invoke_permutation_filter));
		yield_constr.constraint((P::ONES - curr_is_padding_row) * curr_row.invoke_permutation_filter);
	}

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: crate::vars::StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut crate::constraint_consumer::RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
		3
    }
}

#[cfg(test)]
mod tests {
	use anyhow::Result;
	use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
	use crate::stark_testing::test_stark_low_degree;
	use super::*;
	use super::generation::{Keccak256SpongeGenerator, pad101, to_le_blocks};

	#[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Keccak256SpongeStark<F, D>;

        let stark = Keccak256SpongeStark::<F, D>::new();
        test_stark_low_degree(stark)
    }

	#[test]
	fn test_basic() {
		todo!()
	}	
}