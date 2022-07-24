use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use crate::constraint_consumer::ConstraintConsumer;

use super::layout::*;

// 5 "INSNS" (stages) of the STARK
// 0. (8 rows) load input from input colums into wis, two 32-bit limbs at a time from LEFT_INPUT_COL and RIGHT_INPUT_COL respectively and shift to right.
// 1. (48 rows) shift wis left by 1, append / compute next WI, perform 1 round of message schedule and round fn, load a-h as initial his during first row
// 2. (16 rows) shift wis left by 1, perform 1 round of message schedule and round fn. on last row, update his
// 3. (8 rows) shift his left by 1, append original hi. Copy leftmost hi to output col and add hash_idx * 1 << 32 to it to signify which has it's for
// Output col should be zero every row except for the last 8 of a hash.
// Input col should be zero every row except for the 


pub const NUM_PHASES: usize = 4;
pub const NUM_PHASE_0_ROWS: usize = 8;
pub const NUM_PHASE_1_ROWS: usize = 48;
pub const NUM_PHASE_2_ROWS: usize = 16;
pub const NUM_PHASE_3_ROWS: usize = 8;

pub const HIS_IV: [u32; 8] = [
	u32::from_be(0x6a09e668).to_le(),
	u32::from_be(0xbb67ae85).to_le(),
	u32::from_be(0x3c6ef372).to_le(),
	u32::from_be(0xa54ff53a).to_le(),
	u32::from_be(0x510e527f).to_le(),
	u32::from_be(0x9b05688c).to_le(),
	u32::from_be(0x1f83d9ab).to_le(),
	u32::from_be(0x5be0cd19).to_le(),
];

/// compute field_representation of a sequence of 32 bits interpreted little-endian u32 of a specific element of an trace array
macro_rules! bit_decomp_32_at_idx {
	($row:expr, $idx:expr, $col_fn:ident, $f:ty, $p:ty) => {(
		(0..32).fold(<$p>::ZEROS, |acc, i| {
			acc + $row[$col_fn($idx, 31 - i)] * <$f>::from_canonical_u64(1 << i)
		})
	)}
}

/// compute field_representation of a sequence of 32 bits interpreted little-endian u32
macro_rules! bit_decomp_32 {
	($row:expr, $col_fn:ident, $f:ty, $p:ty) => {(
		(0..32).fold(<$p>::ZEROS, |acc, i| {
			acc + $row[$col_fn(31 - i)] * <$f>::from_canonical_u64(1 << i)
		})
	)}
}

fn eval_msg_schedule<F, P>(
	curr_row: &[P; NUM_COLS],
	selector: P
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{}

fn eval_round_fn<F, P>(
	curr_row: &[P; NUM_COLS],
	selector: P
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{}

fn eval_first_row<F, P>(
	curr_row: &[P; NUM_COLS],
	yield_constr: &mut ConstraintConsumer<P>,
	hash_idx: u64
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{
	// set his to initial values
	for i in 0..8 {
		yield_constr.constraint_first_row(curr_row[h_i(i)] - F::from_canonical_u32(HIS_IV[i]));
	}
}

fn eval_phase_0<F, P>(
	curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
	yield_constr: &mut ConstraintConsumer<P>,
	hash_idx: u64
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{
	// degree 1
	let phase_selector = -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] + F::ONE;

	// do a bit decomposition of the left and right inputs against wis[PC*2] and wis[PC*2 + 1] also checking the hash idx
	let decomp_left = bit_decomp_32_at_idx!(curr_row, NUM_WIS-2, wi_bit, F, P) + F::from_canonical_u64(hash_idx << 32);
	let decomp_right = bit_decomp_32_at_idx!(curr_row, NUM_WIS-1, wi_bit, F, P) + F::from_canonical_u64(hash_idx << 32);

	// degree 2
	yield_constr.constraint(phase_selector * (decomp_left - curr_row[LEFT_INPUT_COL]));
	// degree 2
	yield_constr.constraint(phase_selector * (decomp_right - curr_row[RIGHT_INPUT_COL]));

	// shift the next wi bits over by 2
	for i in 2..NUM_WIS {
		for bit in 0..32 {
			// degree 2
			yield_constr.constraint_transition(phase_selector * (next_row[wi_bit(i-2, bit)] - curr_row[wi_bit(i, bit)]));
		}
	}

	// ensure his stay the same
	for i in 0..8 {
		yield_constr.constraint_transition(phase_selector * (next_row[h_i(i)] - curr_row[h_i(i)]));
	}
}

fn eval_phase_1<F, P>(
	curr_row: &[P; NUM_COLS],
	next_row: &[P; NUM_COLS],
	yield_constr: &mut ConstraintConsumer<P>,
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{
	// if transitioning from phase 0 to phase 1, load his into a-h
	let phase_0_selector = -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] - curr_row[phase_bit(3)] + F::ONE;
	let phase_0_selector_next = -next_row[phase_bit(0)] - next_row[phase_bit(1)] - next_row[phase_bit(2)] + F::ONE;
	let transition_to_phase_1 = phase_0_selector * (-phase_0_selector_next + F::ONE);

	let a_field = bit_decomp_32!(next_row, a_bit, F, P);
	let b_field = bit_decomp_32!(next_row, b_bit, F, P);
	let c_field = bit_decomp_32!(next_row, c_bit, F, P);
	let d_field = bit_decomp_32!(next_row, d_bit, F, P);
	let e_field = bit_decomp_32!(next_row, e_bit, F, P);
	let f_field = bit_decomp_32!(next_row, f_bit, F, P);
	let g_field = bit_decomp_32!(next_row, g_bit, F, P);
	let h_field = bit_decomp_32!(next_row, h_bit, F, P);

	// degree 3
	yield_constr.constraint_transition(transition_to_phase_1 * (a_field - next_row[h_i(0)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (b_field - next_row[h_i(1)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (c_field - next_row[h_i(2)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (d_field - next_row[h_i(3)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (e_field - next_row[h_i(4)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (f_field - next_row[h_i(5)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (g_field - next_row[h_i(6)]));
	yield_constr.constraint_transition(transition_to_phase_1 * (h_field - next_row[h_i(7)]));

	let phase_selector = curr_row[phase_bit(0)];

	// msg schedule
	// round fn

	// shift wis left by one
	for i in 1..NUM_WIS {
		for bit in 0..32 {
			// degree 2
			yield_constr.constraint_transition(phase_selector * (next_row[wi_bit(i-1, bit)] - curr_row[wi_bit(i, bit)]));
		}
	}
}

fn eval_phase_transitions<F, P>(
	curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
	yield_constr: &mut ConstraintConsumer<P>,
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{
	let phase_0_selector = -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] - curr_row[phase_bit(3)] + F::ONE;
	let phase_1_selector = curr_row[phase_bit(0)];
	let phase_2_selector = curr_row[phase_bit(1)];
	let phase_3_selector = curr_row[phase_bit(2)];

	let phase_0_selector_next = -next_row[phase_bit(0)] - next_row[phase_bit(1)] - next_row[phase_bit(2)] + F::ONE;
	let phase_1_selector_next = next_row[phase_bit(0)];
	let phase_2_selector_next = next_row[phase_bit(1)];
	let phase_3_selector_next = next_row[phase_bit(2)];


	// ensure phase is only one of possible values
	// degree 2
	yield_constr.constraint(phase_0_selector + phase_1_selector + phase_2_selector + phase_3_selector - F::ONE);

	// degree 2
	let transition_0_selector = phase_0_selector * (-phase_0_selector_next + F::ONE);
	let transition_1_selector = phase_1_selector * (-phase_1_selector_next + F::ONE);
	let transition_2_selector = phase_2_selector * (-phase_2_selector_next + F::ONE);

	let not_in_transition = -transition_0_selector - transition_1_selector - transition_2_selector + F::ONE;

	// inc pc when not transitioning to next phase
	// degre 3
	yield_constr.constraint_transition(not_in_transition * (next_row[PC] - curr_row[PC] - F::ONE));

	// set pc to 0 when going to next phase
	// degree 3
	yield_constr.constraint_transition(transition_0_selector * next_row[PC]);
	yield_constr.constraint_transition(transition_1_selector * next_row[PC]);
	yield_constr.constraint_transition(transition_2_selector * next_row[PC]);

	// ensure phase stays the same when not transitioning to next phase
	for bit in 0..4 {
		// degree 3
		yield_constr.constraint_transition(not_in_transition * (next_row[phase_bit(bit)] - curr_row[phase_bit(bit)]));
	}

	// ensure phase transitions are correct
	// degree 3
	yield_constr.constraint_transition(-(transition_0_selector * phase_1_selector_next) + F::ONE);
	yield_constr.constraint_transition(-(transition_1_selector * phase_2_selector_next) + F::ONE);
	yield_constr.constraint_transition(-(transition_2_selector * phase_3_selector_next) + F::ONE);

	// ensure phase transitions happen after correct number of rows
	yield_constr.constraint_transition(transition_0_selector * (curr_row[PC] - F::from_canonical_u16(8)));
}

fn eval_bits_are_bits<F, P>(
	curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
	yield_constr: &mut ConstraintConsumer<P>,
) where
	F: RichField,
	P: PackedField<Scalar = F>,
{
	// phase_bits
	for i in 0..NUM_PHASES {
		yield_constr.constraint((-curr_row[phase_bit(i)] + F::ONE) * curr_row[phase_bit(i)]);
	}

	// wis
	for i in 0..NUM_WIS {
		for bit in 0..32 {
			yield_constr.constraint((-curr_row[wi_bit(i, bit)] + F::ONE) * curr_row[wi_bit(i, bit)]);
		}
	}

	// s0
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[little_s0_bit(bit)] + F::ONE) * curr_row[little_s0_bit(bit)]);
	}

	// s1
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[little_s1_bit(bit)] + F::ONE) * curr_row[little_s1_bit(bit)]);
	}

	// a
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[a_bit(bit)] + F::ONE) * curr_row[a_bit(bit)]);
	}

	// b
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[b_bit(bit)] + F::ONE) * curr_row[b_bit(bit)]);
	}

	// c
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[c_bit(bit)] + F::ONE) * curr_row[c_bit(bit)]);
	}

	// d
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[d_bit(bit)] + F::ONE) * curr_row[d_bit(bit)]);
	}

	// e
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[e_bit(bit)] + F::ONE) * curr_row[e_bit(bit)]);
	}

	// f
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[f_bit(bit)] + F::ONE) * curr_row[f_bit(bit)]);
	}

	// g
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[g_bit(bit)] + F::ONE) * curr_row[g_bit(bit)]);
	}

	// h
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[h_bit(bit)] + F::ONE) * curr_row[h_bit(bit)]);
	}

	// S0
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[big_s0_bit(bit)] + F::ONE) * curr_row[big_s0_bit(bit)]);
	}

	// S1
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[big_s1_bit(bit)] + F::ONE) * curr_row[big_s1_bit(bit)]);
	}

	// (not e) and g
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[not_e_and_g_bit(bit)] + F::ONE) * curr_row[not_e_and_g_bit(bit)]);
	}

	// e and f
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[e_and_f_bit(bit)] + F::ONE) * curr_row[e_and_f_bit(bit)]);
	}

	// ch
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[ch_bit(bit)] + F::ONE) * curr_row[ch_bit(bit)]);
	}

	// a and b
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[a_and_b_bit(bit)] + F::ONE) * curr_row[a_and_b_bit(bit)]);
	}

	// a and c
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[a_and_c_bit(bit)] + F::ONE) * curr_row[a_and_c_bit(bit)]);
	}

	// b and c
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[b_and_c_bit(bit)] + F::ONE) * curr_row[b_and_c_bit(bit)]);
	}

	// maj
	for bit in 0..32 {
		yield_constr.constraint((-curr_row[maj_bit(bit)] + F::ONE) * curr_row[maj_bit(bit)]);
	}
}

