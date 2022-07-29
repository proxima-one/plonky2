use plonky2::field::{packed::PackedField, types::Field};

use super::layout::*;
use super::constants::{ROUND_CONSTANTS, HASH_IV};
use crate::constraint_consumer::ConstraintConsumer;

// TODO implement phases
// TODO constrain cols that shouldn't change during each phase

// 4 "INSNS" (stages) of the STARK
// 0. (8 rows) load input from left input colum into wis 1 at a time. Set his to IV and load his into a-h in first row. Perform 1 round of round fn
// 1. (8 rows) same as phase, but with the right input column
// 2. (48 rows) shift wis left by 1, append / compute next WI, perform 1 round of message schedule and round fn update his in last row
// 3. (8 rows) shift wis left by 1, shift his left by 1, copy leftmost hi to output col and add hash_idx * 1 << 32 to it to signify which hash it's for
// Output col should be zero every row except for the last 8 of a hash.
// Input col should be zero every row except for the
// All 32-bit integers, including constants, are assumed to be big-endian
// wis always shifted left by one

pub const NUM_PHASES: usize = 4;
pub const NUM_PHASE_0_ROWS: usize = 8;
pub const NUM_PHASE_1_ROWS: usize = 8;
pub const NUM_PHASE_2_ROWS: usize = 48;
pub const NUM_PHASE_3_ROWS: usize = 8;



/// compute field_representation of a sequence of 32 bits interpreted big-endian u32 of a specific element of an trace array
macro_rules! bit_decomp_32_at_idx {
    ($row:expr, $idx:expr, $col_fn:ident, $f:ty, $p:ty) => {
        ((0..32).fold(<$p>::ZEROS, |acc, i| {
            acc + $row[$col_fn($idx, i)] * <$f>::from_canonical_u64(1 << i)
        }))
    };
}

/// compute field_representation of a sequence of 32 bits interpreted big-endian u32
macro_rules! bit_decomp_32 {
    ($row:expr, $col_fn:ident, $f:ty, $p:ty) => {
        ((0..32).fold(<$p>::ZEROS, |acc, i| {
            acc + $row[$col_fn(i)] * <$f>::from_canonical_u64(1 << i)
        }))
    };
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen<P: PackedField>(x: P, y: P) -> P {
    x + y - x * y.doubles()
}

// 0 1 1 0 0 1 // a
// 1 0 1 1 0 0 // a >>> 1. (a >> a)[i] = a[i - 1 % len]
// 1 0 0 1 1 0 // a in trace
// 0 0 1 1 0 1 // (a >>> 1) in trace
// 0 1 0 0 1 1 // (a in trace) >>> 1
// 0 0 0 1 1 0 // a >> 2
// 0 1 1 0 0 0 // (a >> 2) in trace
// 0 0 1 0 0 1 // (a in trace) >> 2

// 1 0 0 1 1 0 // a in trace
// 0 0 1 1 0 1 // (a >>> 1) in trace
// add mod 32

// 1 0 0 1 1 0 // a in trace
// 0 1 1 0 0 0 // (a >> 2) in trace
// add but ignore top k, where k is shift

// gets w[i] for the *next* row
pub(crate) fn eval_msg_schedule<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    let into_phase_2 = next_row[phase_bit(2)];

    // s0 := (w[i-15] >>> 7) xor (w[i-15] >>> 18) xor (w[i-15] >>  3)

    for bit in 0..29 {
        let computed_bit = xor_gen(
            next_row[wi_bit(0, (bit + 7) % 32)],
            next_row[wi_bit(0, (bit + 18) % 32)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[xor_tmp_i_bit(0, bit)] - computed_bit));

        let computed_bit = xor_gen(
            next_row[xor_tmp_i_bit(0, bit)],
            next_row[wi_bit(0, bit + 3)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[little_s0_bit(bit)] - computed_bit));
    }
    for bit in 29..32 {
        // we can ignore the second XOR in this case since it's with 0
        let computed_bit = xor_gen(
            next_row[wi_bit(0, (bit + 7) % 32)],
            next_row[wi_bit(0, (bit + 18) % 32)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[little_s0_bit(bit)] - computed_bit));
    }

    // s1 := (w[i-2] >>> 17) xor (w[i-2] >>> 19) xor (w[i-2] >> 10)

    for bit in 0..22 {
        let computed_bit = xor_gen(
            next_row[wi_bit(13, (bit + 17) % 32)],
            next_row[wi_bit(13, (bit + 19) % 32)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[xor_tmp_i_bit(1, bit)] - computed_bit));

        let computed_bit = xor_gen(
            next_row[xor_tmp_i_bit(1, bit)],
            next_row[wi_bit(13, bit + 10)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[little_s1_bit(bit)] - computed_bit));
    }
    for bit in 22..32 {
        // we can ignore the second XOR in this case since it's with 0
        let computed_bit = xor_gen(
            next_row[wi_bit(13, (bit + 17) % 32)],
            next_row[wi_bit(13, (bit + 19) % 32)],
        );
        // degree 3
        yield_constr.constraint_transition(into_phase_2 * (next_row[little_s1_bit(bit)] - computed_bit));
    }

    // w[i] := w[i-16] + s0 + w[i-7] + s1

    // degree 1
    let s0_field_computed = bit_decomp_32!(next_row, little_s0_bit, F, P);
    let s1_field_computed = bit_decomp_32!(next_row, little_s1_bit, F, P);
    let wi_minus_16_field_computed = bit_decomp_32_at_idx!(curr_row, 0, wi_bit, F, P);
    let wi_minus_7_field_computed = bit_decomp_32_at_idx!(next_row, 8, wi_bit, F, P);
    let wi = bit_decomp_32_at_idx!(next_row, 15, wi_bit, F, P);

    // degree 2
    yield_constr.constraint_transition(
        into_phase_2
            * (next_row[WI_FIELD]
                - (wi_minus_16_field_computed
                    + s0_field_computed
                    + wi_minus_7_field_computed
                    + s1_field_computed)),
    );
    // degree 3
    yield_constr
        .constraint(into_phase_2 * (next_row[WI_FIELD] - (wi + next_row[WI_QUOTIENT] * F::from_canonical_u64(1 << 32))));
}

pub(crate) fn eval_shift_wis<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // shift wis unless in padding
    let in_padding = -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] - curr_row[phase_bit(3)] + F::ONE;
    for i in 0..15 {
        for bit in 0..32 {
            // degree 3
            yield_constr.constraint_transition(
                (-in_padding + F::ONE) * (next_row[wi_bit(i, bit)] - curr_row[wi_bit(i + 1, bit)]),
            );
        }
    }
}

// evaluates round function on the *current* row
pub(crate) fn eval_round_fn<F, P>(curr_row: &[P; NUM_COLS], next_row: &[P; NUM_COLS], yield_constr: &mut ConstraintConsumer<P>)
where
    F: Field,
    P: PackedField<Scalar = F>,
{
    let in_phase_0_to_2 = curr_row[phase_bit(0)] + curr_row[phase_bit(1)] + curr_row[phase_bit(2)];

    // S1 := (e >>> 6) xor (e >>> 11) xor (e >>> 25)
    for bit in 0..32 {
        let computed_bit = xor_gen(
            curr_row[e_bit((bit + 32 - 6) % 32)],
            curr_row[e_bit((bit + 32 - 11) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_0_to_2 * (curr_row[xor_tmp_i_bit(2, bit)] - computed_bit));

        let computed_bit = xor_gen(
            curr_row[xor_tmp_i_bit(2, bit)],
            curr_row[e_bit((bit + 7) % 32)],
        );
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[big_s1_bit(bit)] - computed_bit));
    }

    // ch := (e and f) xor ((not e) and g)
    for bit in 0..32 {
        let computed_bit = curr_row[e_bit(bit)] * curr_row[f_bit(bit)];
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[e_and_f_bit(bit)] - computed_bit));

        let computed_bit = (-curr_row[e_bit(bit)] + F::ONE) * curr_row[g_bit(bit)];
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[not_e_and_g_bit(bit)] - computed_bit));

        let computed_bit = xor_gen(curr_row[e_and_f_bit(bit)], curr_row[not_e_and_g_bit(bit)]);
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[ch_bit(bit)] - computed_bit));
    }

    // S0 := (a >>> 2) xor (a >>> 13) xor (a >>> 22)
    for bit in 0..32 {
        let computed_bit = xor_gen(curr_row[a_bit((bit + 32 - 2) % 32)], curr_row[a_bit((bit + 32 - 13) % 32)]);
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[xor_tmp_i_bit(3, bit)] - computed_bit));
      
        let computed_bit = xor_gen(curr_row[xor_tmp_i_bit(3, bit)], curr_row[a_bit((bit + 10) % 32)]);
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[big_s0_bit(bit)] - computed_bit));
    }

    // maj := (a and b) xor (a and c) xor (b and c)
    for bit in 0..32 {
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[a_and_b_bit(bit)] - curr_row[a_bit(bit)] * curr_row[b_bit(bit)]));

        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[a_and_c_bit(bit)] - curr_row[a_bit(bit)] * curr_row[c_bit(bit)]));

        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[b_and_c_bit(bit)] - curr_row[b_bit(bit)] * curr_row[c_bit(bit)]));

        let computed_bit = xor_gen(curr_row[a_and_b_bit(bit)], curr_row[a_and_c_bit(bit)]);
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[xor_tmp_i_bit(4, bit)] - computed_bit));

        let computed_bit = xor_gen(curr_row[xor_tmp_i_bit(4, bit)], curr_row[b_and_c_bit(bit)]);
        // degree 3
        // yield_constr.constraint(in_phase_0_to_2 * (curr_row[maj_bit(bit)] - computed_bit));
    }

    // set round constant
    for step in 0..64 {
        // degree 2
        // yield_constr.constraint(curr_row[step_bit(step)] * (curr_row[KI] - F::from_canonical_u32(ROUND_CONSTANTS[step])));
    }

    // temp1 := h + S1 + ch + k[i] + w[i]
    // e := d + temp1
	let h_field = bit_decomp_32!(curr_row, h_bit, F, P);
	let big_s1_field = bit_decomp_32!(curr_row, big_s1_bit, F, P);
	let ch_field = bit_decomp_32!(curr_row, ch_bit, F, P);
    let wi_u32 = bit_decomp_32_at_idx!(curr_row, 15, wi_bit, F, P);
    let temp1_minus_ki = h_field + big_s1_field + ch_field + wi_u32;

    let d_field = bit_decomp_32!(curr_row, d_bit, F, P);
    let e_u32_next = bit_decomp_32!(next_row, e_bit, F, P);
    // degree 2
    // yield_constr.constraint(in_phase_0_to_2 * (curr_row[E_NEXT_FIELD] - (d_field + temp1_minus_ki + curr_row[KI])));
    // degree 3
    // yield_constr.constraint_transition(in_phase_0_to_2 * (curr_row[E_NEXT_FIELD] - (e_u32_next + curr_row[E_NEXT_QUOTIENT] * F::from_canonical_u64(1 << 32))));

    // temp2 := S0 + maj
    // a := temp1 + temp2
    let s0_field = bit_decomp_32!(curr_row, big_s0_bit, F, P);
    let maj_field = bit_decomp_32!(curr_row, maj_bit, F, P);
    let temp2 = s0_field + maj_field;
    let a_u32_next = bit_decomp_32!(next_row, a_bit, F, P);
    
    // degree 2
    // yield_constr.constraint(in_phase_0_to_2 * (curr_row[A_NEXT_FIELD] - (temp2 + temp1_minus_ki + curr_row[KI])));
    // degree 3
    // yield_constr.constraint(in_phase_0_to_2 * (curr_row[A_NEXT_FIELD] - (a_u32_next + curr_row[A_NEXT_QUOTIENT]) * F::from_canonical_u64(1 << 32)));


    // h := g
    // g := f
    // f := e
    // d := c
    // c := b
    // b := a
    for bit in 0..32 {
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[h_bit(bit)] - curr_row[g_bit(bit)]));
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[g_bit(bit)] - curr_row[f_bit(bit)]));
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[f_bit(bit)] - curr_row[e_bit(bit)]));
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[d_bit(bit)] - curr_row[c_bit(bit)]));
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[c_bit(bit)] - curr_row[b_bit(bit)]));
        // yield_constr.constraint_transition(in_phase_0_to_2 * (next_row[b_bit(bit)] - curr_row[a_bit(bit)]));
    }
}

fn eval_first_row_of_hash<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // set his to initial values
    let is_hash_start = curr_row[step_bit(0)] * curr_row[phase_bit(0)];
    for i in 0..8 {
        // degree 3
        yield_constr.constraint(is_hash_start * (next_row[h_i(i)] - F::from_canonical_u32(HASH_IV[i])));
    }
}

pub(crate) fn eval_phase_0_and_1<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    eval_first_row_of_hash(curr_row, next_row, yield_constr);

    // degree 1
    let in_phase_0 = curr_row[phase_bit(0)];
    let in_phase_1 = curr_row[phase_bit(1)];
    let in_phase_0_or_1 = in_phase_0 + in_phase_1;

    // load left inputs in phase 0, right inputs in phase 1. Check hash idx and chunk idx.
    let decomp_left = bit_decomp_32_at_idx!(curr_row, 8, wi_bit, F, P)
        + curr_row[HASH_IDX] *  F::from_canonical_u64(1 << 35) + curr_row[CHUNK_IDX] * F::from_canonical_u64(1 << 32);
    let decomp_right = bit_decomp_32_at_idx!(curr_row, 15, wi_bit, F, P)
        + curr_row[HASH_IDX] * F::from_canonical_u64(1 << 35) + curr_row[CHUNK_IDX] * F::from_canonical_u64(1 << 32);

    // degree 2
    yield_constr.constraint(in_phase_0 * (decomp_left - curr_row[LEFT_INPUT_COL]));
    // degree 2
    yield_constr.constraint(in_phase_1 * (decomp_right - curr_row[RIGHT_INPUT_COL]));

    // ensure left and right inputs are zero in all other phases
    yield_constr.constraint((-in_phase_0 + F::ONE) * curr_row[LEFT_INPUT_COL]);
    yield_constr.constraint((-in_phase_1 + F::ONE) * curr_row[RIGHT_INPUT_COL]);

    // ensure his stay the same
    for i in 0..8 {
        // degree 3
        yield_constr.constraint_transition(in_phase_0 * (next_row[h_i(i)] - curr_row[h_i(i)]));
    }
}

pub(crate) fn eval_phase_1<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // if transitioning from phase 0 to phase 1, load his into a-h
    let phase_0_selector = -curr_row[phase_bit(0)]
        - curr_row[phase_bit(1)]
        - curr_row[phase_bit(2)]
        - curr_row[phase_bit(3)]
        + F::ONE;
    let phase_0_selector_next =
        -next_row[phase_bit(0)] - next_row[phase_bit(1)] - next_row[phase_bit(2)] + F::ONE;
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
}

pub(crate) fn eval_phase_2<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    let update_his = next_row[step_bit(64)];

    let vars = [
        bit_decomp_32!(next_row, a_bit, F, P),
        bit_decomp_32!(next_row, b_bit, F, P),
        bit_decomp_32!(next_row, c_bit, F, P),
        bit_decomp_32!(next_row, d_bit, F, P),
        bit_decomp_32!(next_row, e_bit, F, P),
        bit_decomp_32!(next_row, f_bit, F, P),
        bit_decomp_32!(next_row, g_bit, F, P),
        bit_decomp_32!(next_row, h_bit, F, P),
    ];

    for i in 0..8 {
        // degree 2
        yield_constr.constraint_transition(update_his * (curr_row[h_i_next_field(i)] - (curr_row[h_i(i)] + vars[i])));

        // degree 3
        yield_constr.constraint_transition(update_his * (curr_row[h_i_next_field(i)] - (next_row[h_i(i)] + curr_row[h_i_next_quotient(i)] * F::from_canonical_u64(1 << 32))));
    }
}

pub(crate) fn eval_phase_3<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    let in_phase_3 = curr_row[phase_bit(3)];

    // copy leftmost hi to output
    // degree 3
    yield_constr.constraint(in_phase_3 * (curr_row[OUTPUT_COL] - (curr_row[h_i(0)] + curr_row[HASH_IDX] * F::from_canonical_u64(1 << 32))));

    // assert output col is zero in all other phases
    yield_constr.constraint((-in_phase_3 + F::ONE) * curr_row[OUTPUT_COL]);

    // shift his left
    for i in 1..8 {
        // degree 2
        yield_constr.constraint(in_phase_3 * (next_row[h_i(i-1)] - curr_row[h_i(i)]));
    }
}

pub(crate) fn eval_phase_transitions<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    let phase_0_selector = curr_row[phase_bit(0)];
    let phase_1_selector = curr_row[phase_bit(1)];
    let phase_2_selector = curr_row[phase_bit(2)];
    let phase_3_selector = curr_row[phase_bit(3)];
    let is_padding = -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] - curr_row[phase_bit(3)] + F::ONE;

    let phase_0_selector_next = next_row[phase_bit(0)];
    let phase_1_selector_next = next_row[phase_bit(1)];
    let phase_2_selector_next = next_row[phase_bit(2)];
    let phase_3_selector_next = next_row[phase_bit(3)];
    let is_padding_next = -next_row[phase_bit(0)] - next_row[phase_bit(1)] - next_row[phase_bit(2)] - next_row[phase_bit(3)] + F::ONE;

    // ensure phase is only one of possible values
    // degree 2
    yield_constr.constraint(
        is_padding + phase_0_selector + phase_1_selector + phase_2_selector + phase_3_selector - F::ONE,
    );

    // degree 2
    let transition_0_selector = phase_0_selector * (-phase_0_selector_next + F::ONE);
    let transition_1_selector = phase_1_selector * (-phase_1_selector_next + F::ONE);
    let transition_2_selector = phase_2_selector * (-phase_2_selector_next + F::ONE);
    let transition_3_selector = phase_3_selector * (-phase_3_selector_next + F::ONE);
    let not_in_transition = -transition_0_selector - transition_1_selector - transition_2_selector - transition_3_selector + F::ONE;

    // set initial step bits to a 1 followed by NUM_STEPS_PER_HASH-1 0s
    yield_constr.constraint_first_row(curr_row[step_bit(0)] - F::ONE);
    for step in 1..NUM_STEPS_PER_HASH {
        yield_constr.constraint_first_row(curr_row[step_bit(step)]);
    }

    // inc chunk idx in phase 0 but not transitioning to 1
    // same for 1 to 2
    // degree 3
    yield_constr.constraint_transition(phase_0_selector * (-phase_1_selector_next + F::ONE) * (next_row[CHUNK_IDX] - curr_row[CHUNK_IDX] - F::ONE));
    yield_constr.constraint_transition(phase_1_selector * (-phase_2_selector_next + F::ONE) * (next_row[CHUNK_IDX] - curr_row[CHUNK_IDX] - F::ONE));

    // set chunk idx to 0 at the start of phase 0 and 1 when not in padding
    // degree 3
    yield_constr.constraint_transition((-is_padding + F::ONE) * curr_row[step_bit(0)] * curr_row[CHUNK_IDX]);
    yield_constr.constraint_transition((-is_padding + F::ONE) * curr_row[step_bit(8)] * curr_row[CHUNK_IDX]);

    // inc step bits when next is not padding
    for bit in 0..NUM_STEPS_PER_HASH {
        // degree 3
        yield_constr.constraint_transition((-is_padding_next + F::ONE) * (next_row[step_bit((bit + 1) % NUM_STEPS_PER_HASH)] - curr_row[step_bit(bit)]));
    }

    // inc hash idx at last step or stay the same
    // degree 3
    yield_constr.constraint_transition(phase_0_selector_next * (next_row[HASH_IDX] - curr_row[HASH_IDX] - F::ONE) * (next_row[HASH_IDX] - curr_row[HASH_IDX]));
    // esure hash idx stays the same outside last step
    yield_constr.constraint_transition((-phase_0_selector_next + F::ONE) * (next_row[HASH_IDX] - curr_row[HASH_IDX]));

    // ensure phase stays the same when not transitioning to next phase
    for bit in 0..4 {
        // degree 3
        yield_constr.constraint_transition(
            not_in_transition * (next_row[phase_bit(bit)] - curr_row[phase_bit(bit)]),
        );
    }

    // prevent invalid state trnsitions
    // degree 3
    yield_constr.constraint_transition(transition_0_selector * phase_2_selector_next);
    yield_constr.constraint_transition(transition_0_selector * phase_3_selector_next);
    yield_constr.constraint_transition(transition_0_selector * phase_0_selector_next);
    yield_constr.constraint_transition(transition_0_selector * is_padding_next);
    yield_constr.constraint_transition(transition_1_selector * phase_0_selector_next);
    yield_constr.constraint_transition(transition_1_selector * phase_1_selector_next);
    yield_constr.constraint_transition(transition_1_selector * phase_3_selector_next);
    yield_constr.constraint_transition(transition_1_selector * is_padding_next);
    yield_constr.constraint_transition(transition_2_selector * phase_0_selector_next);
    yield_constr.constraint_transition(transition_2_selector * phase_1_selector_next);
    yield_constr.constraint_transition(transition_2_selector * phase_2_selector_next);
    yield_constr.constraint_transition(transition_2_selector * is_padding_next);
    yield_constr.constraint_transition(transition_3_selector * phase_1_selector_next);
    yield_constr.constraint_transition(transition_3_selector * phase_2_selector_next);
    yield_constr.constraint_transition(transition_3_selector * phase_3_selector_next);

    // enforce correct state transitions
    // TODO: actually figure out if these constraints are necessary
    // degree 3
    yield_constr.constraint_transition(transition_0_selector * (-phase_1_selector_next + F::ONE));
    yield_constr.constraint_transition(transition_1_selector * (-phase_2_selector_next + F::ONE));
    yield_constr.constraint_transition(transition_2_selector * (-phase_3_selector_next + F::ONE));
    yield_constr.constraint_transition(transition_3_selector * (-phase_0_selector_next + -is_padding_next + F::ONE));

    // ensure phase transitions happen after correct number of rows
    // degree 3
    yield_constr
        .constraint_transition(transition_0_selector * (-next_row[step_bit(8)] + F::ONE));
    yield_constr.constraint_transition(transition_1_selector * (-next_row[step_bit(16)] + F::ONE));
    yield_constr.constraint_transition(transition_2_selector * (-next_row[step_bit(64)] + F::ONE));
    yield_constr.constraint_transition(phase_3_selector * phase_0_selector_next * (-next_row[step_bit(0)] + F::ONE));
}

pub(crate) fn eval_bits_are_bits<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // phase_bits
    for bit in 0..NUM_PHASES {
        yield_constr.constraint((-curr_row[phase_bit(bit)] + F::ONE) * curr_row[phase_bit(bit)]);
    }

    // step bits
    for bit in 0..NUM_STEPS_PER_HASH {
        yield_constr.constraint((-curr_row[step_bit(bit)] + F::ONE) * curr_row[step_bit(bit)]);
    }

    // wis
    for i in 0..NUM_WIS {
        for bit in 0..32 {
            yield_constr
                .constraint((-curr_row[wi_bit(i, bit)] + F::ONE) * curr_row[wi_bit(i, bit)]);
        }
    }

    // s0
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[little_s0_bit(bit)] + F::ONE) * curr_row[little_s0_bit(bit)]);
    }

    // s1
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[little_s1_bit(bit)] + F::ONE) * curr_row[little_s1_bit(bit)]);
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
        yield_constr.constraint(
            (-curr_row[not_e_and_g_bit(bit)] + F::ONE) * curr_row[not_e_and_g_bit(bit)],
        );
    }

    // e and f
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[e_and_f_bit(bit)] + F::ONE) * curr_row[e_and_f_bit(bit)]);
    }

    // ch
    for bit in 0..32 {
        yield_constr.constraint((-curr_row[ch_bit(bit)] + F::ONE) * curr_row[ch_bit(bit)]);
    }

    // a and b
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[a_and_b_bit(bit)] + F::ONE) * curr_row[a_and_b_bit(bit)]);
    }

    // a and c
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[a_and_c_bit(bit)] + F::ONE) * curr_row[a_and_c_bit(bit)]);
    }

    // b and c
    for bit in 0..32 {
        yield_constr
            .constraint((-curr_row[b_and_c_bit(bit)] + F::ONE) * curr_row[b_and_c_bit(bit)]);
    }

    // maj
    for bit in 0..32 {
        yield_constr.constraint((-curr_row[maj_bit(bit)] + F::ONE) * curr_row[maj_bit(bit)]);
    }

    // tmps
    for i in 0..5 {
        for bit in 0..32 {
            yield_constr.constraint((-curr_row[xor_tmp_i_bit(i, bit)] + F::ONE) * curr_row[xor_tmp_i_bit(i, bit)])
        }
    }
}
