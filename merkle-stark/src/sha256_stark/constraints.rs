use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;

use super::layout::*;
use crate::constraint_consumer::ConstraintConsumer;

// TODO implement phases
// TODO constrain cols that shouldn't change during each phase

// 4 "INSNS" (stages) of the STARK
// 0. (8 rows) load input from input colums into wis, two 32-bit limbs at a time from LEFT_INPUT_COL and RIGHT_INPUT_COL respectively and shift to right. Set his to IV.
// 1. (48 rows) shift wis left by 1, append / compute next WI, perform 1 round of message schedule and round fn, load a-h as his during first row
// 2. (16 rows) shift wis left by 1, perform 1 round of round fn. on last row, update his
// 3. (8 rows) shift his left by 1, append original hi. Copy leftmost hi to output col and add hash_idx * 1 << 32 to it to signify which has it's for
// Output col should be zero every row except for the last 8 of a hash.
// Input col should be zero every row except for the
// All 32-bit integers, including constants, are assumed to be big-endian

pub const NUM_PHASES: usize = 4;
pub const NUM_PHASE_0_ROWS: usize = 8;
pub const NUM_PHASE_1_ROWS: usize = 48;
pub const NUM_PHASE_2_ROWS: usize = 16;
pub const NUM_PHASE_3_ROWS: usize = 8;

// initial values for the digest limbs as big-endian integers
pub const HIS_IV: [u32; 8] = [
    u32::from_be(0x6a09e668),
    u32::from_be(0xbb67ae85),
    u32::from_be(0x3c6ef372),
    u32::from_be(0xa54ff53a),
    u32::from_be(0x510e527f),
    u32::from_be(0x9b05688c),
    u32::from_be(0x1f83d9ab),
    u32::from_be(0x5be0cd19),
];

pub const KIS: [u32; 64] = [
    u32::from_be(0x428a2f98),
    u32::from_be(0x71374491),
    u32::from_be(0xb5c0fbcf),
    u32::from_be(0xe9b5dba5),
    u32::from_be(0x3956c25b),
    u32::from_be(0x59f111f1),
    u32::from_be(0x923f82a4),
    u32::from_be(0xab1c5ed5),
    u32::from_be(0xd807aa98),
    u32::from_be(0x12835b01),
    u32::from_be(0x243185be),
    u32::from_be(0x550c7dc3),
    u32::from_be(0x72be5d74),
    u32::from_be(0x80deb1fe),
    u32::from_be(0x9bdc06a7),
    u32::from_be(0xc19bf174),
    u32::from_be(0xe49b69c1),
    u32::from_be(0xefbe4786),
    u32::from_be(0x0fc19dc6),
    u32::from_be(0x240ca1cc),
    u32::from_be(0x2de92c6f),
    u32::from_be(0x4a7484aa),
    u32::from_be(0x5cb0a9dc),
    u32::from_be(0x76f988da),
    u32::from_be(0x983e5152),
    u32::from_be(0xa831c66d),
    u32::from_be(0xb00327c8),
    u32::from_be(0xbf597fc7),
    u32::from_be(0xc6e00bf3),
    u32::from_be(0xd5a79147),
    u32::from_be(0x06ca6351),
    u32::from_be(0x14292967),
    u32::from_be(0x27b70a85),
    u32::from_be(0x2e1b2138),
    u32::from_be(0x4d2c6dfc),
    u32::from_be(0x53380d13),
    u32::from_be(0x650a7354),
    u32::from_be(0x766a0abb),
    u32::from_be(0x81c2c92e),
    u32::from_be(0x92722c85),
    u32::from_be(0xa2bfe8a1),
    u32::from_be(0xa81a664b),
    u32::from_be(0xc24b8b70),
    u32::from_be(0xc76c51a3),
    u32::from_be(0xd192e819),
    u32::from_be(0xd6990624),
    u32::from_be(0xf40e3585),
    u32::from_be(0x106aa070),
    u32::from_be(0x19a4c116),
    u32::from_be(0x1e376c08),
    u32::from_be(0x2748774c),
    u32::from_be(0x34b0bcb5),
    u32::from_be(0x391c0cb3),
    u32::from_be(0x4ed8aa4a),
    u32::from_be(0x5b9cca4f),
    u32::from_be(0x682e6ff3),
    u32::from_be(0x748f82ee),
    u32::from_be(0x78a5636f),
    u32::from_be(0x84c87814),
    u32::from_be(0x8cc70208),
    u32::from_be(0x90befffa),
    u32::from_be(0xa4506ceb),
    u32::from_be(0xbef9a3f7),
    u32::from_be(0xc67178f2),
];

/// compute field_representation of a sequence of 32 bits interpreted big-endian u32 of a specific element of an trace array
macro_rules! bit_decomp_32_at_idx {
    ($row:expr, $idx:expr, $col_fn:ident, $f:ty, $p:ty) => {
        ((0..32).fold(<$p>::ZEROS, |acc, i| {
            acc + $row[$col_fn($idx, i)] * <$f>::from_canonical_u64(1 << i)
        }))
    };
}

/// compute field_representation of a sequence of 32 bits interpreted bigendian u32
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

/// Computes the arithmetic generalization of `xor3(x, y, z)`.
pub(crate) fn xor3_gen<P: PackedField>(x: P, y: P, z: P) -> P {
    xor_gen(x, xor_gen(y, z))
}

fn eval_msg_schedule<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    let in_phase_1 = curr_row[phase_bit(0)];

    // s0 := (w[i-15] >>>  7) xor (w[i-15] >>> 18) xor (w[i-15] >>  3)

    for bit in 3..32 {
        let computed_bit = xor_gen(
            curr_row[wi_bit(1, (bit + 32 - 7) % 32)],
            curr_row[wi_bit(1, (bit + 14) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[xor_tmp_i_bit(0, bit)] - computed_bit));

        let computed_bit = xor_gen(
            curr_row[xor_tmp_i_bit(0, bit)],
            curr_row[wi_bit(1, bit - 3)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[little_s0_bit(bit)] - computed_bit));
    }
    for bit in 0..3 {
        // we can ignore the second XOR in this case since it's with 0
        let computed_bit = xor_gen(
            curr_row[wi_bit(1, (bit + 32 - 7) % 32)],
            curr_row[wi_bit(1, (bit + 14) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[little_s0_bit(bit)] - computed_bit));
    }

    // s1 := (w[i-2] >>> 17) xor (w[i-2] >>> 19) xor (w[i-2] >> 10)

    for bit in 10..32 {
        let computed_bit = xor_gen(
            curr_row[wi_bit(14, (bit + 15) % 32)],
            curr_row[wi_bit(14, (bit + 13) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[xor_tmp_i_bit(1, bit)] - computed_bit));

        let computed_bit = xor_gen(
            curr_row[xor_tmp_i_bit(1, bit)],
            curr_row[wi_bit(14, bit - 10)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[little_s1_bit(bit)] - computed_bit));
    }
    for bit in 0..10 {
        // we can ignore the second XOR in this case since it's with 0
        let computed_bit = xor_gen(
            curr_row[wi_bit(14, (bit + 15) % 32)],
            curr_row[wi_bit(14, (bit + 13) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1 * (curr_row[little_s1_bit(bit)] - computed_bit));
    }

    // w[i] := w[i-16] + s0 + w[i-7] + s1
    // w[i] goes in the rightmost WI column of the next row,
    // shift of wis happens in `eval_shift_wis`

    // degree 1
    let s0_field_computed = bit_decomp_32!(curr_row, little_s0_bit, F, P);
    let s1_field_computed = bit_decomp_32!(curr_row, little_s1_bit, F, P);
    let wi_minus_16_field_computed = bit_decomp_32_at_idx!(curr_row, 0, wi_bit, F, P);
    let wi_minus_7_field_computed = bit_decomp_32_at_idx!(curr_row, 9, wi_bit, F, P);

    // degree 2
    yield_constr.constraint(
        in_phase_1
            * (curr_row[WI_FIELD]
                - (wi_minus_16_field_computed
                    + s0_field_computed
                    + wi_minus_7_field_computed
                    + s1_field_computed)),
    );
    // degree 3
    yield_constr
        .constraint(in_phase_1 * (curr_row[WI_FIELD] - (curr_row[WI_U32] * curr_row[WI_QUOTIENT])));
    // degree 2
    let wi_u32_computed = bit_decomp_32_at_idx!(next_row, 15, wi_bit, F, P);
    yield_constr.constraint(in_phase_1 * (curr_row[WI_U32] - wi_u32_computed));
}

fn eval_shift_wis<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    // shift the wis left by one for the next row if in phase 1 or 2
    let in_phase_1 = curr_row[phase_bit(0)];
    let in_phase_2 = curr_row[phase_bit(1)];
    // degree 1
    let in_phase_1_or_2 = in_phase_1 + in_phase_2;

    for i in 1..16 {
        for bit in 0..32 {
            // degree 2
            yield_constr.constraint_transition(
                in_phase_1_or_2 * (next_row[wi_bit(i - 1, bit)] - curr_row[wi_bit(i, bit)]),
            );
        }
    }

    // keep wis the same in phase 3
    // degree 1
    let in_phase_3 = curr_row[phase_bit(2)];
    for i in 1..16 {
        for bit in 0..32 {
            // degree 2
            yield_constr.constraint_transition(
                in_phase_1_or_2 * (next_row[wi_bit(i, bit)] - curr_row[wi_bit(i, bit)]),
            );
        }
    }
}

fn eval_round_fn<F, P>(curr_row: &[P; NUM_COLS], next_row: &[P; NUM_COLS], yield_constr: &mut ConstraintConsumer<P>)
where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    let in_phase_1_or_2 = curr_row[phase_bit(0)] + curr_row[phase_bit(1)];
    // S1 := (e >>> 6) xor (e >>> 11) xor (e >>> 25)
    for bit in 0..32 {
        let computed_bit = xor_gen(
            curr_row[e_bit((bit + 32 - 6) % 32)],
            curr_row[e_bit((bit + 32 - 11) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[xor_tmp_i_bit(2, bit)] - computed_bit));

        let computed_bit = xor_gen(
            curr_row[xor_tmp_i_bit(2, bit)],
            curr_row[e_bit((bit + 7) % 32)],
        );
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[big_s1_bit(bit)] - computed_bit));
    }

    // ch := (e and f) xor ((not e) and g)
    for bit in 0..32 {
        let computed_bit = curr_row[e_bit(bit)] * curr_row[f_bit(bit)];
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[e_and_f_bit(bit)] - computed_bit));

        let computed_bit = (-curr_row[e_bit(bit)] + F::ONE) * curr_row[g_bit(bit)];
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[not_e_and_g_bit(bit)] - computed_bit));

        let computed_bit = xor_gen(curr_row[e_and_f_bit(bit)], curr_row[not_e_and_g_bit(bit)]);
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[ch_bit(bit)] - computed_bit));
    }

    // S0 := (a >>> 2) xor (a >>> 13) xor (a >>> 22)
    for bit in 0..32 {
        let computed_bit = xor_gen(curr_row[a_bit((bit + 32 - 2) % 32)], curr_row[a_bit((bit + 32 - 13) % 32)]);
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[xor_tmp_i_bit(3, bit)] - computed_bit));
      
        let computed_bit = xor_gen(curr_row[xor_tmp_i_bit(3, bit)], curr_row[a_bit((bit + 10) % 32)]);
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[big_s0_bit(bit)] - computed_bit));
    }

    // maj := (a and b) xor (a and c) xor (b and c)
    for bit in 0..32 {
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[a_and_b_bit(bit)] - curr_row[a_bit(bit)] * curr_row[b_bit(bit)]));

        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[a_and_c_bit(bit)] - curr_row[a_bit(bit)] * curr_row[c_bit(bit)]));

        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[b_and_c_bit(bit)] - curr_row[b_bit(bit)] * curr_row[c_bit(bit)]));

        let computed_bit = xor_gen(curr_row[a_and_b_bit(bit)], curr_row[a_and_c_bit(bit)]);
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[xor_tmp_i_bit(4, bit)] - computed_bit));

        let computed_bit = xor_gen(curr_row[xor_tmp_i_bit(4, bit)], curr_row[b_and_c_bit(bit)]);
        // degree 3
        yield_constr.constraint(in_phase_1_or_2 * (curr_row[maj_bit(bit)] - computed_bit));
    }

    // temp1 := h + S1 + ch + k[i] + w[i]
    // e := d + temp1
	let h_field = bit_decomp_32!(curr_row, h_bit, F, P);
	let big_s1_field = bit_decomp_32!(curr_row, big_s1_bit, F, P);
	let ch_field = bit_decomp_32!(curr_row, ch_bit, F, P);
    let temp1_minus_ki = h_field + big_s1_field + ch_field;

    let d_field = bit_decomp_32!(curr_row, d_bit, F, P);
    let e_u32_next = bit_decomp_32!(next_row, e_bit, F, P);
    for step in 8..72 {
        // degree 2
        yield_constr.constraint(curr_row[step_bit(step)] * (curr_row[E_NEXT_FIELD] - (d_field + temp1_minus_ki + F::from_canonical_u32(KIS[step - 8]))));
    }
    // degree 3
    yield_constr.constraint_transition(in_phase_1_or_2 * (curr_row[E_NEXT_FIELD] - e_u32_next * curr_row[E_NEXT_QUOTIENT]));

    // temp2 := S0 + maj
    // a := temp1 + temp2
    let s0_field = bit_decomp_32!(curr_row, big_s0_bit, F, P);
    let maj_field = bit_decomp_32!(curr_row, maj_bit, F, P);
    let temp2 = s0_field + maj_field;
    let a_u32_next = bit_decomp_32!(next_row, a_bit, F, P);
    for step in 8..72 {
        // degree 2
        yield_constr.constraint(curr_row[step_bit(step)] * (curr_row[A_NEXT_FIELD] - (temp2 + temp1_minus_ki + F::from_canonical_u32(KIS[step - 8]))));
    }
    // degree 3
    yield_constr.constraint(in_phase_1_or_2 * (curr_row[A_NEXT_FIELD] - a_u32_next * curr_row[A_NEXT_QUOTIENT]));


    // h := g
    // g := f
    // f := e
    // d := c
    // c := b
    // b := a
    for bit in 0..32 {
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[h_bit(bit)] - curr_row[g_bit(bit)]));
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[g_bit(bit)] - curr_row[f_bit(bit)]));
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[f_bit(bit)] - curr_row[e_bit(bit)]));
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[d_bit(bit)] - curr_row[c_bit(bit)]));
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[c_bit(bit)] - curr_row[b_bit(bit)]));
        yield_constr.constraint_transition(in_phase_1_or_2 * (next_row[b_bit(bit)] - curr_row[a_bit(bit)]));
    }
}

fn eval_first_row_of_hash<F, P>(
    curr_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    // set his to initial values
    for i in 0..8 {
        yield_constr.constraint(curr_row[step_bit(0)] * (curr_row[h_i(i)] - F::from_canonical_u32(HIS_IV[i])));
    }
}

fn eval_phase_0<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    // degree 1
    let phase_selector =
        -curr_row[phase_bit(0)] - curr_row[phase_bit(1)] - curr_row[phase_bit(2)] + F::ONE;

    // do a bit decomposition of the left and right inputs, also checking hash idx
    let decomp_left = bit_decomp_32_at_idx!(curr_row, NUM_WIS - 2, wi_bit, F, P)
        + curr_row[HASH_IDX] *  F::from_canonical_u64(1 << 32);
    let decomp_right = bit_decomp_32_at_idx!(curr_row, NUM_WIS - 1, wi_bit, F, P)
        + curr_row[HASH_IDX] * F::from_canonical_u64(1 << 32);

    // degree 2
    yield_constr.constraint(phase_selector * (decomp_left - curr_row[LEFT_INPUT_COL]));
    // degree 2
    yield_constr.constraint(phase_selector * (decomp_right - curr_row[RIGHT_INPUT_COL]));

    // shift the next wi bits over by 2
    for i in 2..NUM_WIS {
        for bit in 0..32 {
            // degree 2
            yield_constr.constraint_transition(
                phase_selector * (next_row[wi_bit(i - 2, bit)] - curr_row[wi_bit(i, bit)]),
            );
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

    // degree 1
    let phase_selector = curr_row[phase_bit(0)];

    // msg schedule
    // round fn
    // shift wis left by one
}

fn eval_phase_transitions<F, P>(
    curr_row: &[P; NUM_COLS],
    next_row: &[P; NUM_COLS],
    yield_constr: &mut ConstraintConsumer<P>,
) where
    F: RichField,
    P: PackedField<Scalar = F>,
{
    let phase_0_selector = -curr_row[phase_bit(0)]
        - curr_row[phase_bit(1)]
        - curr_row[phase_bit(2)]
        - curr_row[phase_bit(3)]
        + F::ONE;
    let phase_1_selector = curr_row[phase_bit(0)];
    let phase_2_selector = curr_row[phase_bit(1)];
    let phase_3_selector = curr_row[phase_bit(2)];

    let phase_0_selector_next =
        -next_row[phase_bit(0)] - next_row[phase_bit(1)] - next_row[phase_bit(2)] + F::ONE;
    let phase_1_selector_next = next_row[phase_bit(0)];
    let phase_2_selector_next = next_row[phase_bit(1)];
    let phase_3_selector_next = next_row[phase_bit(2)];

    // ensure phase is only one of possible values
    // degree 2
    yield_constr.constraint(
        phase_0_selector + phase_1_selector + phase_2_selector + phase_3_selector - F::ONE,
    );

    // degree 2
    let transition_0_selector = phase_0_selector * (-phase_0_selector_next + F::ONE);
    let transition_1_selector = phase_1_selector * (-phase_1_selector_next + F::ONE);
    let transition_2_selector = phase_2_selector * (-phase_2_selector_next + F::ONE);
    let transition_3_selector = phase_3_selector * (-phase_3_selector_next + F::ONE);

    let not_in_transition =
        -transition_0_selector - transition_1_selector + F::ONE;

    // set initial step bits to a 1 followed by NUM_STEPS_PER_HASH-1 0s
    yield_constr.constraint_first_row(curr_row[step_bit(0)] - F::ONE);
    for step in 1..NUM_STEPS_PER_HASH {
        yield_constr.constraint_first_row(curr_row[step_bit(step)]);
    }

    // inc step bits
    for bit in 0..NUM_STEPS_PER_HASH {
        // degree 3
        yield_constr.constraint_transition(not_in_transition * (next_row[step_bit((bit + 1) % NUM_STEPS_PER_HASH)] - curr_row[step_bit(bit)]));
    }

    // ensure phase stays the same when not transitioning to next phase
    for bit in 0..4 {
        // degree 3
        yield_constr.constraint_transition(
            not_in_transition * (next_row[phase_bit(bit)] - curr_row[phase_bit(bit)]),
        );
    }

    // ensure phase transitions are correct
    // degree 3
    yield_constr.constraint_transition(-(transition_0_selector * phase_1_selector_next) + F::ONE);
    yield_constr.constraint_transition(-(transition_1_selector * phase_2_selector_next) + F::ONE);
    yield_constr.constraint_transition(-(transition_2_selector * phase_3_selector_next) + F::ONE);
    yield_constr.constraint_transition(-(transition_3_selector * phase_0_selector_next) + F::ONE);

    // ensure phase transitions happen after correct number of rows
    yield_constr
        .constraint_transition(transition_0_selector * next_row[step_bit(8)]);
    yield_constr.constraint_transition(transition_1_selector * next_row[step_bit(56)]);
    yield_constr.constraint_transition(transition_2_selector * next_row[step_bit(72)]);
    yield_constr.constraint_transition(transition_3_selector * next_row[step_bit(0)]);
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
    for bit in 0..NUM_PHASES {
        yield_constr.constraint((-curr_row[phase_bit(bit)] + F::ONE) * curr_row[phase_bit(bit)]);
    }

    // step bits
    for bit in 0..NUM_STEPS_PER_HASH {
        yield_constr.constraint((-curr_row[phase_bit(bit)] + F::ONE) * curr_row[phase_bit(bit)]);
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
}
