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
use plonky2_util::log2_ceil;

use crate::{
    constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer},
    stark::Stark,
    vars::{StarkEvaluationTargets, StarkEvaluationVars},
};

pub mod constants;
pub mod generation;
pub mod layout;

use generation::{to_u32_array_be, Sha2TraceGenerator};
use layout::*;

use self::constants::{HASH_IV, ROUND_CONSTANTS};

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

#[derive(Copy, Clone)]
pub struct Sha2CompressionStark<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Sha2CompressionStark<F, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
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

        // set hash idx to 1 at the start. hash_idx should be 1-indexed.
        yield_constr.constraint_first_row(P::ONES - curr_row[HASH_IDX]);

        // set his to initial values at start of hash
        let is_hash_start = curr_row[step_bit(0)];
        for i in 0..8 {
            // degree 3
            yield_constr
                .constraint(is_hash_start * (curr_row[h_i(i)] - FE::from_canonical_u32(HASH_IV[i])));
        }

        // ensure his stay the same outside last two rows of hash
        let his_should_change = next_row[step_bit(64)] + curr_row[step_bit(64)];
        for i in 0..8 {
            // degree 2
            yield_constr.constraint_transition((P::ONES - his_should_change) * (next_row[h_i(i)] - curr_row[h_i(i)]));
        }

        let next_is_phase_0: P = (0..16).map(|i| next_row[step_bit(i)]).sum();
        let next_is_phase_1: P = (16..64).map(|i| next_row[step_bit(i)]).sum();
        let next_is_not_padding = next_is_phase_0 + next_is_phase_1 + next_row[step_bit(64)];

        // increment hash idx if we're at the last step and next isn't padding
        let is_last_step = curr_row[step_bit(64)];
        let transition_to_next_hash = is_last_step * next_is_not_padding;
        // degree 3
        yield_constr.constraint_transition(
            transition_to_next_hash * (P::ONES - (next_row[HASH_IDX] - curr_row[HASH_IDX])),
        );

        // otherwise ensure hash idx stays the same unless next row is padding
        // degree 3
        yield_constr.constraint_transition(
            (P::ONES - is_last_step)
                * next_is_not_padding
                * (next_row[HASH_IDX] - curr_row[HASH_IDX]),
        );

        // load input into wis rotated left by one at start
        for i in 0..16 {
            let decomp = bit_decomp_32_at_idx!(curr_row, i, wi_bit, FE, P)
                + curr_row[HASH_IDX] * FE::from_canonical_u64(1 << 32);

            yield_constr.constraint(is_hash_start * (decomp - curr_row[input_i((i + 1) % 16)]));
        }

        // set input filter to 1 iff we're at the start, zero otherwise
        yield_constr.constraint(is_hash_start * (P::ONES - curr_row[INPUT_FILTER]));
        yield_constr.constraint((P::ONES - is_hash_start) * curr_row[INPUT_FILTER]);

        // rotate wis when next step is phase 0 and we're not starting a new hash
        let rotate_wis = next_is_phase_0 * (P::ONES - next_row[step_bit(0)]);
        for i in 0..16 {
            for bit in 0..32 {
                // degree 3
                yield_constr.constraint_transition(
                    rotate_wis * (next_row[wi_bit(i, bit)] - curr_row[wi_bit((i + 1) % 16, bit)]),
                );
            }
        }

        // shift wis left when next step is phase 1
        let shift_wis = next_is_phase_1;
        for i in 0..15 {
            for bit in 0..32 {
                // degree 2
                yield_constr.constraint_transition(
                    shift_wis * (next_row[wi_bit(i, bit)] - curr_row[wi_bit(i + 1, bit)]),
                );
            }
        }

        // round fn in phase 0 or 1
        let is_phase_0_or_1: P = (0..64).map(|i| curr_row[step_bit(i)]).sum();

        // S1 := (e >>> 6) xor (e >>> 11) xor (e >>> 25)
        for bit in 0..32 {
            let computed_bit = xor_gen(
                curr_row[e_bit((bit + 6) % 32)],
                curr_row[e_bit((bit + 11) % 32)],
            );
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[xor_tmp_2_bit(bit)] - computed_bit));

            let computed_bit = xor_gen(
                curr_row[xor_tmp_2_bit(bit)],
                curr_row[e_bit((bit + 25) % 32)],
            );
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[big_s1_bit(bit)] - computed_bit));
        }

        // ch := (e and f) xor ((not e) and g)
        for bit in 0..32 {
            let computed_bit = curr_row[e_bit(bit)] * curr_row[f_bit(bit)];
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[e_and_f_bit(bit)] - computed_bit));

            let computed_bit = (P::ONES - curr_row[e_bit(bit)]) * curr_row[g_bit(bit)];
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[not_e_and_g_bit(bit)] - computed_bit));

            let computed_bit = xor_gen(curr_row[e_and_f_bit(bit)], curr_row[not_e_and_g_bit(bit)]);
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[ch_bit(bit)] - computed_bit));
        }

        // S0 := (a >>> 2) xor (a >>> 13) xor (a >>> 22)
        for bit in 0..32 {
            let computed_bit = xor_gen(
                curr_row[a_bit((bit + 2) % 32)],
                curr_row[a_bit((bit + 13) % 32)],
            );
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[xor_tmp_3_bit(bit)] - computed_bit));

            let computed_bit = xor_gen(
                curr_row[xor_tmp_3_bit(bit)],
                curr_row[a_bit((bit + 22) % 32)],
            );
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[big_s0_bit(bit)] - computed_bit));
        }

        // maj := (a and b) xor (a and c) xor (b and c)
        for bit in 0..32 {
            // degree 3
            yield_constr.constraint(
                is_phase_0_or_1
                    * (curr_row[a_and_b_bit(bit)] - curr_row[a_bit(bit)] * curr_row[b_bit(bit)]),
            );

            // degree 3
            yield_constr.constraint(
                is_phase_0_or_1
                    * (curr_row[a_and_c_bit(bit)] - curr_row[a_bit(bit)] * curr_row[c_bit(bit)]),
            );

            // degree 3
            yield_constr.constraint(
                is_phase_0_or_1
                    * (curr_row[b_and_c_bit(bit)] - curr_row[b_bit(bit)] * curr_row[c_bit(bit)]),
            );

            let computed_bit = xor_gen(curr_row[a_and_b_bit(bit)], curr_row[a_and_c_bit(bit)]);
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[xor_tmp_4_bit(bit)] - computed_bit));

            let computed_bit = xor_gen(curr_row[xor_tmp_4_bit(bit)], curr_row[b_and_c_bit(bit)]);
            // degree 3
            yield_constr.constraint(is_phase_0_or_1 * (curr_row[maj_bit(bit)] - computed_bit));
        }

        // set round constant
        for step in 0..64 {
            // degree 2
            yield_constr.constraint(
                curr_row[step_bit(step)]
                    * (curr_row[KI] - FE::from_canonical_u32(ROUND_CONSTANTS[step])),
            );
        }

        // temp1 := h + S1 + ch + k[i] + w[i]
        // e := d + temp1
        let h_field = bit_decomp_32!(curr_row, h_bit, FE, P);
        let big_s1_field = bit_decomp_32!(curr_row, big_s1_bit, FE, P);
        let ch_field = bit_decomp_32!(curr_row, ch_bit, FE, P);
        let wi_u32 = bit_decomp_32_at_idx!(curr_row, 15, wi_bit, FE, P);
        let temp1_minus_ki = h_field + big_s1_field + ch_field + wi_u32;

        let d_field = bit_decomp_32!(curr_row, d_bit, FE, P);
        let e_u32_next = bit_decomp_32!(next_row, e_bit, FE, P);

        // degree 2
        yield_constr.constraint(
            is_phase_0_or_1 * (curr_row[E_NEXT_FIELD] - (d_field + temp1_minus_ki + curr_row[KI])),
        );
        // degree 3
        yield_constr.constraint_transition(
            is_phase_0_or_1
                * (curr_row[E_NEXT_FIELD]
                    - (e_u32_next + curr_row[E_NEXT_QUOTIENT] * FE::from_canonical_u64(1 << 32))),
        );

        // temp2 := S0 + maj
        // a := temp1 + temp2
        let s0_field = bit_decomp_32!(curr_row, big_s0_bit, FE, P);
        let maj_field = bit_decomp_32!(curr_row, maj_bit, FE, P);
        let temp2 = s0_field + maj_field;
        let a_u32_next = bit_decomp_32!(next_row, a_bit, FE, P);

        // degree 2
        yield_constr.constraint(
            is_phase_0_or_1 * (curr_row[A_NEXT_FIELD] - (temp2 + temp1_minus_ki + curr_row[KI])),
        );
        // degree 3
        yield_constr.constraint(
            is_phase_0_or_1
                * (curr_row[A_NEXT_FIELD]
                    - (a_u32_next + curr_row[A_NEXT_QUOTIENT] * FE::from_canonical_u64(1 << 32))),
        );

        // update local vars when not in last step
        // h := g
        // g := f
        // f := e
        // d := c
        // c := b
        // b := a
        for bit in 0..32 {
            // degree 2
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[h_bit(bit)] - curr_row[g_bit(bit)]));
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[g_bit(bit)] - curr_row[f_bit(bit)]));
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[f_bit(bit)] - curr_row[e_bit(bit)]));
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[d_bit(bit)] - curr_row[c_bit(bit)]));
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[c_bit(bit)] - curr_row[b_bit(bit)]));
            yield_constr
                .constraint_transition(is_phase_0_or_1 * (next_row[b_bit(bit)] - curr_row[a_bit(bit)]));
        }

        // update his in last step of phase 1
        let update_his = curr_row[step_bit(63)];
        let vars = [
            bit_decomp_32!(next_row, a_bit, FE, P),
            bit_decomp_32!(next_row, b_bit, FE, P),
            bit_decomp_32!(next_row, c_bit, FE, P),
            bit_decomp_32!(next_row, d_bit, FE, P),
            bit_decomp_32!(next_row, e_bit, FE, P),
            bit_decomp_32!(next_row, f_bit, FE, P),
            bit_decomp_32!(next_row, g_bit, FE, P),
            bit_decomp_32!(next_row, h_bit, FE, P),
        ];

        for i in 0..8 {
            // degree 2
            yield_constr.constraint_transition(
                update_his * (curr_row[h_i_next_field(i)] - (curr_row[h_i(i)] + vars[i])),
            );

            // degree 3
            yield_constr.constraint_transition(
                update_his
                    * (curr_row[h_i_next_field(i)]
                        - (next_row[h_i(i)]
                            + curr_row[h_i_next_quotient(i)] * FE::from_canonical_u64(1 << 32))),
            );
        }

        // set output to his during last step, 0 otherwise
        for i in 0..8 {
            // degree 2
            yield_constr.constraint(
                is_last_step
                    * (curr_row[output_i(i)]
                        - (curr_row[h_i(i)]
                            + curr_row[HASH_IDX] * FE::from_canonical_u64(1 << 32))),
            );
            yield_constr.constraint((P::ONES - is_last_step) * curr_row[output_i(i)])
        }


        // set output filter to 1 iff it's the last step, zero otherwise
        yield_constr.constraint(is_last_step * (P::ONES - curr_row[OUTPUT_FILTER]));
        yield_constr.constraint((P::ONES - is_last_step) * curr_row[OUTPUT_FILTER]);

        // message schedule to get next row's wi when next row is in phase 1

        let do_msg_schedule = next_is_phase_1;

        // s0 := (w[i-15] >>> 7) xor (w[i-15] >>> 18) xor (w[i-15] >> 3)
        for bit in 0..29 {
            let computed_bit = xor_gen(
                next_row[wi_bit(0, (bit + 7) % 32)],
                next_row[wi_bit(0, (bit + 18) % 32)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[xor_tmp_0_bit(bit)] - computed_bit),
            );

            let computed_bit = xor_gen(
                next_row[xor_tmp_0_bit(bit)],
                next_row[wi_bit(0, bit + 3)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[little_s0_bit(bit)] - computed_bit),
            );
        }
        for bit in 29..32 {
            // we can ignore the second XOR in this case since it's with 0
            let computed_bit = xor_gen(
                next_row[wi_bit(0, (bit + 7) % 32)],
                next_row[wi_bit(0, (bit + 18) % 32)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[little_s0_bit(bit)] - computed_bit),
            );
        }

        // s1 := (w[i-2] >>> 17) xor (w[i-2] >>> 19) xor (w[i-2] >> 10)

        for bit in 0..22 {
            let computed_bit = xor_gen(
                next_row[wi_bit(13, (bit + 17) % 32)],
                next_row[wi_bit(13, (bit + 19) % 32)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[xor_tmp_1_bit(bit)] - computed_bit),
            );

            let computed_bit = xor_gen(
                next_row[xor_tmp_1_bit(bit)],
                next_row[wi_bit(13, bit + 10)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[little_s1_bit(bit)] - computed_bit),
            );
        }
        for bit in 22..32 {
            // we can ignore the second XOR in this case since it's with 0
            let computed_bit = xor_gen(
                next_row[wi_bit(13, (bit + 17) % 32)],
                next_row[wi_bit(13, (bit + 19) % 32)],
            );
            // degree 3
            yield_constr.constraint_transition(
                do_msg_schedule * (next_row[little_s1_bit(bit)] - computed_bit),
            );
        }

        // w[i] := w[i-16] + s0 + w[i-7] + s1

        // degree 1
        let s0_field_computed = bit_decomp_32!(next_row, little_s0_bit, FE, P);
        let s1_field_computed = bit_decomp_32!(next_row, little_s1_bit, FE, P);
        let wi_minus_16_field_computed = bit_decomp_32_at_idx!(curr_row, 0, wi_bit, FE, P);
        let wi_minus_7_field_computed = bit_decomp_32_at_idx!(next_row, 8, wi_bit, FE, P);
        let wi = bit_decomp_32_at_idx!(next_row, 15, wi_bit, FE, P);

        // degree 2
        yield_constr.constraint_transition(
            do_msg_schedule
                * (next_row[WI_FIELD]
                    - (wi_minus_16_field_computed
                        + s0_field_computed
                        + wi_minus_7_field_computed
                        + s1_field_computed)),
        );
        // degree 3
        yield_constr.constraint(
            do_msg_schedule
                * (next_row[WI_FIELD]
                    - (wi + next_row[WI_QUOTIENT] * FE::from_canonical_u64(1 << 32))),
        );

        // set initial step bits to a 1 followed by NUM_STEPS_PER_HASH-1 0s
        yield_constr.constraint_first_row(P::ONES - curr_row[step_bit(0)]);
        for step in 1..NUM_STEPS_PER_HASH {
            yield_constr.constraint_first_row(curr_row[step_bit(step)]);
        }

        // inc step bits when next is not padding
        for bit in 0..NUM_STEPS_PER_HASH {
            // degree 3
            yield_constr.constraint_transition(
                next_is_not_padding
                    * (next_row[step_bit((bit + 1) % NUM_STEPS_PER_HASH)]
                        - curr_row[step_bit(bit)]),
            );
        }

        eval_bits_are_bits(curr_row, yield_constr);
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

fn eval_bits_are_bits<F, P>(curr_row: &[P; NUM_COLS], yield_constr: &mut ConstraintConsumer<P>)
where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // step bits
    for bit in 0..NUM_STEPS_PER_HASH {
        yield_constr.constraint((P::ONES - curr_row[step_bit(bit)]) * curr_row[step_bit(bit)]);
    }

    // wis
    for i in 0..NUM_WIS {
        for bit in 0..32 {
            yield_constr
                .constraint((P::ONES - curr_row[wi_bit(i, bit)]) * curr_row[wi_bit(i, bit)]);
        }
    }

    // s0
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[little_s0_bit(bit)]) * curr_row[little_s0_bit(bit)]);
    }

    // s1
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[little_s1_bit(bit)]) * curr_row[little_s1_bit(bit)]);
    }

    // a
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[a_bit(bit)]) * curr_row[a_bit(bit)]);
    }

    // b
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[b_bit(bit)]) * curr_row[b_bit(bit)]);
    }

    // c
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[c_bit(bit)]) * curr_row[c_bit(bit)]);
    }

    // d
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[d_bit(bit)]) * curr_row[d_bit(bit)]);
    }

    // e
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[e_bit(bit)]) * curr_row[e_bit(bit)]);
    }

    // f
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[f_bit(bit)]) * curr_row[f_bit(bit)]);
    }

    // g
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[g_bit(bit)]) * curr_row[g_bit(bit)]);
    }

    // h
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[h_bit(bit)]) * curr_row[h_bit(bit)]);
    }

    // S0
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[big_s0_bit(bit)]) * curr_row[big_s0_bit(bit)]);
    }

    // S1
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[big_s1_bit(bit)]) * curr_row[big_s1_bit(bit)]);
    }

    // (not e) and g
    for bit in 0..32 {
        yield_constr.constraint(
            (P::ONES - curr_row[not_e_and_g_bit(bit)]) * curr_row[not_e_and_g_bit(bit)],
        );
    }

    // e and f
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[e_and_f_bit(bit)]) * curr_row[e_and_f_bit(bit)]);
    }

    // ch
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[ch_bit(bit)]) * curr_row[ch_bit(bit)]);
    }

    // a and b
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[a_and_b_bit(bit)]) * curr_row[a_and_b_bit(bit)]);
    }

    // a and c
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[a_and_c_bit(bit)]) * curr_row[a_and_c_bit(bit)]);
    }

    // b and c
    for bit in 0..32 {
        yield_constr
            .constraint((P::ONES - curr_row[b_and_c_bit(bit)]) * curr_row[b_and_c_bit(bit)]);
    }

    // maj
    for bit in 0..32 {
        yield_constr.constraint((P::ONES - curr_row[maj_bit(bit)]) * curr_row[maj_bit(bit)]);
    }

    // tmps
    for bit in 0..29 {
        yield_constr.constraint(
            (P::ONES - curr_row[xor_tmp_0_bit(bit)]) * curr_row[xor_tmp_0_bit(bit)],
        );
    }
    for bit in 0..22 {
        yield_constr.constraint(
            (P::ONES - curr_row[xor_tmp_1_bit(bit)]) * curr_row[xor_tmp_1_bit(bit)],
        );
    }
    for bit in 0..32 {
        yield_constr.constraint(
            (P::ONES - curr_row[xor_tmp_2_bit(bit)]) * curr_row[xor_tmp_2_bit(bit)],
        );

        yield_constr.constraint(
            (P::ONES - curr_row[xor_tmp_3_bit(bit)]) * curr_row[xor_tmp_3_bit(bit)],
        );

        yield_constr.constraint(
            (P::ONES - curr_row[xor_tmp_4_bit(bit)]) * curr_row[xor_tmp_4_bit(bit)],
        );
    }
}

pub struct Sha2StarkCompressor {
    inputs: Vec<([u32; 8], [u32; 8])>,
}

impl Sha2StarkCompressor {
    pub fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    pub fn add_instance(&mut self, left_input: [u8; 32], right_input: [u8; 32]) {
        let left = to_u32_array_be(left_input);
        let right = to_u32_array_be(right_input);

        self.inputs.push((left, right));
    }

    /// returns the generated trace against which a proof may be generated
    pub fn generate<F: Field>(self) -> Vec<PolynomialValues<F>> {
        let max_rows = 1 << log2_ceil(self.inputs.len() * NUM_STEPS_PER_HASH);
        let mut generator = Sha2TraceGenerator::<F>::new(max_rows);
        for (left, right) in self.inputs.into_iter() {
            generator.gen_hash(left, right);
        }

        generator.into_polynomial_values()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove;
    use crate::sha256_stark::generation::Sha2TraceGenerator;
    use crate::stark_testing::test_stark_low_degree;
    use crate::verifier::verify_stark_proof;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let stark = S::new();
        test_stark_low_degree(stark)
    }

    // #[test]
    // fn test_stark_circuit() -> Result<()> {
    //     const D: usize = 2;
    //     type C = PoseidonGoldilocksConfig;
    //     type F = <C as GenericConfig<D>>::F;
    //     type S = Sha2CompressionStark<F, D>;

    //     let stark = S::new();

    //     test_stark_circuit_constraints::<F, C, S, D>(stark)
    // }

    #[test]
    fn test_single() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let mut left_input = [0u32; 8];
        let mut right_input = [0u32; 8];
        for i in 0..8 {
            left_input[i] = i as u32;
            right_input[i] = i as u32 + 8;
        }

        let mut generator = Sha2TraceGenerator::<F>::new(128);
        generator.gen_hash(left_input, right_input);

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing)?;

        verify_stark_proof(stark, proof, &config)?;

        Ok(())
    }

    #[test]
    fn test_multiple() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let mut left_input = [0; 32];
        let mut right_input = [0; 32];
        for i in 0..32 {
            left_input[i] = i as u8;
            right_input[i] = i as u8 + 32;
        }

        let mut compressor = Sha2StarkCompressor::new();
        compressor.add_instance(left_input, right_input);

        let mut left_input = [0; 32];
        let mut right_input = [0; 32];
        for i in 0..32 {
            left_input[i] = i as u8 + 64;
            right_input[i] = i as u8 + 96;
        }

        compressor.add_instance(left_input, right_input);
        let trace = compressor.generate();

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing)?;

        verify_stark_proof(stark, proof, &config)?;

        Ok(())
    }
}
