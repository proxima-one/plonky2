/// A STARK that proves variable-time ECGFP5 operations (point additions and 32-bit scalar multiplications).

use std::array;
use std::borrow::Borrow;
use std::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;

pub mod generation;
pub mod layout;
use layout::*;
use plonky2::field::extension::FieldExtension;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;

use crate::constraint_consumer::ConstraintConsumer;
use crate::stark::Stark;
use crate::vars::StarkEvaluationVars;

pub struct Ecgfp5Stark<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize>
    Ecgfp5Stark<F, D, NUM_CHANNELS>
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

// TODO: wrap this in a macro so it can be instasntiated for different sizes
const NUM_CHANNELS: usize = 3;
impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for Ecgfp5Stark<F, D, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    const COLUMNS: usize = ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS;
    const PUBLIC_INPUTS: usize = ECGFP5_NUM_PIS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        // * rust doesn't like using consts for thise
        let curr_row: &Ecgfp5Row<P, 3> = vars.local_values.borrow();
        let next_row: &Ecgfp5Row<P, 3> = vars.next_values.borrow();

        // microcodes flags are binary
        // degree 2
        yield_constr.constraint(curr_row.microcode[0] * (P::ONES - curr_row.microcode[0]));
        yield_constr.constraint(curr_row.microcode[1] * (P::ONES - curr_row.microcode[1]));

        // microcode flags are valid values. We can check this by checking if their sum is binary
        // degree 2
        let microcode_digit_sum = curr_row.microcode[0] + curr_row.microcode[1];
        yield_constr.constraint(microcode_digit_sum * (P::ONES - microcode_digit_sum));

        let curr_microcode_is_add = P::ONES - curr_row.microcode[0] - curr_row.microcode[1];
        let curr_microcode_is_double = curr_row.microcode[0];
        let curr_microcode_is_double_add = curr_row.microcode[1];

        // opcodes are binary
        // degree 2
        yield_constr.constraint(curr_row.opcode[0] * (P::ONES - curr_row.opcode[0]));
        yield_constr.constraint(curr_row.opcode[1] * (P::ONES - curr_row.opcode[1]));

        // opcodes are valid values. We can check this by checking if their sum is binary
        // degree 2
        let opcode_digit_sum = curr_row.opcode[0] + curr_row.opcode[1];
        yield_constr.constraint(opcode_digit_sum * (P::ONES - opcode_digit_sum));

        let curr_opcode_is_add = P::ONES - curr_row.opcode[0] - curr_row.opcode[1];
        let curr_opcode_is_double_and_add = curr_row.opcode[0];
        let curr_opcode_is_scalar_mul = curr_row.opcode[1];

        // is infinity flags must be binary
        yield_constr
            .constraint(curr_row.input_1_is_infinity * (P::ONES - curr_row.input_1_is_infinity));
        yield_constr
            .constraint(curr_row.input_2_is_infinity * (P::ONES - curr_row.input_2_is_infinity));
        yield_constr
            .constraint(curr_row.output_is_infinity * (P::ONES - curr_row.output_is_infinity));
        yield_constr.constraint(
            curr_row.add_lhs_input_is_infinity * (P::ONES - curr_row.add_lhs_input_is_infinity),
        );
        yield_constr.constraint(
            curr_row.add_output_is_infinity * (P::ONES - curr_row.add_lhs_input_is_infinity),
        );
        yield_constr.constraint(
            curr_row.dbl_output_is_infinity * (P::ONES - curr_row.dbl_output_is_infinity),
        );

        // POINT ADDER

        // if microcode is add, or double, then the LHS input is `input_1`
        // if microcode is double and add, then the LHS input is `dbl_output`
        // degree 2
        let lhs_input: Point<P> = [
            array::from_fn(|i| {
                (curr_microcode_is_add + curr_microcode_is_double) * curr_row.input_1[0][i]
                    + curr_microcode_is_double_add * curr_row.dbl_output[0][i]
            }),
            array::from_fn(|i| {
                (curr_microcode_is_add + curr_microcode_is_double) * curr_row.input_1[1][i]
                    + curr_microcode_is_double_add * curr_row.dbl_output[1][i]
            }),
        ];
        for i in 0..5 {
            yield_constr.constraint(curr_row.add_lhs_input[0][i] - lhs_input[0][i]);
            yield_constr.constraint(curr_row.add_lhs_input[1][i] - lhs_input[1][i]);
        }

        // xs_are_same must be binary
        // degree 2
        yield_constr.constraint(curr_row.add_xs_are_same * (P::ONES - curr_row.add_xs_are_same));

        // if xs_are_same is 1, the x1 minus x2 must equal zero
        // degree 3
        let x1_minus_x2 = gfp5_sub(&curr_row.add_lhs_input[0], &curr_row.input_2[0]);
        let filtered = x1_minus_x2.map(|x| x * curr_row.add_xs_are_same);
        constraint_ext_is_zero(&filtered, yield_constr);

        // x1_minus_x2 * x1_minus_x2_inv must be either 1 if xs_are_same zero or zero otherwise
        // degree 3
        let prod = gfp5_mul(&x1_minus_x2, &curr_row.add_x1_minus_x2_inv);
        yield_constr.constraint((P::ONES - curr_row.add_xs_are_same) * (P::ONES - prod[0]));
        yield_constr.constraint(curr_row.add_xs_are_same * prod[0]);
        yield_constr.constraint(prod[1]);
        yield_constr.constraint(prod[2]);
        yield_constr.constraint(prod[3]);
        yield_constr.constraint(prod[4]);

        // same as above, but with ys
        // degree
        yield_constr.constraint(curr_row.add_ys_are_same * (P::ONES - curr_row.add_ys_are_same));

        // degree 3
        let y1_minus_y2 = gfp5_sub(&curr_row.add_lhs_input[1], &curr_row.input_2[1]);
        let filtered = y1_minus_y2.map(|x| x * curr_row.add_ys_are_same);
        constraint_ext_is_zero(&filtered, yield_constr);

        // degree 3
        let prod = gfp5_mul(&y1_minus_y2, &curr_row.add_y1_minus_y2_inv);
        yield_constr.constraint((P::ONES - curr_row.add_ys_are_same) * (P::ONES - prod[0]));
        yield_constr.constraint(curr_row.add_ys_are_same * prod[0]);
        yield_constr.constraint(prod[1]);
        yield_constr.constraint(prod[2]);
        yield_constr.constraint(prod[3]);
        yield_constr.constraint(prod[4]);

        let xs_are_not_same = P::ONES - curr_row.add_xs_are_same;
        // lambda0 = y2 - y1 if xs_are_not_same otherwise 3*x1^2 + A
        let y2_minus_y1 = gfp5_sub(&curr_row.input_2[1], &curr_row.add_lhs_input[1]);
        let three_x1_squared_plus_a = gfp5_add(
            &gfp5_mul(
                &three(),
                &gfp5_mul(&curr_row.add_lhs_input[0], &curr_row.add_lhs_input[0]),
            ),
            &curve_a(),
        );

        for i in 0..5 {
            yield_constr
                .constraint(xs_are_not_same * (curr_row.add_num_lambda[i] - y2_minus_y1[i]));
            yield_constr.constraint(
                (P::ONES - xs_are_not_same)
                    * (curr_row.add_num_lambda[i] - three_x1_squared_plus_a[i]),
            );
        }

        // lambda1 = x2 - x1 if xs_are_not_same otherwise 2*y1
        let x2_minus_x1 = gfp5_sub(&curr_row.input_2[0], &curr_row.add_lhs_input[0]);
        let two_y1 = gfp5_add(&curr_row.add_lhs_input[1], &curr_row.add_lhs_input[1]);

        for i in 0..5 {
            yield_constr
                .constraint(xs_are_not_same * (curr_row.add_denom_lambda[i] - x2_minus_x1[i]));
            yield_constr.constraint(
                (P::ONES - xs_are_not_same) * (curr_row.add_denom_lambda[i] - two_y1[i]),
            );
        }

        // lambda1_is_zero should be binary
        yield_constr.constraint(
            (P::ONES - curr_row.add_lambda_denom_is_zero) * curr_row.add_lambda_denom_is_zero,
        );
        // if lambda1_is_zero then lambda1 and lambda1_inv must both zero
        for i in 0..5 {
            yield_constr
                .constraint(curr_row.add_lambda_denom_is_zero * curr_row.add_denom_lambda[i]);
            yield_constr
                .constraint(curr_row.add_lambda_denom_is_zero * curr_row.add_denom_lambda_inv[i]);
        }

        // lambda1 * lambda1_inv must be 1 unless if lambda1 is zero, in which case it's zero
        let prod = gfp5_mul(&curr_row.add_denom_lambda, &curr_row.add_denom_lambda_inv);
        yield_constr
            .constraint((P::ONES - curr_row.add_lambda_denom_is_zero) * (P::ONES - prod[0]));
        for i in 1..5 {
            yield_constr.constraint((P::ONES - curr_row.add_lambda_denom_is_zero) * prod[i]);
        }

        // lambda = lambda0 * lambda1_inv
        let lambda = gfp5_mul(&curr_row.add_num_lambda, &curr_row.add_denom_lambda_inv);
        constraint_ext_is_equal(&lambda, &curr_row.add_lambda, yield_constr);

        // x3 = lambda^2 - x1 - x2
        let x3 = gfp5_sub(
            &gfp5_sub(
                &gfp5_mul(&curr_row.add_lambda, &curr_row.add_lambda),
                &curr_row.add_lhs_input[0],
            ),
            &curr_row.input_2[0],
        );
        constraint_ext_is_equal(&curr_row.add_x3, &x3, yield_constr);

        // y3 = lambda * (x1 - x3) - y1
        let y3 = gfp5_sub(
            &gfp5_mul(
                &curr_row.add_lambda,
                &gfp5_sub(&curr_row.add_lhs_input[0], &curr_row.add_x3),
            ),
            &curr_row.add_lhs_input[1],
        );

        // I3 = xs_are_same & !ys_are_same = xs_are_same * (1 - ys_are_same)
        // if they're both the same, then it's a doubling, and the result is the point at infinity iff the input is
        let i3 = curr_row.add_xs_are_same * (P::ONES - curr_row.add_ys_are_same);
        yield_constr.constraint(curr_row.add_i3 - i3);

        // conditionally set outputs based on infinity flags
        constraint_ext_is_equal_cond(
            curr_row.add_lhs_input_is_infinity,
            &curr_row.add_output[0],
            &curr_row.input_2[0],
            &curr_row.add_x3,
            yield_constr,
        );
        constraint_ext_is_equal_cond(
            curr_row.add_lhs_input_is_infinity,
            &curr_row.add_output[1],
            &curr_row.input_2[1],
            &y3,
            yield_constr,
        );
        yield_constr.constraint(
            curr_row.add_lhs_input_is_infinity
                * (curr_row.add_output_is_infinity - curr_row.input_2_is_infinity),
        );
        yield_constr.constraint(
            curr_row.input_2_is_infinity
                * (curr_row.add_output_is_infinity - curr_row.add_lhs_input_is_infinity),
        );

        let i1_or_i2 = or_gen(
            curr_row.add_lhs_input_is_infinity,
            curr_row.input_2_is_infinity,
        );
        yield_constr
            .constraint((P::ONES - i1_or_i2) * (curr_row.add_output_is_infinity - curr_row.add_i3));

        // POINT DOUBLER

        // lambda0 = 3*x1^2 + A
        let three_x1_squared_plus_a = gfp5_add(
            &gfp5_mul(
                &three(),
                &gfp5_mul(&curr_row.input_1[0], &curr_row.input_1[0]),
            ),
            &curve_a(),
        );
        constraint_ext_is_equal(
            &curr_row.dbl_num_lambda,
            &three_x1_squared_plus_a,
            yield_constr,
        );

        // lambda1 = 2*y1
        let two_y1 = gfp5_add(&curr_row.input_1[1], &curr_row.input_1[1]);
        constraint_ext_is_equal(&curr_row.dbl_denom_lambda, &two_y1, yield_constr);

        // lambda1_is_zero should be binary
        yield_constr.constraint(
            (P::ONES - curr_row.dbl_lambda_denom_is_zero) * curr_row.dbl_lambda_denom_is_zero,
        );
        // if lambda1_is_zero then lambda1 and lambda1_inv must both zero
        for i in 0..5 {
            yield_constr
                .constraint(curr_row.dbl_lambda_denom_is_zero * curr_row.dbl_denom_lambda[i]);
            yield_constr
                .constraint(curr_row.dbl_lambda_denom_is_zero * curr_row.dbl_denom_lambda_inv[i]);
        }

        // lambda1 * lambda1_inv = 1 unless if lambda1 is zero, in which case it's zero
        let prod = gfp5_mul(&curr_row.dbl_denom_lambda, &curr_row.dbl_denom_lambda_inv);
        yield_constr
            .constraint((P::ONES - curr_row.dbl_lambda_denom_is_zero) * (P::ONES - prod[0]));
        for i in 1..5 {
            yield_constr.constraint((P::ONES - curr_row.dbl_lambda_denom_is_zero) * prod[i]);
        }

        // lambda = lambda0 * lambda1_inv
        let lambda = gfp5_mul(&curr_row.dbl_num_lambda, &curr_row.dbl_denom_lambda_inv);
        constraint_ext_is_equal(&lambda, &curr_row.dbl_lambda, yield_constr);

        // x3 = lambda^2 - x1 - x2
        let x3 = gfp5_sub(
            &gfp5_sub(
                &gfp5_mul(&curr_row.dbl_lambda, &curr_row.dbl_lambda),
                &curr_row.input_1[0],
            ),
            &curr_row.input_1[0],
        );
        constraint_ext_is_equal(&curr_row.dbl_x3, &x3, yield_constr);

        // y3 = lambda * (x1 - x3) - y1
        let y3 = gfp5_sub(
            &gfp5_mul(
                &curr_row.dbl_lambda,
                &gfp5_sub(&curr_row.input_1[0], &curr_row.dbl_x3),
            ),
            &curr_row.input_1[1],
        );

        // I3 = xs_are_not_same & ys_are_not_same = 0 since we're doubling
        // conditionally set outputs based on infinity flags
        constraint_ext_is_equal_cond(
            curr_row.input_1_is_infinity,
            &curr_row.dbl_output[0],
            &curr_row.input_1[0],
            &curr_row.dbl_x3,
            yield_constr,
        );
        constraint_ext_is_equal_cond(
            curr_row.input_1_is_infinity,
            &curr_row.dbl_output[1],
            &curr_row.input_1[1],
            &y3,
            yield_constr,
        );
        yield_constr
            .constraint((P::ONES - curr_row.input_1_is_infinity) * curr_row.dbl_output_is_infinity);
        yield_constr
            .constraint(curr_row.input_1_is_infinity * (P::ONES - curr_row.dbl_output_is_infinity));

        // OPCODES

        // filter cols are binary
        for i in 0..NUM_CHANNELS {
            for opcode in 0..4 {
                yield_constr.constraint(
                    (P::ONES - curr_row.filter_cols_by_opcode[i][opcode])
                        * curr_row.filter_cols_by_opcode[i][opcode],
                );
            }
        }

        // ADD

        // add happens in a single row, so only the corresponding input / output filters may be set
        for i in 0..NUM_CHANNELS {
            yield_constr.constraint(curr_opcode_is_add * curr_row.filter_cols_by_opcode[i][1]);
            yield_constr.constraint(curr_opcode_is_add * curr_row.filter_cols_by_opcode[i][2]);
            yield_constr.constraint(curr_opcode_is_add * curr_row.filter_cols_by_opcode[i][3]);
        }

        // when opcode is add, microcode should be the same
        yield_constr.constraint(curr_opcode_is_add * (curr_opcode_is_add - curr_microcode_is_add));

        // set output to add's output
        for i in 0..5 {
            yield_constr.constraint(
                curr_opcode_is_add * (curr_row.output[0][i] - curr_row.add_output[0][i]),
            );
            yield_constr.constraint(
                curr_opcode_is_add * (curr_row.output[1][i] - curr_row.add_output[1][i]),
            );
        }
        yield_constr.constraint(
            curr_opcode_is_add * (curr_row.output_is_infinity - curr_row.add_output_is_infinity),
        );

        // DOUBLE AND ADD

        // double_and_add happens in a single row, so only the corresponding input / output filters may be set
        for i in 0..NUM_CHANNELS {
            yield_constr
                .constraint(curr_opcode_is_double_and_add * curr_row.filter_cols_by_opcode[i][0]);
            yield_constr
                .constraint(curr_opcode_is_double_and_add * curr_row.filter_cols_by_opcode[i][2]);
            yield_constr
                .constraint(curr_opcode_is_double_and_add * curr_row.filter_cols_by_opcode[i][3]);
        }

        // when opcode is double and add add, microcode should be the same
        yield_constr.constraint(
            curr_opcode_is_double_and_add * (curr_opcode_is_add - curr_microcode_is_add),
        );

        // set output to add's output. add's LHS input is already set to double's output above in this case
        for i in 0..5 {
            yield_constr.constraint(
                curr_opcode_is_double_and_add * (curr_row.output[0][i] - curr_row.add_output[0][i]),
            );
            yield_constr.constraint(
                curr_opcode_is_double_and_add * (curr_row.output[1][i] - curr_row.add_output[1][i]),
            );
        }
        yield_constr.constraint(
            curr_opcode_is_double_and_add
                * (curr_row.output_is_infinity - curr_row.add_output_is_infinity),
        );

        // SCALAR MUL

        // step flags for scalar mul are binary
        for i in 0..32 {
            yield_constr.constraint(
                (P::ONES - curr_row.scalar_step_bits[i]) * curr_row.scalar_step_bits[i],
            );
        }

        // at most one of the step flags may be set
        let step_bit_sum: P = curr_row.scalar_step_bits.iter().copied().sum();
        yield_constr.constraint((P::ONES - step_bit_sum) * step_bit_sum);

        // when opcode isn't scalar mul, the scalar step bits should be zero
        yield_constr.constraint((P::ONES - curr_opcode_is_scalar_mul) * step_bit_sum);

        // check correctness of scalar_step_bits[0]
        let next_row_is_scalar_mul = next_row.opcode[1];
        let transition_to_scalar_mul_from_other =
            (P::ONES - curr_row.opcode[1]) * next_row_is_scalar_mul;
        let transition_to_scalar_mul_from_scalar_mul =
            curr_row.scalar_step_bits[31] * next_row_is_scalar_mul;

        // since the flags are binary checked, this also doubles as a check that the two transition cases are mutually exclusive
        // we apply this constraint with wraparound to deal with the case where the trace starts with a scalar multiplication
        yield_constr.constraint(
            next_row.scalar_step_bits[0]
                - (transition_to_scalar_mul_from_other + transition_to_scalar_mul_from_scalar_mul),
        );

        // CTL filter checks for scalar mul
        for i in 0..NUM_CHANNELS {
            // assert that the input filter for scalar mul is only set during the first step
            yield_constr.constraint(
                curr_row.filter_cols_by_opcode[i][2] * (P::ONES - curr_row.scalar_step_bits[0]),
            );
            // assert that the output filter for scalar mul is set during the last step
            yield_constr.constraint(
                curr_row.filter_cols_by_opcode[i][3] * (P::ONES - curr_row.scalar_step_bits[31]),
            );

            // assert that the other filters aren't set when opcode is scalar mul
            yield_constr
                .constraint(curr_opcode_is_scalar_mul * curr_row.filter_cols_by_opcode[i][0]);
            yield_constr
                .constraint(curr_opcode_is_scalar_mul * curr_row.filter_cols_by_opcode[i][1]);
        }

        // scalar bits are binary
        for i in 0..32 {
            yield_constr.constraint(curr_row.scalar_bits[i] * (P::ONES - curr_row.scalar_bits[i]));
        }

        // scalar bits are big-endian decomp of scalar
        let decomp: P = (0..32)
            .map(|i| curr_row.scalar_bits[i] * FE::from_canonical_u32(1 << (31 - i as u32)))
            .sum();
        yield_constr.constraint(curr_row.scalar - decomp);

        // at the first step of a scalar mul, set input_1 to the identity element

        let (identity, identity_is_inf) = identity_element::<F, FE, D2>();
        // when the next row is scalar mul and the next step is not the first step of that scalar mul, copy output to input 1
        let next_opcode_is_scalar_mul = next_row.opcode[1];
        for i in 0..5 {
            // degree 3
            yield_constr.constraint_transition(
                next_opcode_is_scalar_mul
                    * (P::ONES - next_row.scalar_step_bits[0])
                    * (next_row.input_1[0][i] - curr_row.output[0][i]),
            );
            yield_constr.constraint_transition(
                next_opcode_is_scalar_mul
                    * (P::ONES - next_row.scalar_step_bits[0])
                    * (next_row.input_1[1][i] - curr_row.output[1][i]),
            );
        }

        // when the next row is scalar mul and the next step is the first step of that scalar mul, assert input1 is the identity element
        for i in 0..5 {
            // degree 3
            yield_constr.constraint_transition(
                next_opcode_is_scalar_mul
                    * next_row.scalar_step_bits[0]
                    * (next_row.input_1[0][i] - identity[0][i]),
            );
            yield_constr.constraint_transition(
                next_opcode_is_scalar_mul
                    * next_row.scalar_step_bits[0]
                    * (next_row.input_1[1][i] - identity[1][i]),
            );
        }
        yield_constr.constraint_transition(
            next_opcode_is_scalar_mul
                * next_row.scalar_step_bits[0]
                * (next_row.input_1_is_infinity - FE::from_bool(identity_is_inf)),
        );

        // during scalar mul, if the most-significant scalar bit is 1, then the current microcode is double-and-add
        // otherwise, it's double
        yield_constr.constraint(
            curr_opcode_is_scalar_mul * curr_row.scalar_bits[0] * (P::ONES - curr_row.microcode[1]),
        );
        yield_constr.constraint(
            curr_opcode_is_scalar_mul
                * (P::ONES - curr_row.scalar_bits[0])
                * (P::ONES - curr_row.microcode[0]),
        );

        // shift scalar bits left during scalar mul except for the last step
        for i in 0..31 {
            yield_constr.constraint_transition(
                curr_opcode_is_scalar_mul
                    * (P::ONES - curr_row.scalar_step_bits[31])
                    * (next_row.scalar_bits[i] - curr_row.scalar_bits[i + 1]),
            );
        }

        // move the set scalar step bit to the right each row during scalar mul
        for i in 0..31 {
            yield_constr.constraint_transition(
                curr_opcode_is_scalar_mul
                    * (curr_row.scalar_step_bits[i] - next_row.scalar_step_bits[i + 1]),
            );
        }

        // during scalar mul, set output to add output if it's a double-and-add, otherwise set it to double output
        for i in 0..5 {
            yield_constr.constraint(
                curr_opcode_is_scalar_mul
                    * curr_microcode_is_double_add
                    * (curr_row.output[0][i] - curr_row.add_output[0][i]),
            );
            yield_constr.constraint(
                curr_opcode_is_scalar_mul
                    * curr_microcode_is_double_add
                    * (curr_row.output[1][i] - curr_row.add_output[1][i]),
            );

            yield_constr.constraint(
                curr_opcode_is_scalar_mul
                    * curr_microcode_is_double
                    * (curr_row.output[0][i] - curr_row.dbl_output[0][i]),
            );
            yield_constr.constraint(
                curr_opcode_is_scalar_mul
                    * curr_microcode_is_double
                    * (curr_row.output[1][i] - curr_row.dbl_output[1][i]),
            );
        }
        yield_constr.constraint(
            curr_opcode_is_scalar_mul
                * curr_microcode_is_double_add
                * (curr_row.output_is_infinity - curr_row.add_output_is_infinity),
        );
        yield_constr.constraint(
            curr_opcode_is_scalar_mul
                * curr_microcode_is_double
                * (curr_row.output_is_infinity - curr_row.dbl_output_is_infinity),
        );

        // I/O

        // op_idx starts with 1
        yield_constr.constraint_first_row(P::ONES - curr_row.op_idx);

        // op_idx is incremented each row when opcode is add or double and add
        yield_constr.constraint_transition(
            (curr_opcode_is_add + curr_opcode_is_double_and_add)
                * (next_row.op_idx - curr_row.op_idx - P::ONES),
        );
        // op_idx is incremented when scalar_step_bits[31]
        yield_constr.constraint_transition(
            curr_row.scalar_step_bits[31] * (next_row.op_idx - curr_row.op_idx - P::ONES),
        );

        // check I/O encoding for points
        for coord in 0..1 {
            for i in 0..5 {
                let decoded_lo = curr_row.input_1_encoded[coord][i][0]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded_hi = curr_row.input_1_encoded[coord][i][1]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded = decoded_lo + decoded_hi * FE::from_canonical_u64(1 << 32);
                yield_constr.constraint(curr_row.input_1[coord][i] - decoded);

                let decoded_lo = curr_row.input_2_encoded[coord][i][0]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded_hi = curr_row.input_2_encoded[coord][i][1]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded = decoded_lo + decoded_hi * FE::from_canonical_u64(1 << 32);
                yield_constr.constraint(curr_row.input_2[coord][i] - decoded);

                let decoded_lo = curr_row.output_encoded[coord][i][0]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded_hi = curr_row.output_encoded[coord][i][1]
                    - curr_row.op_idx * FE::from_canonical_u64(1 << 32);
                let decoded = decoded_lo + decoded_hi * FE::from_canonical_u64(1 << 32);
                yield_constr.constraint(curr_row.output[coord][i] - decoded);
            }
        }
        // check I/O encoding for scalar
        yield_constr.constraint(
            curr_row.scalar
                - (curr_row.scalar_encoded - curr_row.op_idx * FE::from_canonical_u64(1 << 32)),
        );
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

/// does addition in GF(p^5)
/// degree 1
pub(crate) fn gfp5_add<P: PackedField>(a: &Ext<P>, b: &Ext<P>) -> Ext<P> {
    array::from_fn(|i| a[i] + b[i])
}

/// does subtraction in GF(p^5)
/// degree 1
pub(crate) fn gfp5_sub<P: PackedField>(a: &Ext<P>, b: &Ext<P>) -> Ext<P> {
    array::from_fn(|i| a[i] - b[i])
}

/// does multiplication in GF(p^5)
/// degree 2
pub(crate) fn gfp5_mul<P: PackedField<Scalar = F>, F: Field>(a: &Ext<P>, b: &Ext<P>) -> Ext<P> {
    let d0 = a[0] * b[0]
        + (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]) * F::from_canonical_u32(3);
    let d1 = a[0] * b[1]
        + a[1] * b[0]
        + (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]) * F::from_canonical_u32(3);
    let d2 = a[0] * b[2]
        + a[1] * b[1]
        + a[2] * b[0]
        + (a[3] * b[4] + a[4] * b[3]) * F::from_canonical_u32(3);
    let d3 = a[0] * b[3]
        + a[1] * b[2]
        + a[2] * b[1]
        + a[3] * b[0]
        + a[4] * b[4] * F::from_canonical_u32(3);
    let d4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

    [d0, d1, d2, d3, d4]
}

pub fn three<P: PackedField>() -> [P; 5] {
    [
        P::ONES + P::ONES + P::ONES,
        P::ZEROS,
        P::ZEROS,
        P::ZEROS,
        P::ZEROS,
    ]
}

fn curve_a<P: PackedField>() -> [P; 5] {
    let a0 = P::Scalar::from_canonical_u64(6148914689804861439);
    let a1 = P::Scalar::from_canonical_u64(263);
    [P::ONES * a0, P::ONES * a1, P::ZEROS, P::ZEROS, P::ZEROS]
}

fn identity_element<F: RichField, FE: FieldExtension<D, BaseField = F>, const D: usize>(
) -> (Point<FE>, bool) {
    use ecgfp5::curve::Point as CurvePoint;

    let identity = CurvePoint::NEUTRAL;
    let ([x, y], is_inf) = identity.to_weierstrass();

    let x: [F; 5] = x.0.map(|x| F::from_canonical_u64(x.to_u64()));
    let y: [F; 5] = y.0.map(|y| F::from_canonical_u64(y.to_u64()));

    (
        [x.map(FE::from_basefield), y.map(FE::from_basefield)],
        is_inf,
    )
}

fn constraint_ext_is_equal<P: PackedField>(
    a: &Ext<P>,
    b: &Ext<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    for i in 0..5 {
        yield_constr.constraint(a[i] - b[i]);
    }
}

// a = cond ? b : c
fn constraint_ext_is_equal_cond<P: PackedField>(
    cond: P,
    a: &Ext<P>,
    b: &Ext<P>,
    c: &Ext<P>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    for i in 0..5 {
        yield_constr.constraint(cond * (a[i] - b[i]));
        yield_constr.constraint((P::ONES - cond) * (a[i] - c[i]));
    }
}

fn constraint_ext_is_one<P: PackedField>(a: &Ext<P>, yield_constr: &mut ConstraintConsumer<P>) {
    yield_constr.constraint(P::ONES - a[0]);
    yield_constr.constraint(a[1]);
    yield_constr.constraint(a[2]);
    yield_constr.constraint(a[3]);
    yield_constr.constraint(a[4]);
}

fn constraint_ext_is_zero<P: PackedField>(a: &Ext<P>, yield_constr: &mut ConstraintConsumer<P>) {
    yield_constr.constraint(a[0]);
    yield_constr.constraint(a[1]);
    yield_constr.constraint(a[2]);
    yield_constr.constraint(a[3]);
    yield_constr.constraint(a[4]);
}

fn or_gen<P: PackedField>(a: P, b: P) -> P {
    a + b - a * b
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ecgfp5::curve::Point as CurvePoint;
    use ecgfp5::scalar::Scalar;
    use plonky2::field::extension::quintic::QuinticExtension;
    use plonky2::field::packable::Packable;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use rand::{rngs::ThreadRng, Rng};

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::verifier::verify_stark_proof_no_ctl;
    use crate::{
        stark_testing::test_stark_low_degree,
        starky2lib::ecgfp5_vartime::generation::Ecgfp5StarkGenerator,
    };

    const D: usize = 2;
    const NUM_CHANNELS: usize = 3;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type S = Ecgfp5Stark<F, D, NUM_CHANNELS>;
    type GFP5 = QuinticExtension<F>;

    fn random_point(rng: &mut ThreadRng) -> CurvePoint {
        CurvePoint::GENERATOR * Scalar::from_u64(rng.gen())
    }

    #[test]
    fn test_gfp5_mul() {
        let a = GFP5::rand();
        let b = GFP5::rand();
        let c = a * b;

        let c_arr = gfp5_mul::<F, F>(&a.to_basefield_array(), &b.to_basefield_array());
        let c_computed = GFP5::from_basefield_array(c_arr);
        assert_eq!(c, c_computed);
    }

    #[test]
    fn test_stark_degree() -> Result<()> {
        let stark = S::new();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_only_adds() -> Result<()> {
        let mut generator = Ecgfp5StarkGenerator::<NUM_CHANNELS>::new();
        let mut rng = rand::thread_rng();

        for _ in 0..32 {
            let a = random_point(&mut rng);
            let b = random_point(&mut rng);
            let _ = generator.gen_add(a, b, 0);
        }

        let trace = generator.into_polynomial_values();
        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)
    }

    #[test]
    fn test_only_double_adds() -> Result<()> {
        let mut generator = Ecgfp5StarkGenerator::<NUM_CHANNELS>::new();
        let mut rng = rand::thread_rng();

        for _ in 0..32 {
            let a = random_point(&mut rng);
            let b = random_point(&mut rng);
            let _ = generator.gen_double_add(a, b, 0);
        }

        let trace = generator.into_polynomial_values();
        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)
    }

    #[test]
    fn test_only_scalar_muls() -> Result<()> {
        let mut generator = Ecgfp5StarkGenerator::<NUM_CHANNELS>::new();
        let mut rng = rand::thread_rng();

        for _ in 0..32 {
            let p = random_point(&mut rng);
            let s: u32 = rng.gen();
            let _ = generator.gen_scalar_mul(p, s, 0);
        }

        let trace = generator.into_polynomial_values();
        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)
    }

    #[test]
    fn test_all_ops() -> Result<()> {
        let mut generator = Ecgfp5StarkGenerator::<NUM_CHANNELS>::new();
        let mut rng = rand::thread_rng();

        for _ in 0..96 {
            let op: u32 = rng.gen_range(0..3);
            match op {
                // add
                0 => {
                    let a = random_point(&mut rng);
                    let b = random_point(&mut rng);
                    let _ = generator.gen_add(a, b, 0);
                }
                // double-add
                1 => {
                    let a = random_point(&mut rng);
                    let b = random_point(&mut rng);
                    let _ = generator.gen_double_add(a, b, 0);
                }
                // scalar mul
                2 => {
                    let p = random_point(&mut rng);
                    let s: u32 = rng.gen();
                    let _ = generator.gen_scalar_mul(p, s, 0);
                }
                _ => unreachable!(),
            }
        }

        let trace = generator.into_polynomial_values();
        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)
    }
}
