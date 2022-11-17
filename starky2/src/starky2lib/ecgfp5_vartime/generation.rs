use std::{
    borrow::{Borrow, BorrowMut},
};

use ecgfp5::{curve::Point as CurvePoint, field::GFp5, scalar::Scalar};
use plonky2::field::{
    extension::{quintic::QuinticExtension, FieldExtension},
    goldilocks_field::GoldilocksField,
    ops::Square,
    polynomial::PolynomialValues,
    types::{Field, PrimeField64},
};
use plonky2_util::log2_ceil;

use super::layout::*;
use crate::util::trace_rows_to_poly_values;

type F = GoldilocksField;
type GFP5 = QuinticExtension<F>;
type GenPoint = ([GFP5; 2], bool);

pub const MICROCODE_ADD: [F; 2] = [F::ZERO, F::ZERO];
pub const MICROCODE_DBL: [F; 2] = [F::ONE, F::ZERO];
pub const MICROCODE_DBL_AND_ADD: [F; 2] = [F::ZERO, F::ONE];

pub const OPCODE_ADD: [F; 2] = [F::ZERO, F::ZERO];
pub const OPCODE_DBL_AND_ADD: [F; 2] = [F::ONE, F::ZERO];
pub const OPCODE_SCALAR_MUL: [F; 2] = [F::ZERO, F::ONE];

const A: GFP5 = QuinticExtension::<F>([F::TWO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
const B: GFP5 = QuinticExtension::<F>([F::ZERO, GoldilocksField(263), F::ZERO, F::ZERO, F::ZERO]);
const THREE: GFP5 = QuinticExtension::<F>([GoldilocksField(3), F::ZERO, F::ZERO, F::ZERO, F::ZERO]);

pub(crate) fn curve_a() -> GFP5 {
    (THREE * B - A.square()) * THREE.inverse()
}

pub struct Ecgfp5StarkGenerator<const NUM_CHANNELS: usize>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    trace: Vec<[F; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]>,
    op_idx: u32,
}

impl<const NUM_CHANNELS: usize> Default for Ecgfp5StarkGenerator<NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const NUM_CHANNELS: usize> Ecgfp5StarkGenerator<NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        Self {
            trace: Vec::new(),
            op_idx: 1,
        }
    }

    fn gen_add_unit(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
        // handle input
        match row.microcode.map(|x| x.to_canonical_u64()) {
            // ADD OR DOUBLE
            [0, 0] | [1, 0] => {
                row.add_lhs_input = row.input_1;
                row.add_lhs_input_is_infinity = row.input_1_is_infinity;
            }
            // DOUBLE AND ADD
            [0, 1] => {
                row.add_lhs_input = row.dbl_output;
                row.add_lhs_input_is_infinity = row.dbl_output_is_infinity;
            }
            _ => panic!("invalid microcode"),
        };

        let a = row.add_lhs_input.map(GFP5::from_basefield_array);
        let b = row.input_2.map(GFP5::from_basefield_array);
        let a_is_inf = row.add_lhs_input_is_infinity == F::ONE;
        let b_is_inf = row.input_2_is_infinity == F::ONE;

        let [x1, y1] = a;
        let [x2, y2] = b;
        let xs_are_same = x1 == x2;
        let ys_are_same = y1 == y2;
        row.add_xs_are_same = F::from_bool(xs_are_same);
        row.add_ys_are_same = F::from_bool(ys_are_same);

        let xs_diff_inv = if xs_are_same {
            GFP5::ZERO
        } else {
            (x1 - x2).inverse()
        };
        let ys_diff_inv = if ys_are_same {
            GFP5::ZERO
        } else {
            (y1 - y2).inverse()
        };
        row.add_x1_minus_x2_inv = xs_diff_inv.to_basefield_array();
        row.add_y1_minus_y2_inv = ys_diff_inv.to_basefield_array();

        let add_num_lambda = if xs_are_same {
            x1.square() * THREE + curve_a()
        } else {
            y2 - y1
        };
        row.add_num_lambda = add_num_lambda.to_basefield_array();

        let add_denom_lambda = if xs_are_same { y1 * GFP5::TWO } else { x2 - x1 };
        let denom_is_zero = add_denom_lambda == GFP5::ZERO;

        row.add_denom_lambda = add_denom_lambda.to_basefield_array();
        row.add_lambda_denom_is_zero = F::from_bool(denom_is_zero);
        let denom_inv = if denom_is_zero {
            GFP5::ZERO
        } else {
            add_denom_lambda.inverse()
        };

        row.add_denom_lambda_inv = denom_inv.to_basefield_array();

        let lambda = add_num_lambda * denom_inv;
        row.add_lambda = lambda.to_basefield_array();

        let x3 = lambda.square() - x1 - x2;
        let y3 = lambda * (x1 - x3) - y1;
        row.add_x3 = x3.to_basefield_array();

        let add_output_is_infinity = xs_are_same && !ys_are_same;
        row.add_i3 = F::from_bool(add_output_is_infinity);

        row.add_output = if a_is_inf {
            [x2.to_basefield_array(), y2.to_basefield_array()]
        } else if b_is_inf {
            [x1.to_basefield_array(), y1.to_basefield_array()]
        } else {
            [x3.to_basefield_array(), y3.to_basefield_array()]
        };

        row.add_output_is_infinity = if a_is_inf {
            F::from_bool(b_is_inf)
        } else if b_is_inf {
            F::from_bool(a_is_inf)
        } else {
            row.add_i3
        };
    }

    fn gen_double_unit(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
        let a = row.input_1.map(GFP5::from_basefield_array);
        let a_is_inf = row.input_1_is_infinity == F::ONE;

        let [x1, y1] = a;

        let num = x1.square() * THREE + curve_a();
        let denom = y1 * GFP5::TWO;
        let denom_is_zero = denom == GFP5::ZERO;
        let denom_inv = if denom_is_zero {
            GFP5::ZERO
        } else {
            denom.inverse()
        };

        let lambda = num * denom_inv;
        let x3 = lambda.square() - x1 - x1;
        let y3 = lambda * (x1 - x3) - y1;
        let i3 = a_is_inf;

        row.dbl_num_lambda = num.to_basefield_array();
        row.dbl_denom_lambda = denom.to_basefield_array();
        row.dbl_lambda_denom_is_zero = F::from_bool(denom_is_zero);
        row.dbl_denom_lambda_inv = denom_inv.to_basefield_array();
        row.dbl_lambda = lambda.to_basefield_array();
        row.dbl_x3 = x3.to_basefield_array();
        row.dbl_output_is_infinity = F::from_bool(i3);
        row.dbl_output = if i3 {
            [x1.to_basefield_array(), y1.to_basefield_array()]
        } else {
            [x3.to_basefield_array(), y3.to_basefield_array()]
        };
    }

    fn gen_input(
        &mut self,
        row: &mut Ecgfp5Row<F, NUM_CHANNELS>,
        a: CurvePoint,
        b: CurvePoint,
        scalar: u32,
    ) -> (GenPoint, GenPoint) {
        let a = ecgfp5_to_plonky2(a);
        let b = ecgfp5_to_plonky2(b);

        let scalar = scalar as u64;
        row.scalar = F::from_canonical_u64(scalar);

        let (a_encoded, a_is_inf_encoded) = trace_encode_point(a);
        let (b_encoded, b_is_inf_encoded) = trace_encode_point(b);

        row.input_1 = a_encoded;
        row.input_2 = b_encoded;
        row.input_1_is_infinity = a_is_inf_encoded;
        row.input_2_is_infinity = b_is_inf_encoded;

        (a, b)
    }

    // TODO we don't acutally need the add_output columns - get rid of them
    fn gen_output(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
        if row.microcode == MICROCODE_DBL {
            row.output = row.dbl_output;
            row.output_is_infinity = row.dbl_output_is_infinity;
        } else {
            row.output = row.add_output;
            row.output_is_infinity = row.add_output_is_infinity;
        }
    }

    fn gen_ctl_filters(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>, channel: usize) {
        let opcode = row.opcode.map(|x| x.to_canonical_u64());

        match opcode {
            // ADD
            [0, 0] => {
                row.filter_cols_by_opcode[channel][0] = F::ONE;
            }
            // DOUBLE_AND_ADD
            [1, 0] => {
                row.filter_cols_by_opcode[channel][1] = F::ONE;
            }
            // SCALAR MUL
            [0, 1] => {
                row.filter_cols_by_opcode[channel][2] = row.scalar_step_bits[0];
                row.filter_cols_by_opcode[channel][3] = row.scalar_step_bits[31];
            }
            _ => panic!("Invalid opcode"),
        }
    }

    /// A + B
    pub fn gen_add(&mut self, a: CurvePoint, b: CurvePoint, channel: usize) -> (CurvePoint, u32) {
        let mut row = Ecgfp5Row::new();
        row.op_idx = F::from_canonical_u32(self.op_idx);
        row.microcode = MICROCODE_ADD;
        row.opcode = OPCODE_ADD;

        self.gen_input(&mut row, a, b, 0);
        self.gen_double_unit(&mut row);
        self.gen_add_unit(&mut row);
        self.gen_output(&mut row);
        self.gen_ctl_filters(&mut row, channel);

        let output = a + b;
        #[cfg(debug_assertions)]
        {
            let (output, output_is_inf) = ecgfp5_to_plonky2(output);
            assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
            if !output_is_inf {
                assert!(output == row.output.map(GFP5::from_basefield_array));
            }
        }

        let idx = self.op_idx;
        self.trace.push(row.into());
        self.op_idx += 1;

        (output, idx)
    }

    // 2A + B
    pub fn gen_double_add(
        &mut self,
        a: CurvePoint,
        b: CurvePoint,
        channel: usize,
    ) -> (CurvePoint, u32) {
        let mut row = Ecgfp5Row::new();
        row.op_idx = F::from_canonical_u32(self.op_idx);
        row.microcode = MICROCODE_DBL_AND_ADD;
        row.opcode = OPCODE_DBL_AND_ADD;

        self.gen_input(&mut row, a, b, 0);
        self.gen_double_unit(&mut row);
        self.gen_add_unit(&mut row);
        self.gen_output(&mut row);
        self.gen_ctl_filters(&mut row, channel);

        let output = a.double() + b;
        #[cfg(debug_assertions)]
        {
            let (output, output_is_inf) = ecgfp5_to_plonky2(output);
            assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
            if !output_is_inf {
                assert!(output == row.output.map(GFP5::from_basefield_array));
            }
        }

        let idx = self.op_idx;
        self.trace.push(row.into());
        self.op_idx += 1;

        (output, idx)
    }

    pub fn gen_scalar_mul(
        &mut self,
        p: CurvePoint,
        scalar: u32,
        channel: usize,
    ) -> (CurvePoint, u32) {
        let mut mask = scalar;
        let mut a = CurvePoint::NEUTRAL;
        for i in 0..32 {
            let mut row = Ecgfp5Row::new();

            row.op_idx = F::from_canonical_u32(self.op_idx);
            row.opcode = OPCODE_SCALAR_MUL;
            row.scalar_step_bits[i] = F::ONE;

            let is_dbl = mask & 0x8000_0000 == 0;

            row.microcode = if is_dbl {
                MICROCODE_DBL
            } else {
                MICROCODE_DBL_AND_ADD
            };

            let mut _mask = mask;
            for i in 0..32 {
                row.scalar_bits[i] = F::from_bool(_mask & 0x8000_0000 != 0);
                _mask <<= 1;
            }

            self.gen_input(&mut row, a, p, mask);
            self.gen_double_unit(&mut row);
            self.gen_add_unit(&mut row);
            self.gen_output(&mut row);
            self.gen_ctl_filters(&mut row, channel);

            a = if is_dbl { a.double() } else { a.double() + p };

            mask <<= 1;
            self.trace.push(row.into());
        }

        let output = p * Scalar::from_u64(scalar as u64);
        #[cfg(debug_assertions)]
        {
            let row: &Ecgfp5Row<F, NUM_CHANNELS> = self.trace.last().unwrap().borrow();
            let (output, output_is_inf) = ecgfp5_to_plonky2(output);
            assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
            if !output_is_inf {
                assert!(output == row.output.map(GFP5::from_basefield_array));
            }
        }

        let idx = self.op_idx;
        self.op_idx += 1;

        (output, idx)
    }

    pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
        let log_target_len = log2_ceil(self.trace.len());
        while self.trace.len() < (1 << log_target_len) {
            // generate dummy operations and disable CTL filters for them
            self.gen_add(CurvePoint::NEUTRAL, CurvePoint::NEUTRAL, 0);

            let last_row: &mut Ecgfp5Row<F, NUM_CHANNELS> =
                self.trace.last_mut().unwrap().borrow_mut();
            last_row.filter_cols_by_opcode[0][0] = F::ZERO;
        }

        trace_rows_to_poly_values(self.trace)
    }
}

fn gfp5_to_plonky2(x: GFp5) -> GFP5 {
    GFP5::from_basefield_array(x.0.map(|x| F::from_canonical_u64(x.to_u64())))
}

pub(crate) fn ecgfp5_to_plonky2(x: CurvePoint) -> GenPoint {
    let ([x, y], is_inf) = x.to_weierstrass();
    ([gfp5_to_plonky2(x), gfp5_to_plonky2(y)], is_inf)
}

fn trace_encode_point(([x, y], is_inf): GenPoint) -> (Point<F>, F) {
    (
        [x.to_basefield_array(), y.to_basefield_array()],
        F::from_bool(is_inf),
    )
}

#[cfg(test)]
mod tests {
    use rand::{rngs::ThreadRng, Rng};
    use plonky2::field::types::Field64;

    use super::*;

    fn random_point(rng: &mut ThreadRng) -> CurvePoint {
        CurvePoint::GENERATOR * Scalar::from_u64(rng.gen())
    }

    const ECGFP5_TRUE: u64 = 0xFFFFFFFFFFFFFFFF;

    #[test]
    fn test_gfp5s_are_same() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let arr: [u64; 5] = [rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()];
            let arr = arr.map(|x| F::from_noncanonical_u64(x).to_canonical_u64());
            let (x0, _) = GFp5::from_u64(arr[0], arr[1], arr[2], arr[3], arr[4]);
            let x1 = GFP5::from_basefield_array(arr.map(|x| F::from_canonical_u64(x)));

            let arr: [u64; 5] = [rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()];
            let arr = arr.map(|x| F::from_noncanonical_u64(x).to_canonical_u64());
            let (y0, _) = GFp5::from_u64(arr[0], arr[1], arr[2], arr[3], arr[4]);
            let y1 = GFP5::from_basefield_array(arr.map(|x| F::from_canonical_u64(x)));

            let z0 = x0 * y0;
            let z1 = x1 * y1;
            assert!(gfp5_to_plonky2(z0) == z1);

            let z0 = x0 + y0;
            let z1 = x1 + y1;
            assert!(gfp5_to_plonky2(z0) == z1);
        }
    }

    #[test]
    fn test_add() {
        let mut generator = Ecgfp5StarkGenerator::<3>::new();
        let mut rng = rand::thread_rng();

        let a = random_point(&mut rng);
        let b = random_point(&mut rng);
        let c = a + b;

        let (output, idx) = generator.gen_add(a, b, 0);
        assert!(c.equals(output) == ECGFP5_TRUE);
        assert!(idx == 1);
    }

    #[test]
    fn test_double_add() {
        let mut generator = Ecgfp5StarkGenerator::<3>::new();
        let mut rng = rand::thread_rng();

        let a = random_point(&mut rng);
        let b = random_point(&mut rng);
        let c = a.double() + b;

        let (output, idx) = generator.gen_double_add(a, b, 0);
        assert!(c.equals(output) == ECGFP5_TRUE);
        assert!(idx == 1);
    }

    #[test]
    fn test_scalar_mul() {
        let mut generator = Ecgfp5StarkGenerator::<3>::new();
        let mut rng = rand::thread_rng();

        let a = random_point(&mut rng);
        let b: u32 = rng.gen();
        let c = a * Scalar::from_u64(b as u64);

        let (output, idx) = generator.gen_scalar_mul(a, b, 0);
        assert!(c.equals(output) == ECGFP5_TRUE);
        assert!(idx == 1);
    }

    #[test]
    fn test_multiple() {
        let mut generator = Ecgfp5StarkGenerator::<3>::new();
        let mut rng = rand::thread_rng();

        for idx in 1u32..=30 {
            let op = rng.gen_range(0..3);
            let channel = rng.gen_range(0..3);
            match op {
                0 => {
                    let a = random_point(&mut rng);
                    let b = random_point(&mut rng);
                    let c = a + b;

                    let (output, op_idx) = generator.gen_add(a, b, channel);
                    assert!(c.equals(output) == ECGFP5_TRUE);
                    assert!(idx == op_idx);
                }
                // double and add
                1 => {
                    let a = random_point(&mut rng);
                    let b = random_point(&mut rng);
                    let c = a.double() + b;

                    let (output, op_idx) = generator.gen_double_add(a, b, channel);
                    assert!(c.equals(output) == ECGFP5_TRUE);
                    assert!(idx == op_idx);
                }
                // scalar mul
                2 => {
                    let a = random_point(&mut rng);
                    let b: u32 = rng.gen();
                    let c = a * Scalar::from_u64(b as u64);

                    let (output, op_idx) = generator.gen_scalar_mul(a, b, channel);
                    assert!(c.equals(output) == ECGFP5_TRUE);
                    assert!(idx == op_idx);
                }
                _ => unreachable!(),
            }
        }
    }
}
