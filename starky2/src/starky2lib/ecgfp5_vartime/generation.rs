use std::array;

use super::layout::*;
use arrayref::array_ref;
use plonky2::field::{
	goldilocks_field::GoldilocksField,
	types::{PrimeField64, Field, Field64},
	extension::{FieldExtension, quintic::QuinticExtension},
	ops::Square
};
use plonky2_util::log2_ceil;
use ecgfp5::{
	curve::Point as CurvePoint,
	field::GFp5,
	scalar::Scalar
};

type F = GoldilocksField;
type GFP5 = QuinticExtension<F>;
type GenPoint = ([GFP5; 2], bool);
type InputEncodedGFP5<T> = [[T; 2]; 5];
type InputEncodedPoint<T> = [InputEncodedGFP5<T>; 2];

pub struct Ecgfp5StarkGenerator<const NUM_CHANNELS: usize> {
	trace: Vec<Ecgfp5Row<F, NUM_CHANNELS>>,
	op_idx: u32
}

impl<const NUM_CHANNELS: usize> Ecgfp5StarkGenerator<NUM_CHANNELS>
where
	[(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:
{
	pub fn new() -> Self {
		Self {
			trace: Vec::new(),
			op_idx: 1,
		}
	}

	fn gen_add_unit(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
		let a = row.add_lhs_input.map(|x| GFP5::from_basefield_array(x));
		let b = row.input_2.map(|x| GFP5::from_basefield_array(x));
		let a_is_inf = row.add_lhs_input_is_infinity == F::ONE;
		let b_is_inf = row.input_2_is_infinity == F::ONE;

		let [x1, y1] = a;
		let [x2, y2] = b;
		let xs_are_same = x1 == x2;
		let ys_are_same = y1 == y2;
		row.add_xs_are_same = F::from_bool(xs_are_same);
		row.add_ys_are_same = F::from_bool(ys_are_same);

		let xs_diff_inv = if xs_are_same { GFP5::ZERO } else { (x1 - x2).inverse() };
		let ys_diff_inv = if ys_are_same { GFP5::ZERO } else { (y1 - y2).inverse() };
		row.add_x1_minus_x2_inv = xs_diff_inv.to_basefield_array();
		row.add_y1_minus_y2_inv = ys_diff_inv.to_basefield_array();

		let xs_are_not_same = !xs_are_same;
		let add_num_lambda = if xs_are_not_same{
			y2 - y1
		} else {
			x1.square() * GFP5::from_canonical_u8(3) + GFP5::TWO
		};
		row.add_num_lambda = add_num_lambda.to_basefield_array();

		let add_denom_lambda = if xs_are_not_same {
			x2 - x1
		} else {
			y1 * GFP5::TWO
		};
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

		let add_output_is_infinity = x1 != x2 && y1 != y2;
		row.add_output_is_infinity = F::from_bool(add_output_is_infinity);

		row.add_output = if a_is_inf {
			[x2.to_basefield_array(), y2.to_basefield_array()]
		} else if b_is_inf {
			[x1.to_basefield_array(), y1.to_basefield_array()]
		} else {
			[x3.to_basefield_array(), y3.to_basefield_array()]
		};
		row.add_output_is_infinity = F::from_bool(add_output_is_infinity);
	}

	fn gen_double_unit(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
		let a = row.input_1.map(|x| GFP5::from_basefield_array(x));
		let a_is_inf = row.input_1_is_infinity == F::ONE;

		let [x1, y1] = a;

		let num = x1.square() * GFP5::from_canonical_u8(3) + GFP5::TWO;
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

	fn gen_scalar_mul_unit(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
		let curr_opcode_is_scalar_mul = row.opcode == OPCODE_SCALAR_MUL; 
		let scalar = row.scalar.to_canonical_u64() as u32;

		row.scalar_inv = if scalar == 0 { F::ZERO } else { row.scalar.inverse() };

		if curr_opcode_is_scalar_mul {
			let mut mask = scalar;
			for o in row.scalar_bits.iter_mut().rev() {
				*o = F::from_canonical_u32(mask & 1);
				mask >>= 1;
			}	
		}
	}

	fn gen_input(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>, a: CurvePoint, b: CurvePoint, scalar: u32) -> (GenPoint, GenPoint) {
		let a = ecgfp5_to_plonky2(a);
		let b = ecgfp5_to_plonky2(b);

		row.input_1_encoded = input_encode_point(a, self.op_idx);
		row.input_2_encoded = input_encode_point(b, self.op_idx);

		let scalar = scalar as u64;
		let op_idx = self.op_idx as u64;
		row.scalar_encoded = F::from_canonical_u64(scalar | (op_idx << 32));

		let (a_encoded, a_is_inf_encoded) = trace_encode_point(a);
		let (b_encoded, b_is_inf_encoded) = trace_encode_point(b);

		row.input_1 = a_encoded;
		row.input_2 = b_encoded;
		row.input_1_is_infinity = a_is_inf_encoded;
		row.input_2_is_infinity = b_is_inf_encoded;

		// TODO: figure out how to make rust let me use the constants below
		match row.microcode.map(|x| x.to_canonical_u64()) {
			// ADD
			[0, 0] => {
				row.add_lhs_input = row.input_1;
				row.add_lhs_input_is_infinity = row.input_1_is_infinity;
			},
			// DOUBLE
			[0, 1] => {
				row.add_lhs_input = row.dbl_output;
				row.add_lhs_input_is_infinity = row.dbl_output_is_infinity;
			},
			// DOUBLE_AND_ADD
			[1, 0] => {
				row.add_lhs_input = row.dbl_output;
				row.add_lhs_input_is_infinity = row.dbl_output_is_infinity;
			}
			_ => panic!("Invalid microcode"),
		};

		(a, b)
	}

	// TODO we don't acutally need the add_output columns - get rid of them
	fn gen_output(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>) {
		// if row.opcode == OPCODE_SCALAR_MUL && row.is_last_step_of_scalar_mul == F::ONE {
		// 	row.output = row.input_1;
		// 	row.output_is_infinity = row.input_1_is_infinity;
		// } else {
		// 	row.output = row.add_output;
		// 	row.output_is_infinity = row.add_output_is_infinity;
		// }
		row.output = row.add_output;
		row.output_is_infinity = row.add_output_is_infinity;

		let output_coords = row.output.map(|x| GFP5::from_basefield_array(x));
		let output_is_inf = row.output_is_infinity == F::ONE;
		let output = (output_coords, output_is_inf);


		row.output_encoded = input_encode_point(output, self.op_idx);
	}

	fn gen_ctl_filters(&mut self, row: &mut Ecgfp5Row<F, NUM_CHANNELS>, channel: usize) {
		let opcode = row.opcode.map(|x| x.to_canonical_u64());

		match opcode {
			// ADD
			[0, 0] => {
				row.filter_cols_by_opcode[channel][0] = F::ONE;
			},
			// DOUBLE_AND_ADD
			[1, 0] => {
				row.filter_cols_by_opcode[channel][1] = F::ONE;
			},
			// SCALAR MUL
			[0, 1] => {
				row.filter_cols_by_opcode[channel][2] = row.is_first_step_of_scalar_mul;
				row.filter_cols_by_opcode[channel][3] = row.is_last_step_of_scalar_mul;
			},
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
		self.gen_add_unit(&mut row);
		self.gen_double_unit(&mut row);
		self.gen_scalar_mul_unit(&mut row);
		self.gen_output(&mut row);
		self.gen_ctl_filters(&mut row, channel);

		let output = a + b;
		#[cfg(debug_assertions)]
		{
			let (output, output_is_inf) = ecgfp5_to_plonky2(output);
			assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
			if !output_is_inf {
				assert!(output == row.output.map(|x| GFP5::from_basefield_array(x)));
			}
		}

		let idx = self.op_idx;
		self.trace.push(row);
		self.op_idx += 1;

		(output, idx)
	}

	// 2A + B
	pub fn gen_double_add(&mut self, a: CurvePoint, b: CurvePoint, channel: usize) -> (CurvePoint, u32) {
		let mut row = Ecgfp5Row::new();
		row.op_idx = F::from_canonical_u32(self.op_idx);
		row.microcode = MICROCODE_DBL_AND_ADD;
		row.opcode = OPCODE_DBL_AND_ADD;

		self.gen_input(&mut row, a, b, 0);
		self.gen_add_unit(&mut row);
		self.gen_double_unit(&mut row);
		self.gen_scalar_mul_unit(&mut row);
		self.gen_output(&mut row);
		self.gen_ctl_filters(&mut row, channel);

		let output = a.double() + b;
		#[cfg(debug_assertions)]
		{
			let (output, output_is_inf) = ecgfp5_to_plonky2(output);
			assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
			if !output_is_inf {
				assert!(output == row.output.map(|x| GFP5::from_basefield_array(x)));
			}
		}

		let idx = self.op_idx;
		self.trace.push(row);
		self.op_idx += 1;

		(output, idx)
	}

	pub fn gen_scalar_mul(&mut self, p: CurvePoint, scalar: u32, channel: usize) -> (CurvePoint, u32) {
		let mut mask = scalar;
		let mut is_first_step = true;
		let mut a = CurvePoint::NEUTRAL;
		while mask > 0 {

			let mut row = Ecgfp5Row::new();
			row.op_idx = F::from_canonical_u32(self.op_idx);
			row.opcode = OPCODE_SCALAR_MUL;
			row.is_first_step_of_scalar_mul = if is_first_step {
				is_first_step = false;
				F::ONE
			} else {
				F::ZERO
			};
			row.is_last_step_of_scalar_mul = F::ZERO;

			row.microcode = if mask & 0x8000_0000 == 0 {
				MICROCODE_DBL
			} else {
				MICROCODE_DBL_AND_ADD
			};

			self.gen_input(&mut row, a, p, mask);
			self.gen_add_unit(&mut row);
			self.gen_double_unit(&mut row);
			self.gen_scalar_mul_unit(&mut row);
			self.gen_output(&mut row);
			self.gen_ctl_filters(&mut row, channel);

			a = if mask & 0x8000_0000 != 0 {
				a.double() + a
			} else {
				a.double()
			};
			
			mask <<= 1;	
		}

		// last iteration (if scalar is zero, this is also the first iteration)
		let mut row = Ecgfp5Row::new();
		row.op_idx = F::from_canonical_u32(self.op_idx);
		row.opcode = OPCODE_SCALAR_MUL;
		row.microcode = MICROCODE_DBL_AND_ADD;
		row.is_first_step_of_scalar_mul = F::from_bool(is_first_step);
		row.is_last_step_of_scalar_mul = F::ONE;

		self.gen_input(&mut row, a, p, mask);
		self.gen_add_unit(&mut row);
		self.gen_double_unit(&mut row);
		self.gen_scalar_mul_unit(&mut row);
		self.gen_output(&mut row);
		self.gen_ctl_filters(&mut row, channel);


		let output = p * Scalar::from_u64(scalar as u64);
		#[cfg(debug_assertions)]
		{
			let (output, output_is_inf) = ecgfp5_to_plonky2(output);
			assert!(F::from_bool(output_is_inf) == row.output_is_infinity);
			if !output_is_inf {
				println!("computed output: {:?}", row.output.map(|x| GFP5::from_basefield_array(x)));
				println!("correct output: {:?}", output);
				assert!(output == row.output.map(|x| GFP5::from_basefield_array(x)));
			}
		}

		let idx = self.op_idx;
		self.trace.push(row);
		self.op_idx += 1;

		(output, idx)
	}
}

pub const MICROCODE_ADD: [F; 2] = [F::ZERO, F::ZERO];
pub const MICROCODE_DBL: [F; 2] = [F::ONE, F::ZERO];
pub const MICROCODE_DBL_AND_ADD: [F; 2] = [F::ZERO, F::ONE];

pub const OPCODE_ADD: [F; 2] = [F::ZERO, F::ZERO];
pub const OPCODE_DBL_AND_ADD: [F; 2] = [F::ONE, F::ZERO];
pub const OPCODE_SCALAR_MUL: [F; 2] = [F::ZERO, F::ONE];

fn input_encode_gfp5(x: GFP5, op_idx: u32) -> InputEncodedGFP5<F> {
	let op_idx = op_idx as u64;
	let mut result = [[F::ZERO; 2]; 5];
	for (i, x) in <GFP5 as FieldExtension<5>>::to_basefield_array(&x).iter().enumerate() {
		let lo = x.to_canonical_u64() & ((1 << 32) - 1);
		let hi = x.to_canonical_u64() >> 32;
		result[i][0] = F::from_canonical_u64(lo as u64| (op_idx << 32));
		result[i][1] = F::from_canonical_u64(hi as u64 | (op_idx << 32));
	}

	result
}

fn gfp5_to_plonky2(x: GFp5) -> GFP5 {
	GFP5::from_basefield_array(x.0.map(|x| F::from_canonical_u64(x.to_u64())))
}

pub(crate) fn ecgfp5_to_plonky2(x: CurvePoint) -> GenPoint {
	let ([x, y], is_inf) = x.to_weierstrass();
	([gfp5_to_plonky2(x), gfp5_to_plonky2(y)], is_inf)
}

fn trace_encode_point(([x, y], is_inf): GenPoint) -> (Point<F>, F) {
	([x.to_basefield_array(), y.to_basefield_array()], F::from_bool(is_inf))	
}

fn input_encode_point(([x, y], _): GenPoint, op_idx: u32) -> InputEncodedPoint<F> {
	[input_encode_gfp5(x, op_idx), input_encode_gfp5(y, op_idx)]
}

#[cfg(test)]
mod tests {
	use rand::{rngs::ThreadRng, Rng};
	use super::*;

	fn random_point(rng: &mut ThreadRng) -> CurvePoint {
		CurvePoint::GENERATOR * Scalar::from_u64(rng.gen())
	}

	const ECGFP5_TRUE: u64 = 0xFFFFFFFFFFFFFFFF;

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
				},
				// double and add
				1 => {
					let a = random_point(&mut rng);
					let b = random_point(&mut rng);
					let c = a.double() + b;

					let (output, op_idx) = generator.gen_double_add(a, b, channel);
					assert!(c.equals(output) == ECGFP5_TRUE);
					assert!(idx == op_idx);
				},
				// scalar mul
				2 => {
					let a = random_point(&mut rng);
					let b: u32 = rng.gen();
					let c = a * Scalar::from_u64(b as u64);

					let (output, op_idx) = generator.gen_scalar_mul(a, b, channel);
					assert!(c.equals(output) == ECGFP5_TRUE);
					assert!(idx == op_idx);
				},
				_ => unreachable!(),
			}
		}
	}
}
