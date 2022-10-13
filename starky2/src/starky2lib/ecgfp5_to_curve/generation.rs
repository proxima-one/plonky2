use plonky2::field::{
	goldilocks_field::GoldilocksField,
	extension::quintic::QuinticExtension,
	polynomial::PolynomialValues,
	extension::FieldExtension,
	types::Field
};
use ecgfp5::curve::Point as CurvePoint;

use super::layout::ECGFP5_HTC_NUM_COLS_BASE;


type F = GoldilocksField;
type GFP5 = QuinticExtension<F>;
type GenPoint = ([GFP5; 2], bool);
type InputEncodedGFP5<T> = [[T; 2]; 5];
type InputEncodedPoint<T> = [InputEncodedGFP5<T>; 2];

pub struct Ecgfp5HtcStarkGenerator<const NUM_CHANNELS: usize>
where
	[(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:,
{
	trace: Vec<[F; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]>,
	op_idx: u32
}

impl<const NUM_CHANNELS: usize> Ecgfp5HtcStarkGenerator<NUM_CHANNELS>
where
	[(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:,
{
	fn new() -> Self {
		Self {
			trace: Vec::new(),
			op_idx: u32
		}
	}

	fn gen_htc(u: GFP5) -> (u32, CurvePoint) {
		todo!()
	}

	fn into_polynomial_values() -> Vec<PolynomialValues<F>> {
		todo!()
	}
}

fn gen_sgn0(x: GFP5) -> [[F; 5]; 5] {
	todo!()
}
