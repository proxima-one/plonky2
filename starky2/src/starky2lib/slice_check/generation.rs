use crate::util::trace_rows_to_poly_values;

use super::layout::*;
use plonky2::field::{
	types::PrimeField64,
	polynomial::PolynomialValues
};


pub struct SliceCheckRowGenerator<'a, F: PrimeField64, const NUM_CHANNELS: usize> {
	trace: Vec<SliceCheckRow<F, NUM_CHANNELS>>,
	left_mem: &'a[F],
	right_mem: &'a [F],

	left_addr: usize,
	right_addr: usize,

	len: usize,
	count: usize,
}

impl<'a, F: PrimeField64, const NUM_CHANNELS: usize> SliceCheckRowGenerator<'a, F, NUM_CHANNELS>
where [(); SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:
{
	pub fn new(left_mem: &'a[F], right_mem: &'a[F]) -> SliceCheckRowGenerator<'a, F, NUM_CHANNELS> {
		SliceCheckRowGenerator {
			trace: Vec::new(),
			left_mem,
			right_mem,
			left_addr: 0,
			right_addr: 0,
			len: 0,
			count: 0,
		}	
	}

	fn gen_row(&self) -> SliceCheckRow<F, NUM_CHANNELS> {
		let mut row = SliceCheckRow::new();
		row.count = F::from_canonical_usize(self.count);
		row.len = F::from_canonical_usize(self.len);
		row.left_addr = F::from_canonical_usize(self.left_addr);
		row.right_addr = F::from_canonical_usize(self.right_addr);

		let value = self.left_mem[self.left_addr];
		assert_eq!(value, self.right_mem[self.right_addr]);
		row.value = value; 

		row.count_minus_len_minus_one_inv = (row.count - row.len - F::ONE).try_inverse().unwrap_or(F::ZERO);
		row
	}

	pub fn gen_slice_check(&mut self, left_start: usize, right_start: usize, len: usize, channel: usize) {
		self.left_addr = left_start;
		self.right_addr = right_start;
		self.len = len;
		self.count = 0;
		let mut row = self.gen_row();
		row.slice_filters[channel] = F::ONE;

		while self.count < self.len {
			self.trace.push(row);
			self.count += 1;
			self.left_addr += 1;
			self.right_addr += 1;
		}
	}

	pub fn pad_to_target_len(&mut self, log2_target_len: usize) {
		let target_len = self.trace.len().max(1 << log2_target_len);
		self.left_addr = 0;
		self.right_addr = 0;
		self.len = 0;
		self.count = 0;
		if self.trace.len() < target_len {
			let row = self.gen_row();
			self.trace.resize(target_len, row)
		}
	}

	pub fn into_polynomial_values(self) -> Vec<PolynomialValues<F>> {
		let rows = self.trace.into_iter().map(|r| r.into()).collect();
		trace_rows_to_poly_values(rows)
	}
}
