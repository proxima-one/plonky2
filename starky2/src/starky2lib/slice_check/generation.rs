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

	remaining_len: usize,
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
			remaining_len: 0
		}	
	}

	fn gen_row(&self) -> SliceCheckRow<F, NUM_CHANNELS> {
		let mut row = SliceCheckRow::new();
		row.remaining_len = F::from_canonical_usize(self.remaining_len);
		row.left_addr = F::from_canonical_usize(self.left_addr);
		row.right_addr = F::from_canonical_usize(self.right_addr);
		row.is_padding_row = F::ZERO;

		let value = self.left_mem[self.left_addr];
		row.value = value; 

		row.remaining_len_inv = row.remaining_len.try_inverse().unwrap_or(F::ZERO);
		row
	}

	pub fn gen_slice_check(&mut self, left_start: usize, right_start: usize, len: usize, channel: usize) {
		self.left_addr = left_start;
		self.right_addr = right_start;
		self.remaining_len = len - 1;
		let mut row = self.gen_row();
		row.slice_filters[channel] = F::ONE;
		self.trace.push(row);

		while self.remaining_len > 0 {
			self.remaining_len -= 1;
			self.left_addr += 1;
			self.right_addr += 1;
			assert_eq!(self.left_mem[self.left_addr], self.right_mem[self.right_addr]);
			row = self.gen_row();
			self.trace.push(row);
		}
		self.trace.last_mut().unwrap().done = F::ONE;
	}

	pub fn pad_to_target_len(&mut self, log2_target_len: usize) {
		let target_len = self.trace.len().next_power_of_two().max(1 << log2_target_len);
		if self.trace.len() < target_len {
			let mut row = self.gen_row();
			row.done = F::ONE;
			row.is_padding_row = F::ONE;

			self.trace.resize(target_len, row);
		}
	}

	pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
		self.pad_to_target_len(0);
		let rows = self.trace.into_iter().map(|r| r.into()).collect();
		trace_rows_to_poly_values(rows)
	}
}
