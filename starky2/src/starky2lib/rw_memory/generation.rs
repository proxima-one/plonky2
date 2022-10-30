use std::borrow::{Borrow, BorrowMut};

use arrayref::array_ref;
use itertools::Itertools;
use plonky2::field::{
    polynomial::PolynomialValues,
    types::{Field, PrimeField64},
};
use plonky2_util::log2_ceil;

use super::layout::*;
use crate::{util::trace_rows_to_poly_values, lookup::permuted_cols};

pub struct RwMemoryGenerator<F: Field, const NUM_CHANNELS: usize>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
	timestamp: u64,
	mem: Vec<Option<F>>,
    trace: Vec<[F; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>,
}

#[derive(Copy, Clone, Debug)]
pub enum MemOp<F: Field> {
	Read(usize),
	Write(usize, F)
}

impl<F: PrimeField64, const NUM_CHANNELS: usize> RwMemoryGenerator<F, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
	pub fn new() -> Self {
		Self { timestamp: 1, trace: Vec::new(), mem: Vec::new() }
	}

	// TODO: don't panic, define error type instead
	pub fn gen_ops(&mut self, ops: &[MemOp<F>], channels: &[usize]) {
		for &op in ops {
			match op {
				MemOp::Read(addr) => {
					self.gen_read(addr, channels);
				},
				MemOp::Write(addr, val) => {
					self.gen_write(addr, val, channels)
				}
			}
		}	
	}

	pub fn gen_write(&mut self, addr: usize, value: F, channels: &[usize]) {
		let mut row = RwMemoryRow::<F, NUM_CHANNELS>::new();

		row.timestamp = F::from_canonical_u64(self.timestamp);
		row.addr = F::from_canonical_u64(addr as u64);
		row.value = value;
		row.is_write = F::ONE;
	
		Self::gen_channel_filters(&mut row, channels);

		self.write_to_mem(addr, value);
		self.trace.push(row.into());
		self.timestamp += 1;
	}

	fn write_to_mem(&mut self, addr: usize, val: F) {
		if addr >= self.mem.len() {
			self.mem.resize(addr + 1, None);
		}
		self.mem[addr] = Some(val);
	}

	fn read_from_mem(&mut self, addr: usize) -> F {
		if addr >= self.mem.len() {
			panic!("attempted to read from uninitialized memory")
		}
		self.mem[addr].expect("attempted to read from uninitialized memory")
	}

	fn mem_is_contiguous(&self) -> bool {
		if self.mem[0].is_none() {
			return false;
		}

		let addrs_accessed = self.mem.iter().enumerate().filter_map(|(i, v)| v.as_ref().map(|_| i)).sorted();
		for (curr, next) in addrs_accessed.tuple_windows() {
			if next != curr && next != curr + 1 {
				return false;
			}
		}

		true
	}

	pub fn gen_read(&mut self, addr: usize, channels: &[usize]) -> F {
		let mut row = RwMemoryRow::<F, NUM_CHANNELS>::new();

		let value = self.read_from_mem(addr);
		row.timestamp = F::from_canonical_u64(self.timestamp);
		row.addr = F::from_canonical_u64(addr as u64);
		row.value = value;
		row.is_write = F::ZERO;
	
		Self::gen_channel_filters(&mut row, channels);

		self.trace.push(row.into());
		self.timestamp += 1;
		value
	}

	fn gen_channel_filters(row: &mut RwMemoryRow<F, NUM_CHANNELS>, channels: &[usize])  {
		for &channel in channels {
			debug_assert!(channel < NUM_CHANNELS);
			row.filter_cols[channel] = F::ONE;
		}
	}

	fn gen_sorted(&mut self) {
		let sorted_accesses = self.trace.iter().map(|row_arr| {
			let row: &RwMemoryRow<F, NUM_CHANNELS> = row_arr.borrow();
			let addr = row.addr.to_canonical_u64();
			let timestamp = row.timestamp.to_canonical_u64();
			let value = row.value;
			let is_write = row.is_write;
			(addr, timestamp, value, is_write)
		})
		.sorted_by_cached_key(|(addr, timestamp, _, _)| (*addr, *timestamp));

		let mut prev_timestamp = None;
		let mut prev_addr = F::ZERO;
		for (i, (addr, timestamp, value, is_write)) in sorted_accesses.enumerate() {
			let mut row: &mut RwMemoryRow<F, NUM_CHANNELS> = self.trace[i].borrow_mut();
			row.addr_sorted = F::from_canonical_u64(addr);
			row.timestamp_sorted = F::from_canonical_u64(timestamp);
			row.value_sorted = value;
			row.is_write_sorted = is_write;

			(row.timestamp_sorted_diff, prev_timestamp) = match prev_timestamp {
				None => (F::ONE, Some(row.timestamp_sorted)),
				Some(prev) => {
					if prev_addr == row.addr_sorted {
						let diff = row.timestamp_sorted - prev;
						(diff, Some(row.timestamp_sorted))
					} else {
						(F::ONE, Some(row.timestamp_sorted))
					}
				}
			};

			prev_addr = row.addr_sorted;
		}
	}

	fn gen_luts(cols: &mut [PolynomialValues<F>]) {
		for (input, table, input_permuted, table_permuted) in lookup_permutation_sets().into_iter() {
			let (permuted_input, permuted_table) = permuted_cols(&cols[input].values, &cols[table].values);
			cols[input_permuted] = PolynomialValues::new(permuted_input);
			cols[table_permuted] = PolynomialValues::new(permuted_table);
		}
	}

	fn pad_to_len(&mut self, log2_target_len: usize) {
		let target_len = 1 << (log2_ceil(self.trace.len()).max(log2_target_len));

		while self.trace.len() < target_len {
			self.gen_read(0, &[]);
		}
	}

	pub fn into_polynomial_values_of_target_degree(mut self, log2_target_degree: usize) -> Vec<PolynomialValues<F>> {
		assert!(self.mem_is_contiguous(), "memory must form a contiguous segment whose address starts at 0");
		self.pad_to_len(log2_target_degree);
		self.gen_sorted();

		let mut values = trace_rows_to_poly_values(self.trace);
		Self::gen_luts(&mut values);

		values
	}

	pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
		self.into_polynomial_values_of_target_degree(0)
	}
}
