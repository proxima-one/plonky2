use std::borrow::{Borrow, BorrowMut};

use itertools::Itertools;
use plonky2::field::{
    polynomial::PolynomialValues,
    types::{Field, PrimeField64},
};

use super::layout::*;
use crate::util::trace_rows_to_poly_values;

pub struct RoMemoryStarkGenerator<F: Field, const NUM_CHANNELS: usize>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    trace: Vec<[F; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>,
}

impl<F: PrimeField64, const NUM_CHANNELS: usize> Default for RoMemoryStarkGenerator<F, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField64, const NUM_CHANNELS: usize> RoMemoryStarkGenerator<F, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        Self { trace: Vec::new() }
    }

    pub fn gen_access(&mut self, addr: F, value: F, channels: &[usize]) {
        let mut row = RoMemoryRow::new();
        row.addr = addr;
        row.value = value;
        Self::gen_channel_filters(&mut row, channels);
        self.trace.push(row.into());
    }

    fn gen_channel_filters(row: &mut RoMemoryRow<F, NUM_CHANNELS>, channels: &[usize]) {
        for &channel in channels {
            debug_assert!(channel < NUM_CHANNELS);
            row.filter_cols[channel] = F::ONE;
        }
    }

    pub fn gen_access_trace<I: Iterator<Item = (F, F)>>(
        &mut self,
        accesses: &mut I,
        channels: &[usize],
    ) {
        for (addr, value) in accesses {
            self.gen_access(addr, value, channels);
        }
    }

    fn pad(&mut self, log2_target_len: Option<usize>) {
        let first_row = self.trace[0];
        let next_power_of_two = self.trace.len().next_power_of_two();
        let target_len = next_power_of_two.max(1 << log2_target_len.unwrap_or(0));
        self.trace.resize(target_len, first_row);
    }

    fn gen_sorted_cols(&mut self) {
        let sorted_accesses = self
            .trace
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let row: &RoMemoryRow<F, NUM_CHANNELS> = row.borrow();
                (row.addr, i)
            })
            .sorted_by_cached_key(|(addr, _)| addr.to_canonical_u64())
            .collect_vec();

        for (i, (addr, j)) in (0..self.trace.len()).zip(sorted_accesses) {
            let row: &RoMemoryRow<F, NUM_CHANNELS> = self.trace[j].borrow();
            let value = row.value;

            let row: &mut RoMemoryRow<F, NUM_CHANNELS> = self.trace[i].borrow_mut();
            row.addr_sorted = addr;
            row.value_sorted = value;

            // println!("({}, {})", addr, value);
        }
    }

    pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
        self.pad(None);
        self.gen_sorted_cols();
        trace_rows_to_poly_values(self.trace)
    }

    pub fn into_polynomial_values_with_degree(
        mut self,
        degree_bits: usize,
    ) -> Vec<PolynomialValues<F>> {
        self.pad(Some(degree_bits));
        self.gen_sorted_cols();
        trace_rows_to_poly_values(self.trace)
    }
}
