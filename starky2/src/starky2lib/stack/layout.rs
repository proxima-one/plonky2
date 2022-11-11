use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use crate::{
    cross_table_lookup::{CtlColSet, TableID},
    util::transmute_no_compile_time_size_checks,
};

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct StackRow<T: Copy, const NUM_CHANNELS: usize> {
    // memory cols
    pub(crate) addr: T,
    pub(crate) timestamp: T,
    pub(crate) value: T,
    pub(crate) is_write: T,

    pub(crate) addr_sorted: T,
    pub(crate) timestamp_sorted: T,
    pub(crate) value_sorted: T,
    pub(crate) is_write_sorted: T,

    // used for checking timestamp ordering via range check
    pub(crate) timestamp_sorted_diff: T,
    pub(crate) timestamp_sorted_diff_permuted: T,

    pub(crate) sp: T,
    // 1 if the current operation is a pop, 0 if it's a push
    pub(crate) is_pop: T,

    // used to range check addresses and timestamp differenes
    pub(crate) timestamp_permuted: T,

    // fitler cols for each lookup channel
    // >1 channel can be helpful when a STARK only wants to read part of the memory
    pub(crate) filter_cols: [T; NUM_CHANNELS],
}

pub(crate) fn sorted_access_permutation_pairs() -> Vec<(usize, usize)> {
    vec![(0, 4), (1, 5), (2, 6), (3, 7)]
}

pub(crate) fn lookup_permutation_sets() -> Vec<(usize, usize, usize, usize)> {
    vec![
        // (timestamp_sorted_diff, timestamp, timestamp_sorted_diff_permuted, timestamp_permuted)
        (8, 1, 9, 12),
    ]
}

/// [is_pop, value, timestamp] for each channel
pub fn ctl_cols<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    (0..NUM_CHANNELS).map(move |i| {
        CtlColSet::new(
            tid,
            vec![12, 2, 1],
            Some(STACK_NUM_COLS_BASE - (NUM_CHANNELS - i)),
        )
    })
}

pub(crate) const STACK_NUM_COLS_BASE: usize = size_of::<StackRow<u8, 0>>();

impl<T: Copy + Default, const NUM_CHANNELS: usize> StackRow<T, NUM_CHANNELS>
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); STACK_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}

impl<T: Copy + Default, const NUM_CHANNELS: usize> Default for StackRow<T, NUM_CHANNELS>
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; STACK_NUM_COLS_BASE + NUM_CHANNELS]>
    for StackRow<T, NUM_CHANNELS>
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; STACK_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<StackRow<T, NUM_CHANNELS>>
    for [T; STACK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: StackRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<StackRow<T, NUM_CHANNELS>>
    for [T; STACK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &StackRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<StackRow<T, NUM_CHANNELS>>
    for [T; STACK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut StackRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; STACK_NUM_COLS_BASE + NUM_CHANNELS]>
    for StackRow<T, NUM_CHANNELS>
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; STACK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; STACK_NUM_COLS_BASE + NUM_CHANNELS]>
    for StackRow<T, NUM_CHANNELS>
where
    [(); STACK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; STACK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
