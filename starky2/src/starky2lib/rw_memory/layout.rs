use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use memoffset::offset_of;

use crate::{
    cross_table_lookup::{CtlColSet, TableID},
    util::transmute_no_compile_time_size_checks,
};

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct RwMemoryRow<T: Copy, const NUM_CHANNELS: usize> {
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

    // used to range check addresses and timestamp differenes
    pub(crate) timestamp_permuted: T,

    // fitler cols for each lookup channel
    // >1 channel can be helpful when a STARK only wants to read part of the memory
    pub(crate) filter_cols: [T; NUM_CHANNELS],
}

pub(crate) fn sorted_access_permutation_pairs() -> Vec<(usize, usize)> {
    type R = RwMemoryRow<u8, 0>;
    vec![
        (offset_of!(R, addr), offset_of!(R, addr_sorted)),
        (offset_of!(R, timestamp), offset_of!(R, timestamp_sorted)),
        (offset_of!(R, value), offset_of!(R, value_sorted)),
        (offset_of!(R, is_write), offset_of!(R, is_write_sorted)),
    ]
}

pub(crate) fn lookup_permutation_sets() -> Vec<(usize, usize, usize, usize)> {
    vec![
        // (timestamp_sorted_diff, timestamp, timestamp_sorted_diff_permuted, timestamp_permuted)
        (
            offset_of!(RwMemoryRow<u8, 0>, timestamp_sorted_diff),
            offset_of!(RwMemoryRow<u8, 0>, timestamp),
            offset_of!(RwMemoryRow<u8, 0>, timestamp_sorted_diff_permuted),
            offset_of!(RwMemoryRow<u8, 0>, timestamp_permuted),
        ),
    ]
}

/// [is_write, addr, value, timestamp] for each channel
pub fn ctl_cols<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = RwMemoryRow<u8, 0>;
    (0..NUM_CHANNELS).map(move |i| {
        CtlColSet::new(
            tid,
            vec![
                offset_of!(R, is_write),
                offset_of!(R, addr),
                offset_of!(R, value),
                offset_of!(R, timestamp),
            ],
            Some(RW_MEMORY_NUM_COLS_BASE - (NUM_CHANNELS - i)),
        )
    })
}

pub(crate) const RW_MEMORY_NUM_COLS_BASE: usize = size_of::<RwMemoryRow<u8, 0>>();

impl<T: Copy + Default, const NUM_CHANNELS: usize> RwMemoryRow<T, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}

impl<T: Copy + Default, const NUM_CHANNELS: usize> Default for RwMemoryRow<T, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RwMemoryRow<T, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<RwMemoryRow<T, NUM_CHANNELS>>
    for [T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: RwMemoryRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<RwMemoryRow<T, NUM_CHANNELS>>
    for [T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &RwMemoryRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<RwMemoryRow<T, NUM_CHANNELS>>
    for [T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut RwMemoryRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RwMemoryRow<T, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RwMemoryRow<T, NUM_CHANNELS>
where
    [(); RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; RW_MEMORY_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
