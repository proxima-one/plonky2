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
pub struct RoMemoryRow<T: Copy, const NUM_CHANNELS: usize> {
    pub(crate) addr: T,
    pub(crate) value: T,
    pub(crate) addr_sorted: T,
    pub(crate) value_sorted: T,
    // fitler cols for each lookup channel
    // >0 channel can be helpful when a STARK only wants to read part of the memory
    pub(crate) filter_cols: [T; NUM_CHANNELS],
}

/// [addr, value] for each channel
pub fn ctl_cols<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = RoMemoryRow<u8, 0>;
    (0..NUM_CHANNELS).map(move |i| {
        CtlColSet::new(
            tid,
            vec![offset_of!(R, addr), offset_of!(R, value)],
            Some(offset_of!(R, filter_cols) + i),
        )
    })
}

pub(crate) const RO_MEMORY_NUM_COLS_BASE: usize = size_of::<RoMemoryRow<u8, 0>>();

impl<T: Copy + Default, const NUM_CHANNELS: usize> RoMemoryRow<T, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}

impl<T: Copy + Default, const NUM_CHANNELS: usize> Default for RoMemoryRow<T, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RoMemoryRow<T, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<RoMemoryRow<T, NUM_CHANNELS>>
    for [T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: RoMemoryRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<RoMemoryRow<T, NUM_CHANNELS>>
    for [T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &RoMemoryRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<RoMemoryRow<T, NUM_CHANNELS>>
    for [T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut RoMemoryRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RoMemoryRow<T, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]>
    for RoMemoryRow<T, NUM_CHANNELS>
where
    [(); RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; RO_MEMORY_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
