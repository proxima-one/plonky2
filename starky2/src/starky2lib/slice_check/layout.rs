use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use crate::util::transmute_no_compile_time_size_checks;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SliceCheckRow<T: Copy, const NUM_CHANNELS: usize> {
    pub(crate) is_padding_row: T,
    pub(crate) done: T,
    pub(crate) remaining_len_inv: T,
    pub(crate) remaining_len: T,
    pub(crate) left_addr: T,
    pub(crate) right_addr: T,
    pub(crate) value: T,

    pub(crate) slice_filters: [T; NUM_CHANNELS],
}

pub(crate) const SLICE_CHECK_NUM_COLS_BASE: usize = size_of::<SliceCheckRow<u8, 0>>();

impl<T: Copy + Default, const NUM_CHANNELS: usize> SliceCheckRow<T, NUM_CHANNELS>
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}

impl<T: Copy + Default, const NUM_CHANNELS: usize> Default for SliceCheckRow<T, NUM_CHANNELS>
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]>
    for SliceCheckRow<T, NUM_CHANNELS>
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<SliceCheckRow<T, NUM_CHANNELS>>
    for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: SliceCheckRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<SliceCheckRow<T, NUM_CHANNELS>>
    for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]: Sized,
{
    fn borrow(&self) -> &SliceCheckRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<SliceCheckRow<T, NUM_CHANNELS>>
    for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut SliceCheckRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]>
    for SliceCheckRow<T, NUM_CHANNELS>
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]>
    for SliceCheckRow<T, NUM_CHANNELS>
where
    [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
