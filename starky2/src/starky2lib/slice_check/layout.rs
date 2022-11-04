use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
    ops::Range,
};

use memoffset::{offset_of, span_of};

use crate::{
    cross_table_lookup::{CtlColSet, TableID},
    permutation::PermutationPair,
    util::transmute_no_compile_time_size_checks,
};

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SliceCheckRow<T: Copy, const NUM_CHANNELS: usize> {
	pub(crate) count_minus_len_minus_one_inv: T,
	pub(crate) count: T,
	pub(crate) len: T,
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

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]> for SliceCheckRow<T, NUM_CHANNELS>
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<SliceCheckRow<T, NUM_CHANNELS>> for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: SliceCheckRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<SliceCheckRow<T, NUM_CHANNELS>> for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]: Sized,
{
    fn borrow(&self) -> &SliceCheckRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<SliceCheckRow<T, NUM_CHANNELS>> for [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut SliceCheckRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]> for SliceCheckRow<T, NUM_CHANNELS>
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]> for SliceCheckRow<T, NUM_CHANNELS>
where
	[T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; SLICE_CHECK_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
