use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;

use crate::cross_table_lookup::{CtlColumn, TableID};
use crate::util::transmute_no_compile_time_size_checks;

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct XorLayout<T: Copy, const N: usize, const NUM_CHANNELS: usize> {
    pub(crate) a: T,
    pub(crate) b: T,
    pub(crate) output: T,
    pub(crate) a_bits: [T; N],
    pub(crate) b_bits: [T; N],
    pub(crate) channel_filters: [T; NUM_CHANNELS]
}

impl<T: Copy, const N: usize, const NUM_CHANNELS: usize> XorLayout<T, N, NUM_CHANNELS> {
    pub(crate) const fn a_col() -> usize {
        0
    }

    pub(crate) const fn b_col() -> usize {
        1
    }

    pub(crate) const fn output_col() -> usize {
        2
    }

    pub(crate) const fn channel_filter_col(channel: usize) -> usize {
        3 + 2 * N + channel 
    }

    pub fn ctl_cols_a(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..NUM_CHANNELS).map(move |i| {
            CtlColumn::new(tid, Self::a_col(), Some(Self::channel_filter_col(i)))
        })
    }

    pub fn ctl_cols_b(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..NUM_CHANNELS).map(move |i| {
            CtlColumn::new(tid, Self::b_col(), Some(Self::channel_filter_col(i)))
        })
    }

    pub fn ctl_cols_output(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..NUM_CHANNELS).map(move |i| {
            CtlColumn::new(tid, Self::output_col(), Some(Self::channel_filter_col(i)))
        })
    }
}

impl<T: Copy, const N: usize, const NUM_CHANNELS: usize> From<[T; 3 + 2 * N + NUM_CHANNELS]> for XorLayout<T, N, NUM_CHANNELS> {
    fn from(row: [T; 3 + 2 * N + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(row) }
    }
}

impl<T: Copy, const N: usize, const NUM_CHANNELS: usize> From<XorLayout<T, N, NUM_CHANNELS>> for [T; 3 + 2 * N + NUM_CHANNELS] {
    fn from(value: XorLayout<T, N, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const N: usize, const NUM_CHANNELS: usize> Borrow<XorLayout<T, N, NUM_CHANNELS>> for [T; 3 + 2 * N + NUM_CHANNELS] {
    fn borrow(&self) -> &XorLayout<T, N, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const N: usize, const NUM_CHANNELS: usize> BorrowMut<XorLayout<T, N, NUM_CHANNELS>> for [T; 3 + 2 * N + NUM_CHANNELS] {
    fn borrow_mut(&mut self) -> &mut XorLayout<T, N, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}
