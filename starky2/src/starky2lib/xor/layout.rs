use std::borrow::{Borrow, BorrowMut};
use std::mem::transmute;

use crate::cross_table_lookup::{CtlColumn, TableID};
use crate::util::transmute_no_compile_time_size_checks;

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct XorLayout<T: Copy, const N: usize> {
    pub(crate) a: T,
    pub(crate) b: T,
    pub(crate) output: T,
    pub(crate) a_bits: [T; N],
    pub(crate) b_bits: [T; N],
}

impl<T: Copy, const N: usize> XorLayout<T, N> {
    pub(crate) const fn a_col() -> usize {
        0
    }

    pub(crate) const fn b_col() -> usize {
        1
    }

    pub(crate) const fn output_col() -> usize {
        2
    }

    pub fn ctl_cols_a(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..N).map(move |i| CtlColumn::new(tid, Self::a_col() + i, None))
    }

    pub fn ctl_cols_b(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..N).map(move |i| CtlColumn::new(tid, Self::b_col() + i, None))
    }

    pub fn ctl_cols_output(tid: TableID) -> impl Iterator<Item = CtlColumn> {
        (0..N).map(move |i| CtlColumn::new(tid, Self::output_col() + i, None))
    }
}

impl<T: Copy, const N: usize> From<[T; 3 + 2 * N]> for XorLayout<T, N> {
    fn from(row: [T; 3 + 2 * N]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(row) }
    }
}

impl<T: Copy, const N: usize> From<XorLayout<T, N>> for [T; 3 + 2 * N] {
    fn from(value: XorLayout<T, N>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const N: usize> Borrow<XorLayout<T, N>> for [T; 3 + 2 * N] {
    fn borrow(&self) -> &XorLayout<T, N> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const N: usize> BorrowMut<XorLayout<T, N>> for [T; 3 + 2 * N] {
    fn borrow_mut(&mut self) -> &mut XorLayout<T, N> {
        unsafe { transmute(self) }
    }
}
