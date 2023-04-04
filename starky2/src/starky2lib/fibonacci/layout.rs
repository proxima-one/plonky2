use std::{borrow::{Borrow, BorrowMut}, mem::transmute};

use crate::util::transmute_no_compile_time_size_checks;

#[repr(C)]
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct FibonacciRow<T: Copy> {
    pub n: T,
    pub f_n: T,
    pub f_n_minus_1: T,
	pub n_minus_k_inv: T,
	pub is_done: T
}

impl<T: Copy> From<[T; 5]>
    for FibonacciRow<T>
{
    fn from(row: [T; 5]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(row) }
    }
}

impl<T: Copy> From<FibonacciRow<T>>
    for [T; 5]
{
    fn from(value: FibonacciRow<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<FibonacciRow<T>>
    for [T; 5]
{
    fn borrow(&self) -> &FibonacciRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<FibonacciRow<T>>
    for [T; 5]
{
    fn borrow_mut(&mut self) -> &mut FibonacciRow<T> {
        unsafe { transmute(self) }
    }
}
