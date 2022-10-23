use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use crate::{util::transmute_no_compile_time_size_checks, permutation::PermutationPair, cross_table_lookup::{TableID, CtlColSet}};

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct RlpRow<T: Copy, const NUM_CHANNELS: usize> {
	// info about the current item we're encoding
	pub(crate) item_id: T,
	pub(crate) next_item_addr: T,
	pub(crate) is_last_item: T, 
	pub(crate) depth: T,

	// info about the current entry
	pub(crate) is_list: T,
	pub(crate) len: T,
	pub(crate) idx: T,

	// state
	// 0000: observe new item 
	// 0001: observe new entry
	// 0010: push prefix
	// 0100: push str 
	// 1000: push item id
	pub(crate) opcode: [T; 4],

	// prefix calculation
	// says how many bytes we need to encode the prefix for the current entry, with the following encoding
	// 0000000: 1
	// 0000001: 2
	// ...
	// 1000000: 8
	// we cap the prefix length at 8 and assume no individual item will have a payload greater than 2^32 bytes
	pub(crate) prefix_num_bytes_bits: [T; 8],

	// these are not range checked by this STARK. they should be range-checked
	// via a CTL, ideally to the `integer_rc` stark
	pub(crate) prefix_bytes: [T; 8],


    // fitler cols for each lookup channe
    pub(crate) filter_cols: [T; NUM_CHANNELS],
}

pub(crate) const RLP_NUM_COLS_BASE: usize = size_of::<RlpRow<u8, 0>>();

impl<T: Copy + Default, const NUM_CHANNELS: usize> RlpRow<T, NUM_CHANNELS>
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); RLP_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; RLP_NUM_COLS_BASE + NUM_CHANNELS]>
    for RlpRow<T, NUM_CHANNELS>
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: [T; RLP_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<RlpRow<T, NUM_CHANNELS>>
    for [T; RLP_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn from(value: RlpRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<RlpRow<T, NUM_CHANNELS>>
    for [T; RLP_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &RlpRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<RlpRow<T, NUM_CHANNELS>>
    for [T; RLP_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut RlpRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; RLP_NUM_COLS_BASE + NUM_CHANNELS]>
    for RlpRow<T, NUM_CHANNELS>
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; RLP_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; RLP_NUM_COLS_BASE + NUM_CHANNELS]>
    for RlpRow<T, NUM_CHANNELS>
where
    [(); RLP_NUM_COLS_BASE + NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; RLP_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}