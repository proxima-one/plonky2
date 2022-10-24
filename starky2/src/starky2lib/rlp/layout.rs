use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use crate::{util::transmute_no_compile_time_size_checks, permutation::PermutationPair, cross_table_lookup::{TableID, CtlColSet}};

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct RlpRow<T: Copy> {
    // register state
	pub(crate) op_id: T,
    pub(crate) pc: T,
    pub(crate) count: T,
    pub(crate) content_len: T,
    pub(crate) list_count: T,
    pub(crate) depth: T,
	pub(crate) next: T,
    pub(crate) is_last: T,

    // opcode
    // 00000000: NewEntry
    // 00000001: List
    // 00000010: Recurse
    // 00000100: Return
    // 00001000: StrPush
    // 00010000: StrPrefix
    // 00100000: ListPrefix
    // 01000000: EndEntry
    // 10000000: Halt
    pub(crate) opcode: [T; 8],


    // advice columns for checking register state / transitions
    // for checking if depth is 0
    pub(crate) depth_is_zero: T,
    pub(crate) depth_inv: T,
    // for checking if content len is 0
    pub(crate) content_len_is_zero: T,
    pub(crate) content_len_inv: T,
    // for chcecking if count == content.len
    pub(crate) content_len_minus_count_is_zero: T,
    pub(crate) content_len_minus_count_inv: T,
    // for checking if  list_count == content.len()
    pub(crate) content_len_minus_list_count_is_zero: T,
    pub(crate) content_len_minus_list_count_inv: T,
    // for checking prefix cases
    // 0000: single byte in [0x00..0x7F]
    // 0001: string <=55 bytes long
    // 0010: string >55 bytes long
    // 0100: list whose inner encodings total <=55 bytes long
    // 1000: list whose inner encodings total >55 bytes long
    pub(crate) prefix_case_flags: [T; 4],

    // LUTs for range checks
    pub(crate) rc_u8: T,
    pub(crate) rc_55: T,
    
    // advice for checking LUT contents
    pub(crate) count_u8: T,
    pub(crate) count_u8_minus_255_inv: T,
    pub(crate) count_u8_is_255: T,
    pub(crate) count_55: T,
    pub(crate) count_55_minus_55_inv: T,
    pub(crate) count_55_is_55: T, 

    // 5-channel CTL to the input memory
    // each represented as [addr, val]
    pub(crate) input_memory_ctl: [[T; 2]; 5],
    // 3-channel CTL to the call stack
    // each represented as [is_pop, val]
    pub(crate) call_stack_ctl: [[T; 2]; 3],
    // 2-channel CTL to the output stack
    // each represented as [is_pop, val]
    pub(crate) output_stack_ctl: [[T; 2]; 2],
}

pub(crate) const RLP_NUM_COLS: usize = size_of::<RlpRow<u8>>();

impl<T: Copy + Default> RlpRow<T>
{
    pub fn new() -> Self {
        [T::default(); RLP_NUM_COLS].into()
    }
}

impl<T: Copy> From<[T; RLP_NUM_COLS]>
    for RlpRow<T>
{
    fn from(value: [T; RLP_NUM_COLS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<RlpRow<T>>
    for [T; RLP_NUM_COLS]
{
    fn from(value: RlpRow<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<RlpRow<T>>
    for [T; RLP_NUM_COLS]
{
    fn borrow(&self) -> &RlpRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<RlpRow<T>>
    for [T; RLP_NUM_COLS]
{
    fn borrow_mut(&mut self) -> &mut RlpRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; RLP_NUM_COLS]>
    for RlpRow<T>
{
    fn borrow(&self) -> &[T; RLP_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; RLP_NUM_COLS]>
    for RlpRow<T>
{
    fn borrow_mut(&mut self) -> &mut [T; RLP_NUM_COLS] {
        unsafe { transmute(self) }
    }
}
