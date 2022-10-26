use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute}, ops::Range,
};
use memoffset::{offset_of, span_of};

use crate::{util::transmute_no_compile_time_size_checks, permutation::PermutationPair, cross_table_lookup::{TableID, CtlColSet}};

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct RlpRow<T: Copy> {
    // register state: 8 cols (off 0)
	pub(crate) op_id: T,
    pub(crate) pc: T,
    pub(crate) count: T,
    pub(crate) content_len: T,
    pub(crate) list_count: T,
    pub(crate) depth: T,
	pub(crate) next: T,
    pub(crate) is_last: T,

    // opcode: 8 cols (off 8)
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
    // 14 cols (off 16)
    // for checking if depth is 0
    pub(crate) depth_is_zero: T,
    pub(crate) depth_inv: T,
    // for checking if content len is 0
    pub(crate) content_len_is_zero: T,
    pub(crate) content_len_inv: T,
    // for checking if list count is 0
    pub(crate) list_count_is_zero: T,
    pub(crate) list_count_inv: T,
    // for chcecking if count == content.len
    pub(crate) content_len_minus_count_is_zero: T,
    pub(crate) content_len_minus_count_inv: T,
    // for checking if  list_count == content.len()
    pub(crate) content_len_minus_list_count_is_zero: T,
    pub(crate) content_len_minus_list_count_inv: T,

    // for checking prefix cases: 4 cols (off 30)
    // 0000: single byte in [0x00..0x7F]
    // 0001: string <=55 bytes long
    // 0010: string >55 bytes long
    // 0100: list whose inner encodings total <=55 bytes long
    // 1000: list whose inner encodings total >55 bytes long
    pub(crate) prefix_case_flags: [T; 4],

    // byte range checks via LUT
    // 15 cols (off 34)
    // there are 5 rc'd cells - one is for
    // bytes read from input memory
    // the other are for the byte decomposition of count
    // used to calculate the ceil(log_256(count))
    pub(crate) rc_u8s: [T; 5],
    pub(crate) rc_u8_permuted: [T; 5],
    pub(crate) lut_u8_permuteds: [T; 5],

    // range checking for prefix calculation
    // 18 cols (off 49)
    pub(crate) rc_55_limbs: [T; 6],
    pub(crate) rc_55_limbs_permuted: [T; 6],
    pub(crate) lut_55_permuted_limbs: [T; 6],

    // range checking for special case where: 3 cols (off 67)
    // it's a single-byte string in 0x00..0x7F
    pub(crate) rc_127_permuted: T,
    pub(crate) lut_127_permuted: T,
    pub(crate) rc_127: T,

    // advice for checks applied when the prover claims
    // count is greater than 55
    // 2 cols (off 70)
    pub(crate) upper_limbs_sum_inv: T,
    pub(crate) count_in_range: T,
    // advice for counting length of length in bytes: 5 cols (off 72)
    // 0000: 0,
    // 0001: 1,
    // 0010: 2,
    // 0100: 3,
    // 1000: 4,
    pub(crate) log256_flags: [T; 4],
    pub(crate) top_byte_inv: T,

    // other bytes for prefix calculation: 4 cols (off 77)
    pub(crate) count_is_one: T,
    pub(crate) count_minus_one_inv: T,
    pub(crate) prefix_case_tmp: T,
    pub(crate) prefix_case_tmp_2: T,

    
    // advice for checking LUT contents: 9 (off 81)
    pub(crate) count_127: T,
    pub(crate) count_127_minus_127_inv: T,
    pub(crate) count_127_is_127: T,
    pub(crate) count_u8: T,
    pub(crate) count_u8_minus_255_inv: T,
    pub(crate) count_u8_is_255: T,
    pub(crate) count_55: T,
    pub(crate) count_55_minus_55_inv: T,
    pub(crate) count_55_is_55: T, 

    // 5-channel CTL to the input memory: 15 cols
    // each represented as [addr, val]
    pub(crate) input_memory: [[T; 2]; 5],
    pub(crate) input_memory_filters: [T; 5],
    // 3-channel CTL to the call stack: 9 cols
    // each represented as [is_pop, val]
    pub(crate) call_stack: [[T; 3]; 3],
    pub(crate) call_stack_filters: [T; 3],
    // 5-channel CTL to the output stack: 20 cols
    // each represented as [is_pop, val]
    pub(crate) output_stack: [[T; 3]; 5],
    pub(crate) output_stack_filters: [T; 5],
}

pub fn rc_55_cols() -> Range<usize> { span_of!(RlpRow<u8>, rc_55_limbs) }
pub fn lut_55_col() -> usize { offset_of!(RlpRow<u8>, count_55) }
pub fn rc_55_permuted_cols() -> Range<usize> { span_of!(RlpRow<u8>, rc_55_limbs_permuted) }
pub fn lut_55_permuted_cols() -> Range<usize> { span_of!(RlpRow<u8>, lut_55_permuted_limbs) }

pub fn rc_u8_cols() -> Range<usize> { span_of!(RlpRow<u8>, rc_u8s) }
pub fn lut_u8_col() -> usize { offset_of!(RlpRow<u8>, count_u8) }
pub fn rc_u8_permuted_cols() -> Range<usize> { span_of!(RlpRow<u8>, rc_u8_permuted) }
pub fn lut_u8_permuted_cols() -> Range<usize> { span_of!(RlpRow<u8>, lut_u8_permuteds) }

pub fn rc_127_col() -> usize { offset_of!(RlpRow<u8>, rc_127) }
pub fn lut_127_col() -> usize { offset_of!(RlpRow<u8>, count_127) }
pub fn rc_127_permuted_col() -> usize { offset_of!(RlpRow<u8>, rc_127_permuted) }
pub fn lut_127_permuted_col() -> usize { offset_of!(RlpRow<u8>, count_127_minus_127_inv) }

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
