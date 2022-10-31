use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};
use memoffset::{offset_of, span_of};

use itertools::Itertools;

use crate::cross_table_lookup::CtlColSet;
use crate::{cross_table_lookup::TableID, util::transmute_no_compile_time_size_checks};

pub const KECCAK_WIDTH_BYTES: usize = 200;
pub const KECCAK_WIDTH_U32S: usize = KECCAK_WIDTH_BYTES / 4;
pub const KECCAK_RATE_BYTES: usize = 136;
pub const KECCAK_RATE_U32S: usize = KECCAK_RATE_BYTES / 4;
pub const KECCAK_CAPACITY_BYTES: usize = 64;
pub const KECCAK_CAPACITY_U32S: usize = KECCAK_CAPACITY_BYTES / 4;

#[repr(C)]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Keccak256StackRow<T: Copy> {
    /// 00: halt 
    /// 01: absorb
    /// 10: squeeze 
    /// we start a new sponge whenever we go from squeeze to absorb mode
    pub(crate) opcode: [T; 2],

    /// binary flag indicating when to "invoke" the permutation STARK
    pub(crate) invoke_permutation_filter: T,

    /// id of the current hash being absorbed or squeezed 
    /// this is used by the stack to ensure there's a 1-1 mapping between preimages and hashes.
    /// it starts at the number of items to be hashed minus 1, and it decrements by one for each preimage
    /// when it reaches zero, that's the last item. 
    pub(crate) op_id: T,

    pub(crate) is_last_block: T,

    // TODO: make these bytes to avoid duplicating the cols below
    /// current block being absorbed as 32-bit chunks
    pub(crate) input_block: [T; KECCAK_RATE_U32S],

    /// next bytes to be popped off of the stack - in other words, this is a 136-channel stack lookup
    pub(crate) input_block_bytes: [T; KECCAK_RATE_BYTES],
    /// only need one of these because it's always pop!
    pub(crate) stack_is_pop: T,
    /// filters for when we are and aren't popping from the stack - unfortunately we need 136 of these because sometimes
    /// we will stop early
    pub(crate) stack_filters: [T; KECCAK_RATE_BYTES],
    /// ditto for timestamps. 
    pub(crate) timestamps: [T; KECCAK_RATE_BYTES],

    /// we also have two more stack channels for reading the current op_id and len from the stack containing payloads to be hashed
    /// these are used to determine / check hash_idx
    pub(crate) op_id_stack_filter: T,
    pub(crate) op_id_stack_timestamp: T,

    /// len of the current item being hashed, in bytes
    /// this is popped off of the input stack and is assumed to be correct
    /// that is, we assume here that the input stack was "produced" by another STARK
    pub(crate) len: T,
    pub(crate) len_stack_filter: T,
    pub(crate) len_stack_timestamp: T,

    /// rate words of the current sponge state as u32s
    pub(crate) curr_state_rate: [T; KECCAK_RATE_U32S],

    /// rate part of the sponge state as u32s after the input block has been xor'd into the rate portion of the state
    /// i.e. the thing the permutation (keccak_f) will use as input
    pub(crate) xored_state_rate: [T; KECCAK_RATE_U32S],

    /// capacity words of the current sponge state as u32s
    pub(crate) curr_state_capacity: [T; KECCAK_CAPACITY_U32S],

    /// new sponge state as u32s
    /// rate || capacity
    pub(crate) new_state: [T; KECCAK_WIDTH_U32S],

    /// a column into which len is copied
    pub(crate) rc_136: T,
    pub(crate) rc_136_permuted: T,
    /// a LUT used to check padding against length
    pub(crate) lut_136: T,
    pub(crate) lut_136_is_135: T,
    pub(crate) lut_136_minus_135_inv: T,
    pub(crate) lut_136_permuted: T,

    pub(crate) output_mem_addrs: [T; 32],
    pub(crate) output_mem_values: [T; 32],
    pub(crate) output_mem_filter: T,
}

pub(crate) fn lookup_pairs() -> Vec<((usize, usize), (usize, usize))> {
    vec![
        (
            (offset_of!(R, rc_136), offset_of!(R, rc_136_permuted)),
            (offset_of!(R, lut_136), offset_of!(R, lut_136_permuted))
        )
    ]
}

impl<T: Copy + Default> Keccak256StackRow<T> {
    pub fn new() -> Self {
        [T::default(); KECCAK_256_STACK_NUM_COLS].into()
    }
}


pub fn xor_ctl_cols_a(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    span_of!(R, input_block)
        .map(move |i| CtlColSet::new(
            tid,
            vec![i],
            Some(offset_of!(R, opcode))
        ))
}

pub fn xor_ctl_cols_b(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    span_of!(R, curr_state_rate)
        .map(move |i| CtlColSet::new(
            tid,
            vec![i],
            Some(offset_of!(R, opcode))
        ))
}

pub fn xor_ctl_cols_output(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    span_of!(R, xored_state_rate)
        .map(move |i| CtlColSet::new(
            tid,
            vec![i],
            Some(offset_of!(R, opcode))
        ))
}

pub fn keccak_ctl_col_input(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    let cols = span_of!(R, xored_state_rate);
    let cols = cols.chain(span_of!(R, curr_state_capacity));
    std::iter::once(CtlColSet::new(
        tid,
        cols.collect_vec(),
        Some(offset_of!(R, invoke_permutation_filter)),
    ))
}

pub fn keccak_ctl_col_output(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    let cols = span_of!(R, new_state).collect_vec();
    std::iter::once(CtlColSet::new(
        tid,
        cols,
        Some(offset_of!(R, invoke_permutation_filter)),
    ))
}

// TODO: replace with memory CTLs
// pub fn input_ctl_col(tid: TableID) -> impl Iterator<Item = CtlColSet> {
//     let cols = span_of!(R, input_block).collect_vec();
//     std::iter::once(CtlColSet::new(tid, cols, Some(offset_of!(R, mode_bits) + 1)))
// }

// pub fn output_ctl_col(tid: TableID) -> impl Iterator<Item = CtlColSet> {
//     let cols = span_of!(R, curr_state_rate).collect_vec();
//     std::iter::once(CtlColSet::new(tid, cols, Some(offset_of!(R, mode_bits) + 1)))
// }

impl<T: Copy + Default> Default for Keccak256StackRow<T> {
    fn default() -> Self {
        Self::new()
    }
}

type R = Keccak256StackRow<u8>;
// `u8` is guaranteed to have a `size_of` of 1.
pub const KECCAK_256_STACK_NUM_COLS: usize = size_of::<R>();

/// 1 public input: the starting timestamp of the input stack.
pub const KECCAK_256_STACK_NUM_PIS: usize = 1;

impl<T: Copy> From<[T; KECCAK_256_STACK_NUM_COLS]> for Keccak256StackRow<T> {
    fn from(value: [T; KECCAK_256_STACK_NUM_COLS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<Keccak256StackRow<T>> for [T; KECCAK_256_STACK_NUM_COLS] {
    fn from(value: Keccak256StackRow<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<Keccak256StackRow<T>> for [T; KECCAK_256_STACK_NUM_COLS] {
    fn borrow(&self) -> &Keccak256StackRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<Keccak256StackRow<T>> for [T; KECCAK_256_STACK_NUM_COLS] {
    fn borrow_mut(&mut self) -> &mut Keccak256StackRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; KECCAK_256_STACK_NUM_COLS]> for Keccak256StackRow<T> {
    fn borrow(&self) -> &[T; KECCAK_256_STACK_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; KECCAK_256_STACK_NUM_COLS]> for Keccak256StackRow<T> {
    fn borrow_mut(&mut self) -> &mut [T; KECCAK_256_STACK_NUM_COLS] {
        unsafe { transmute(self) }
    }
}
