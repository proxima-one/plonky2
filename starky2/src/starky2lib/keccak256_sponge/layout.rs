use std::{mem::{size_of, transmute}, borrow::{Borrow, BorrowMut}};

use crate::{util::transmute_no_compile_time_size_checks, cross_table_lookup::TableID};
use crate::cross_table_lookup::CtlColumn;

pub(crate) const KECCAK_WIDTH_BYTES: usize = 200;
pub(crate) const KECCAK_WIDTH_U32S: usize = KECCAK_WIDTH_BYTES / 4;
pub(crate) const KECCAK_RATE_BYTES: usize = 136;
pub(crate) const KECCAK_RATE_U32S: usize = KECCAK_RATE_BYTES / 4;
pub(crate) const KECCAK_CAPACITY_BYTES: usize = 64;
pub(crate) const KECCAK_CAPACITY_U32S: usize = KECCAK_CAPACITY_BYTES / 4;


#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct Keccak256SpongeRow<T: Copy> {
    /// 00: padding row
    /// 01: absorb
    /// 10: squeeze
    /// 11: illegal
    /// we start a new sponge whenever we go from squeeze to absorb mode
    pub(crate) mode_bits: [T; 2],

	/// set to 1 when absorbing, 0 when squeezing
	pub(crate) input_filter: T,
	/// set to 0 when absorbing, 1 when squeezing
	pub(crate) output_filter: T,

    /// set to 0 during padding rows, 1 otherwise
    pub(crate) invoke_permutation_filter: T,

    /// a LUT used to range-check bytes
    pub(crate) u8_lookup: T,
    /// a LUT used ot range-check 7-bit numbers
    pub(crate) u7_lookup: T,

	/// idx of the current block being absorbed or squeezed as two bytes
	/// This is used so lookups can be sure there's a 1-1 mapping between sponge instances
	/// when the sponge is used by multiple looking tables over many blocks
    /// this is range checked to be a 15-bit number
	pub(crate) block_idx_bytes: [T; 2],

	/// idx of the current hash being absorbed or squeezed as two bytes
	/// This is used so lookups can be sure there's a 1-1 mapping between sponge instances
	/// when the sponge is used by multiple looking tables over many blocks
    /// this is range checked to be a 16-bit number`
	pub(crate) hash_idx_bytes: [T; 2],

    /// current block being absorbed as 32-bit chunks
    pub(crate) input_block: [T; KECCAK_RATE_U32S],

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

    /// current block being absorbed as 32-bit chunks, each encoded as follows for lookup separation (from LSB to MSB):
    /// bits 0..32: the 32-bit chunk of the current block
    /// bits 32..48: 16-bit current hash idx.
    /// bits 48..63: 15-bit current block idx
    pub(crate) input_block_encoded: [T; KECCAK_RATE_U32S],

    /// columns for constructing the LUT
    pub(crate) u8_lookup_bits: [T; 8],

}

impl<T: Copy + Default> Keccak256SpongeRow<T> {
    pub fn new() -> Self {
        [T::default(); KECCAK_256_NUM_COLS].into()
    }
}

pub const fn xor_filter_col() -> usize {
    0
}

pub const fn input_filter_col() -> usize {
    xor_filter_col() + 2
}

pub const fn output_filter_col() -> usize {
    input_filter_col() + 1
}

pub const fn invoke_permutation_filter_col() -> usize {
    output_filter_col() + 1
}

pub(crate) const fn u8_lut_col() -> usize {
    invoke_permutation_filter_col() + 1
}

pub(crate) const fn u7_lut_col() -> usize {
    u8_lut_col() + 1
}

pub(crate) const fn block_idx_bytes_start_col() -> usize {
    u7_lut_col() + 1
}

pub(crate) const fn hash_idx_bytes_start_col() -> usize {
    block_idx_bytes_start_col() + 2
}

pub(crate) const fn input_block_start_col() -> usize {
    hash_idx_bytes_start_col() + 2
}

pub(crate) const fn curr_state_rate_start_col() -> usize {
    input_block_start_col() + KECCAK_RATE_U32S
}

pub(crate) const fn xored_state_rate_start_col() -> usize {
    curr_state_rate_start_col() + KECCAK_RATE_U32S
}

pub(crate) const fn curr_state_capacity_start_col() -> usize {
    xored_state_rate_start_col() + KECCAK_RATE_U32S
}

pub(crate) const fn new_state_start_col() -> usize {
    curr_state_capacity_start_col() + KECCAK_WIDTH_U32S 
}

pub fn xor_ctl_cols_a(tid: TableID) -> impl Iterator<Item = CtlColumn> {
    (0..KECCAK_RATE_U32S).map(move |i| CtlColumn::new(
        tid,
    input_block_start_col() + i,
        Some(xor_filter_col())
    ))
}

pub fn xor_ctl_cols_b(tid: TableID) -> impl Iterator<Item = CtlColumn> {
    (0..KECCAK_RATE_U32S).map(move |i| CtlColumn::new(
        tid,
        curr_state_rate_start_col() + i,
        Some(xor_filter_col())
    ))
}

pub fn xor_ctl_cols_c(tid: TableID) -> impl Iterator<Item = CtlColumn> {
    (0..KECCAK_RATE_U32S).map(move |i| CtlColumn::new(
        tid,
        xored_state_rate_start_col() + i,
        Some(xor_filter_col())
    ))
}

pub fn keccak_ctl_col_input(tid: TableID) -> impl Iterator<Item = CtlColumn> {
    (0..KECCAK_RATE_U32S).map(move |i| CtlColumn::new(
        tid,
        xored_state_rate_start_col() + i,
        Some(invoke_permutation_filter_col())
    )).chain((0..KECCAK_CAPACITY_U32S).map(move |i| CtlColumn::new(
        tid,
        curr_state_capacity_start_col() + i,
        Some(invoke_permutation_filter_col())
    )))
}

pub fn keccak_ctl_col_output(tid: TableID) -> impl Iterator<Item = CtlColumn> {
    (0..KECCAK_WIDTH_U32S).map(move |i| CtlColumn::new(
        tid,
        new_state_start_col() + i,
        Some(xor_filter_col())
    ))
}

impl<T: Copy + Default> Default for Keccak256SpongeRow<T> {
    fn default() -> Self {
        Self::new()
    }
}

// `u8` is guaranteed to have a `size_of` of 1.
pub const KECCAK_256_NUM_COLS: usize = size_of::<Keccak256SpongeRow<u8>>();
pub const KECCAK_256_NUM_PIS: usize = 0;

impl<T: Copy> From<[T; KECCAK_256_NUM_COLS]> for Keccak256SpongeRow<T> {
    fn from(value: [T; KECCAK_256_NUM_COLS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<Keccak256SpongeRow<T>> for [T; KECCAK_256_NUM_COLS] {
    fn from(value: Keccak256SpongeRow<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<Keccak256SpongeRow<T>> for [T; KECCAK_256_NUM_COLS] {
    fn borrow(&self) -> &Keccak256SpongeRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<Keccak256SpongeRow<T>> for [T; KECCAK_256_NUM_COLS] {
    fn borrow_mut(&mut self) -> &mut Keccak256SpongeRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; KECCAK_256_NUM_COLS]> for Keccak256SpongeRow<T> {
    fn borrow(&self) -> &[T; KECCAK_256_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; KECCAK_256_NUM_COLS]> for Keccak256SpongeRow<T> {
    fn borrow_mut(&mut self) -> &mut [T; KECCAK_256_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

