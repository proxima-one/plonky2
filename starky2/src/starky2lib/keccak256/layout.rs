use std::{mem::{size_of, transmute}, borrow::{Borrow, BorrowMut}};

use crate::util::transmute_no_compile_time_size_checks;

pub(crate) const KECCAK_WIDTH_BYTES: usize = 200;
pub(crate) const KECCAK_WIDTH_U32S: usize = KECCAK_WIDTH_BYTES / 4;
pub(crate) const KECCAK_RATE_BYTES: usize = 136;
pub(crate) const KECCAK_RATE_U32S: usize = KECCAK_RATE_BYTES / 4;
pub(crate) const KECCAK_CAPACITY_BYTES: usize = 64;
pub(crate) const KECCAK_CAPACITY_U32S: usize = KECCAK_CAPACITY_BYTES / 4;


#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct Keccak256Layout<T: Copy> {
    /// 1 if this row represents a full input block, i.e. one in which each byte is an input byte,
    /// not a padding byte; 0 otherwise.
    pub(crate) is_full_input_block: T,

    /// 1 if this row represents the final block of a sponge, in which case some or all of the bytes
    /// in the block will be padding bytes; 0 otherwise.
    pub(crate) is_final_block: T,

	/// set to 1 when absorbing, 0 when squeezing
	pub(crate) input_filter: T,
	/// set to 0 when absorbing, 1 when squeezing
	pub(crate) output_filter: T,

    /// The length of the original input, in u32s. This is not checked by this STARK. It must be checked by the 'calling' STARK
    pub len: T,

	/// set to 1 pretty much every row (I think). may not be necessary
	pub(crate) invoke_permutation_filter: T,

	/// set to 1 when absorbing, 0 when squeezing
	pub(crate) invoke_xor_filter: T,

	/// num_byte
	pub(crate) block_idx: T,

	/// idx of the current instance of the sponge.
	/// This is used so lookups can be sure there's a 1-1 mapping between sponge instances
	/// when the sponge is used by multiple looking tables over many blocks
	pub(crate) hash_idx: T,

	/// length of the current block being absorbed in bytes. This is not checked by this function, 
	pub(crate) block_len: T,

	/// current state of the sponge as u32s
	/// by convention: rate_bits || cpacity_bits
	pub(crate) curr_state: [T; KECCAK_WIDTH_U32S],

	/// rate part of the sponge state as u32s after the input block has been xor'd into the rate portion of the state
	/// i.e. the thing the permutation (keccak_f) will use as input
	pub(crate) curr_rate_state_xord: [T; KECCAK_RATE_U32S],
}

impl<T: Copy + Default> Keccak256Layout<T> {
    pub fn new() -> Self {
        [T::default(); KECCAK_256_NUM_COLS].into()
    }
}

impl<T: Copy + Default> Default for Keccak256Layout<T> {
    fn default() -> Self {
        Self::new()
    }
}

// `u8` is guaranteed to have a `size_of` of 1.
pub const KECCAK_256_NUM_COLS: usize = size_of::<Keccak256Layout<u8>>();

impl<T: Copy> From<[T; KECCAK_256_NUM_COLS]> for Keccak256Layout<T> {
    fn from(value: [T; KECCAK_256_NUM_COLS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<Keccak256Layout<T>> for [T; KECCAK_256_NUM_COLS] {
    fn from(value: Keccak256Layout<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<Keccak256Layout<T>> for [T; KECCAK_256_NUM_COLS] {
    fn borrow(&self) -> &Keccak256Layout<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<Keccak256Layout<T>> for [T; KECCAK_256_NUM_COLS] {
    fn borrow_mut(&mut self) -> &mut Keccak256Layout<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; KECCAK_256_NUM_COLS]> for Keccak256Layout<T> {
    fn borrow(&self) -> &[T; KECCAK_256_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; KECCAK_256_NUM_COLS]> for Keccak256Layout<T> {
    fn borrow_mut(&mut self) -> &mut [T; KECCAK_256_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

