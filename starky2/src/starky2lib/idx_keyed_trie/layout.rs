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
pub struct IdxKeyedTrieRow<T: Copy> {
	pub(crate) idx: T 
	// TODO
}

pub(crate) const IDX_KEYED_TRIE_NUM_COLS: usize = size_of::<IdxKeyedTrieRow<u8>>();

impl<T: Copy + Default> IdxKeyedTrieRow<T> {
    pub fn new() -> Self {
        [T::default(); IDX_KEYED_TRIE_NUM_COLS].into()
    }
}

impl<T: Copy> From<[T; IDX_KEYED_TRIE_NUM_COLS]> for IdxKeyedTrieRow<T> {
    fn from(value: [T; IDX_KEYED_TRIE_NUM_COLS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<IdxKeyedTrieRow<T>> for [T; IDX_KEYED_TRIE_NUM_COLS] {
    fn from(value: IdxKeyedTrieRow<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<IdxKeyedTrieRow<T>> for [T; IDX_KEYED_TRIE_NUM_COLS] {
    fn borrow(&self) -> &IdxKeyedTrieRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<IdxKeyedTrieRow<T>> for [T; IDX_KEYED_TRIE_NUM_COLS] {
    fn borrow_mut(&mut self) -> &mut IdxKeyedTrieRow<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; IDX_KEYED_TRIE_NUM_COLS]> for IdxKeyedTrieRow<T> {
    fn borrow(&self) -> &[T; IDX_KEYED_TRIE_NUM_COLS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; IDX_KEYED_TRIE_NUM_COLS]> for IdxKeyedTrieRow<T> {
    fn borrow_mut(&mut self) -> &mut [T; IDX_KEYED_TRIE_NUM_COLS] {
        unsafe { transmute(self) }
    }
}
