use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, transmute},
};

use memoffset::offset_of;

use crate::{util::transmute_no_compile_time_size_checks, cross_table_lookup::{TableID, CtlColSet}};

// NOTE: THIS IS ONLY DEFINED OVER GOLDILOCKS FIELD (p = w^64 - 2^32 + 1). ONLY INSTANTIATE IT OVER GOLDILOCKS

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct Ecgfp5Row<T: Copy, const NUM_CHANNELS: usize> {
    pub(crate) op_idx: T,

    // 00 add
    // 01 double
    // 10 double and add
    // 11 illegal
    pub(crate) microcode: [T; 2],

    // 00 add
    // 01 double and add
    // 10 scalar mul
    // 11 illegal
    pub(crate) opcode: [T; 2],

    // the LHS input
    pub(crate) input_1: Point<T>,

    // the RHS input
    // if this current microcode is add or double and add, this is the addend
    // if the current microcode is double, this is ignored
    pub(crate) input_2: Point<T>,

    // 1 if the LHS input is the point at infinity, 0 otherwise
    pub(crate) input_1_is_infinity: T,
    // 1 if the RHS input is the point at infinity, 0 otherwise
    pub(crate) input_2_is_infinity: T,

    // the scalar to be multiplied against. must fit in 32-bits
    // each step, if the current MSB is 1, the current power of two is subtracted from it
    pub(crate) scalar: T,
    // scalar as big-endian bits
    pub(crate) scalar_bits: [T; 32],
    pub(crate) scalar_step_bits: [T; 32],

    // the output point of the operation at hand. this is always in weierstrass form
    pub(crate) output: Point<T>,
    pub(crate) output_is_infinity: T,

    // working variables for add
    pub(crate) add_lhs_input_is_infinity: T,
    pub(crate) add_lhs_input: Point<T>,
    pub(crate) add_num_lambda: Ext<T>,
    pub(crate) add_lambda_denom_is_zero: T,
    pub(crate) add_denom_lambda: Ext<T>,
    pub(crate) add_denom_lambda_inv: Ext<T>,
    pub(crate) add_lambda: Ext<T>,
    pub(crate) add_x3: Ext<T>,
    pub(crate) add_i3: T,
    pub(crate) add_output: Point<T>,
    pub(crate) add_output_is_infinity: T,
    // the inverse of x1 minus_x2 if they aren't equal, 0 otherwise
    pub(crate) add_x1_minus_x2_inv: Ext<T>,
    // 1 if the the x coordinates of the add inputs are the same, 0 otherwise
    pub(crate) add_xs_are_same: T,
    pub(crate) add_y1_minus_y2_inv: Ext<T>,
    pub(crate) add_ys_are_same: T,

    // working variables for double
    pub(crate) dbl_num_lambda: Ext<T>,
    pub(crate) dbl_denom_lambda: Ext<T>,
    pub(crate) dbl_denom_lambda_inv: Ext<T>,
    pub(crate) dbl_lambda_denom_is_zero: T,
    pub(crate) dbl_lambda: Ext<T>,
    pub(crate) dbl_x3: Ext<T>,
    pub(crate) dbl_output: Point<T>,
    pub(crate) dbl_output_is_infinity: T,

    // filters for cross-table lookups
    // 0: add,
    // 1: double-add,
    // 2: scalar mul input
    // 3: scalar mul output
    pub(crate) filter_cols_by_opcode: [[T; 4]; NUM_CHANNELS],
}

pub fn ctl_cols_add<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = Ecgfp5Row<u8, 0>;
    let mut colset = Vec::new();
    colset.push(
        offset_of!(R, op_idx),
    );
    colset.push(
        offset_of!(R, opcode),
    );
    colset.push(
        offset_of!(R, opcode) + 1,
    );

    colset.extend((0..10).map(|i| offset_of!(R, input_1) + i));
    colset.extend((0..10).map(|i| offset_of!(R, input_2) + i));
    colset.extend((0..10).map(|i| offset_of!(R, output) + i));

    (0..NUM_CHANNELS).map(move |i| CtlColSet::new(
        tid,
        colset.clone(),
        Some(offset_of!(R, filter_cols_by_opcode) + 4 * i),
    ))
}

pub fn ctl_cols_double_add<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = Ecgfp5Row<u8, 0>;
    let mut colset = Vec::new();
    colset.push(
        offset_of!(R, op_idx),
    );
    colset.push(
        offset_of!(R, opcode),
    );
    colset.push(
        offset_of!(R, opcode) + 1,
    );

    colset.extend((0..10).map(|i| offset_of!(R, input_1) + i));
    colset.extend((0..10).map(|i| offset_of!(R, input_2) + i));
    colset.extend((0..10).map(|i| offset_of!(R, output) + i));

    (0..NUM_CHANNELS).map(move |i| CtlColSet::new(
        tid,
        colset.clone(),
        Some(offset_of!(R, filter_cols_by_opcode) + 1 + 4 * i),
    ))
}

pub fn ctl_cols_scalar_mul_input<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = Ecgfp5Row<u8, 0>;
    let mut colset = Vec::new();
    colset.push(
        offset_of!(R, op_idx),
    );
    colset.push(
        offset_of!(R, opcode),
    );
    colset.push(
        offset_of!(R, opcode) + 1,
    );

    colset.extend((0..10).map(|i| offset_of!(R, input_2) + i));
    colset.push(offset_of!(R, scalar));

    (0..NUM_CHANNELS).map(move |i| CtlColSet::new(
        tid,
        colset.clone(),
        Some(offset_of!(R, filter_cols_by_opcode) + 2 + 4 * i),
    ))
}

pub fn ctl_cols_scalar_mul_output<const NUM_CHANNELS: usize>(tid: TableID) -> impl Iterator<Item = CtlColSet> {
    type R = Ecgfp5Row<u8, 0>;
    let mut colset = Vec::new();

    colset.push(
        offset_of!(R, op_idx),
    );
    colset.push(
        offset_of!(R, opcode),
    );
    colset.push(
        offset_of!(R, opcode) + 1,
    );
    colset.extend((0..10).map(|i| offset_of!(R, output) + i));

    (0..NUM_CHANNELS).map(move |i| CtlColSet::new(
        tid,
        colset.clone(),
        Some(offset_of!(R, filter_cols_by_opcode) + 3 + 4 * i),
    ))
}

pub const ECGFP5_NUM_COLS_BASE: usize = size_of::<Ecgfp5Row<u8, 0>>();
pub const ECGFP5_NUM_PIS: usize = 0;

pub type Ext<T> = [T; 5];
pub type Point<T> = [Ext<T>; 2];

impl<T: Copy + Default, const NUM_CHANNELS: usize> Ecgfp5Row<T, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    pub fn new() -> Self {
        [T::default(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS].into()
    }
}

impl<T: Copy + Default, const NUM_CHANNELS: usize> Default for Ecgfp5Row<T, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<[T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]>
    for Ecgfp5Row<T, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn from(value: [T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<Ecgfp5Row<T, NUM_CHANNELS>>
    for [T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn from(value: Ecgfp5Row<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<Ecgfp5Row<T, NUM_CHANNELS>>
    for [T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn borrow(&self) -> &Ecgfp5Row<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<Ecgfp5Row<T, NUM_CHANNELS>>
    for [T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut Ecgfp5Row<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]>
    for Ecgfp5Row<T, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn borrow(&self) -> &[T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]>
    for Ecgfp5Row<T, NUM_CHANNELS>
where
    [(); ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS]:,
{
    fn borrow_mut(&mut self) -> &mut [T; ECGFP5_NUM_COLS_BASE + 4 * NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
