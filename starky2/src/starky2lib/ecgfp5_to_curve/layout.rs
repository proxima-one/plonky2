use std::{mem::{transmute, size_of}, borrow::{Borrow, BorrowMut}};

use crate::{util::transmute_no_compile_time_size_checks};

// NOTE: THIS IS ONLY DEFINED OVER GOLDILOCKS FIELD (p = w^64 - 2^32 + 1). ONLY INSTANTIATE IT OVER GOLDILOCKS

#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct Ecgfp5HtcRow<T: Copy, const NUM_CHANNELS: usize> {
	// input-encoded version of the GF(p^5) element to be mapped into the curve
	pub(crate) u_encoded: Ext<[T; 2]>,
	// decoded version of the GF(p^5) element to be mapped into the curve
	pub(crate) u: Ext<T>,
	// a bunch of variables. See section 6.6.2 of this IRTF draft for more details:
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16
	pub(crate) tv1_inv: Ext<T>,
	pub(crate) tv1: Ext<T>,
	pub(crate) tv1_is_zero: T,
	pub(crate) x1: Ext<T>,
	pub(crate) gx1: Ext<T>,
	pub(crate) x2: Ext<T>,
	pub(crate) gx2: Ext<T>,
	pub(crate) sqrt_gx1: Ext<T>,
	pub(crate) sqrt_gx2: Ext<T>,

	// we use the legendre symbol for "is square"
	// see the ECGFP5 paper for details on legendre symbol calculation
	// https://eprint.iacr.org/2022/274.pdf
	pub(crate) gx1_legendre_sym: Ext<T>,
	pub(crate) frob1_gx1: Ext<T>,
	pub(crate) fromb2_gx1: Ext<T>,
	pub(crate) frob1_x_frob2_gx1: Ext<T>,
	pub(crate) frob2_frob1_x_frob2_gx1: Ext<T>,
	// gx1_to_r is in the base field so we can ignore the other 4 limbs
	// of course, we check to ensure this is the case
	pub(crate) gx1_to_r: T,
	pub(crate) squares: [T; 63],
	pub(crate) square_31_inv: T,

	// sgn0(u) = sign_m_u[4]
	pub(crate) sign_i_u: [T; 5],
	pub(crate) zero_i_u: [T; 5],
	pub(crate) sign_m_u: [T; 5],
	pub(crate) zero_m_u: [T; 5],
	pub(crate) qi_u: [T; 5],

	// sgn0(y) = sign_m_y[4]
	pub(crate) sign_i_y: [T; 5],
	pub(crate) zero_i_y: [T; 5],
	pub(crate) sign_m_y: [T; 5],
	pub(crate) zero_m_y: [T; 5],
	pub(crate) qi_m: [T; 5],

	// output point and its input-encoded form
	pub(crate) output: Point<T>,
	pub(crate) output_encoded: Point<[T; 2]>,
}

pub const ECGFP5_HTC_NUM_COLS_BASE: usize = size_of::<Ecgfp5HtcRow<u8, 0>>();
pub const ECGFP5_HTC_NUM_PIS: usize = 0;

pub type Ext<T> = [T; 5];
pub type Point<T> = [Ext<T>; 2];

impl<T: Copy + Default, const NUM_CHANNELS: usize> Ecgfp5HtcRow<T, NUM_CHANNELS>
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    pub fn new() -> Self {
        [T::default(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS].into()
    }
}


impl<T: Copy, const NUM_CHANNELS: usize> From<[T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]> for Ecgfp5HtcRow<T, NUM_CHANNELS> 
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn from(value: [T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> From<Ecgfp5HtcRow<T, NUM_CHANNELS>> for [T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS] 
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn from(value: Ecgfp5HtcRow<T, NUM_CHANNELS>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<Ecgfp5HtcRow<T, NUM_CHANNELS>> for [T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS] 
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn borrow(&self) -> &Ecgfp5HtcRow<T, NUM_CHANNELS>{
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<Ecgfp5HtcRow<T, NUM_CHANNELS>> for [T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn borrow_mut(&mut self) -> &mut Ecgfp5HtcRow<T, NUM_CHANNELS> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> Borrow<[T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]> for Ecgfp5HtcRow<T, NUM_CHANNELS> 
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn borrow(&self) -> &[T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy, const NUM_CHANNELS: usize> BorrowMut<[T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]> for Ecgfp5HtcRow<T, NUM_CHANNELS> 
where
    [(); ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS]:
{
    fn borrow_mut(&mut self) -> &mut [T; ECGFP5_HTC_NUM_COLS_BASE + NUM_CHANNELS] {
        unsafe { transmute(self) }
    }
}
