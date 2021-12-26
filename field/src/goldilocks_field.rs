use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num::{BigUint, Integer};
use plonky2_util::{assume, branch_hint};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::extension_field::quadratic::QuadraticExtension;
use crate::extension_field::quartic::QuarticExtension;
use crate::extension_field::{Extendable, Frobenius};
use crate::field_types::{Field, PrimeField};
use crate::inversion::try_inverse_u64;

const EPSILON: u64 = (1 << 32) - 1;

/// A field selected to have fast reduction.
///
/// Its order is 2^64 - 2^32 + 1.
/// ```ignore
/// P = 2**64 - EPSILON
///   = 2**64 - 2**32 + 1
///   = 2**32 * (2**32 - 1) + 1
/// ```
#[derive(Copy, Clone, Serialize, Deserialize)]
#[repr(transparent)]
pub struct GoldilocksField(pub u64);

impl Default for GoldilocksField {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialEq for GoldilocksField {
    fn eq(&self, other: &Self) -> bool {
        self.to_canonical_u64() == other.to_canonical_u64()
    }
}

impl Eq for GoldilocksField {}

impl Hash for GoldilocksField {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.to_canonical_u64())
    }
}

impl Display for GoldilocksField {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Debug for GoldilocksField {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Field for GoldilocksField {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
    const TWO: Self = Self(2);
    const NEG_ONE: Self = Self(Self::ORDER - 1);

    const TWO_ADICITY: usize = 32;
    const CHARACTERISTIC_TWO_ADICITY: usize = Self::TWO_ADICITY;

    // Sage: `g = GF(p).multiplicative_generator()`
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self(7);

    // Sage:
    // ```
    // g_2 = g^((p - 1) / 2^32)
    // g_2.multiplicative_order().factor()
    // ```
    const POWER_OF_TWO_GENERATOR: Self = Self(1753635133440165772);

    const BITS: usize = 64;

    fn order() -> BigUint {
        Self::ORDER.into()
    }
    fn characteristic() -> BigUint {
        Self::order()
    }

    #[inline(always)]
    fn try_inverse(&self) -> Option<Self> {
        try_inverse_u64(self)
    }

    fn from_biguint(n: BigUint) -> Self {
        Self(n.mod_floor(&Self::order()).to_u64_digits()[0])
    }

    fn to_biguint(&self) -> BigUint {
        self.to_canonical_u64().into()
    }

    #[inline]
    fn from_canonical_u64(n: u64) -> Self {
        debug_assert!(n < Self::ORDER);
        Self(n)
    }

    fn from_noncanonical_u128(n: u128) -> Self {
        reduce128(n)
    }

    fn rand_from_rng<R: Rng>(rng: &mut R) -> Self {
        Self::from_canonical_u64(rng.gen_range(0..Self::ORDER))
    }

    #[inline]
    fn multiply_accumulate(&self, x: Self, y: Self) -> Self {
        // u64 + u64 * u64 cannot overflow.
        reduce128((self.0 as u128) + (x.0 as u128) * (y.0 as u128))
    }
}

impl PrimeField for GoldilocksField {
    const ORDER: u64 = 0xFFFFFFFF00000001;

    #[inline]
    fn to_canonical_u64(&self) -> u64 {
        let mut c = self.0;
        // We only need one condition subtraction, since 2 * ORDER would not fit in a u64.
        if c >= Self::ORDER {
            c -= Self::ORDER;
        }
        c
    }

    fn to_noncanonical_u64(&self) -> u64 {
        self.0
    }

    #[inline]
    fn from_noncanonical_u64(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    unsafe fn add_canonical_u64(&self, rhs: u64) -> Self {
        let (res_wrapped, carry) = self.0.overflowing_add(rhs);
        // Add EPSILON * carry cannot overflow unless rhs is not in canonical form.
        Self(res_wrapped + EPSILON * (carry as u64))
    }

    #[inline]
    unsafe fn sub_canonical_u64(&self, rhs: u64) -> Self {
        let (res_wrapped, borrow) = self.0.overflowing_sub(rhs);
        // Sub EPSILON * carry cannot underflow unless rhs is not in canonical form.
        Self(res_wrapped - EPSILON * (borrow as u64))
    }
}

impl Neg for GoldilocksField {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self(Self::ORDER - self.to_canonical_u64())
        }
    }
}

impl Add for GoldilocksField {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        let (sum, over) = self.0.overflowing_add(rhs.0);
        let (mut sum, over) = sum.overflowing_add((over as u64) * EPSILON);
        if over {
            // NB: self.0 > Self::ORDER && rhs.0 > Self::ORDER is necessary but not sufficient for
            // double-overflow.
            // This assume does two things:
            //  1. If compiler knows that either self.0 or rhs.0 <= ORDER, then it can skip this
            //     check.
            //  2. Hints to the compiler how rare this double-overflow is (thus handled better with
            //     a branch).
            assume(self.0 > Self::ORDER && rhs.0 > Self::ORDER);
            branch_hint();
            sum += EPSILON; // Cannot overflow.
        }
        Self(sum)
    }
}

impl AddAssign for GoldilocksField {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sum for GoldilocksField {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl Sub for GoldilocksField {
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        let (diff, under) = self.0.overflowing_sub(rhs.0);
        let (mut diff, under) = diff.overflowing_sub((under as u64) * EPSILON);
        if under {
            // NB: self.0 < EPSILON - 1 && rhs.0 > Self::ORDER is necessary but not sufficient for
            // double-underflow.
            // This assume does two things:
            //  1. If compiler knows that either self.0 >= EPSILON - 1 or rhs.0 <= ORDER, then it
            //     can skip this check.
            //  2. Hints to the compiler how rare this double-underflow is (thus handled better
            //     with a branch).
            assume(self.0 < EPSILON - 1 && rhs.0 > Self::ORDER);
            branch_hint();
            diff -= EPSILON; // Cannot underflow.
        }
        Self(diff)
    }
}

impl SubAssign for GoldilocksField {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for GoldilocksField {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        reduce128((self.0 as u128) * (rhs.0 as u128))
    }
}

impl MulAssign for GoldilocksField {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Product for GoldilocksField {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl Div for GoldilocksField {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl DivAssign for GoldilocksField {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl Extendable<2> for GoldilocksField {
    type Extension = QuadraticExtension<Self>;

    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^2 - 7).is_irreducible()`.
    const W: Self = Self(7);

    // DTH_ROOT = W^((ORDER - 1)/2)
    const DTH_ROOT: Self = Self(18446744069414584320);

    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 2] =
        [Self(18081566051660590251), Self(16121475356294670766)];

    const EXT_POWER_OF_TWO_GENERATOR: [Self; 2] = [Self(0), Self(15659105665374529263)];
}

impl Extendable<4> for GoldilocksField {
    type Extension = QuarticExtension<Self>;

    const W: Self = Self(7);

    // DTH_ROOT = W^((ORDER - 1)/4)
    const DTH_ROOT: Self = Self(281474976710656);

    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 4] = [
        Self(5024755240244648895),
        Self(13227474371289740625),
        Self(3912887029498544536),
        Self(3900057112666848848),
    ];

    const EXT_POWER_OF_TWO_GENERATOR: [Self; 4] =
        [Self(0), Self(0), Self(0), Self(12587610116473453104)];
}

/// Fast addition modulo ORDER for x86-64.
/// This function is marked unsafe for the following reasons:
///   - It is only correct if x + y < 2**64 + ORDER = 0x1ffffffff00000001.
///   - It is only faster in some circumstances. In particular, on x86 it overwrites both inputs in
///     the registers, so its use is not recommended when either input will be used again.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    use std::arch::asm;
    let res_wrapped: u64;
    let adjustment: u64;
    asm!(
        "add {0}, {1}",
        // Trick. The carry flag is set iff the addition overflowed.
        // sbb x, y does x := x - y - CF. In our case, x and y are both {1:e}, so it simply does
        // {1:e} := 0xffffffff on overflow and {1:e} := 0 otherwise. {1:e} is the low 32 bits of
        // {1}; the high 32-bits are zeroed on write. In the end, we end up with 0xffffffff in {1}
        // on overflow; this happens be EPSILON.
        // Note that the CPU does not realize that the result of sbb x, x does not actually depend
        // on x. We must write the result to a register that we know to be ready. We have a
        // dependency on {1} anyway, so let's use it.
        "sbb {1:e}, {1:e}",
        inlateout(reg) x => res_wrapped,
        inlateout(reg) y => adjustment,
        options(pure, nomem, nostack),
    );
    assume(x != 0 || (res_wrapped == y && adjustment == 0));
    assume(y != 0 || (res_wrapped == x && adjustment == 0));
    // Add EPSILON == subtract ORDER.
    // Cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + adjustment
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let (res_wrapped, carry) = x.overflowing_add(y);
    // Below cannot overflow unless the assumption if x + y < 2**64 + ORDER is incorrect.
    res_wrapped + EPSILON * (carry as u64)
}

/// Reduces to a 64-bit value. The result might not be in canonical form; it could be in between the
/// field order and `2^64`.
#[inline]
fn reduce128(x: u128) -> GoldilocksField {
    let (x_lo, x_hi) = split(x); // This is a no-op
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & EPSILON;

    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        branch_hint(); // A borrow is exceedingly rare. It is faster to branch.
        t0 -= EPSILON; // Cannot underflow.
    }
    let t1 = x_hi_lo * EPSILON;
    let t2 = unsafe { add_no_canonicalize_trashing_input(t0, t1) };
    GoldilocksField(t2)
}

#[inline]
fn split(x: u128) -> (u64, u64) {
    (x as u64, (x >> 64) as u64)
}

impl Frobenius<1> for GoldilocksField {}

#[cfg(test)]
mod tests {
    use crate::{test_field_arithmetic, test_prime_field_arithmetic};

    test_prime_field_arithmetic!(crate::field::goldilocks_field::GoldilocksField);
    test_field_arithmetic!(crate::field::goldilocks_field::GoldilocksField);
}