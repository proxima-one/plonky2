use plonky2::field::{
    polynomial::PolynomialValues,
    types::{Field, PrimeField64},
};
use plonky2_util::log2_ceil;

use super::layout::XorLayout;
use crate::util::{is_power_of_two, trace_rows_to_poly_values};

pub struct XorGenerator<F: PrimeField64, const N: usize, const NUM_CHANNELS: usize>
where
    [(); 3 + 2 * N + NUM_CHANNELS]:,
{
    trace: Vec<[F; 3 + 2 * N + NUM_CHANNELS]>,
}

impl<F: PrimeField64, const N: usize, const NUM_CHANNELS: usize> XorGenerator<F, N, NUM_CHANNELS>
where
    [(); 3 + 2 * N + NUM_CHANNELS]:,
{
    pub fn new() -> XorGenerator<F, N, NUM_CHANNELS> {
        Self { trace: Vec::new() }
    }

    pub const fn a_col() -> usize {
        XorLayout::<F, N, NUM_CHANNELS>::a_col()
    }

    pub const fn b_col() -> usize {
        XorLayout::<F, N, NUM_CHANNELS>::b_col()
    }

    pub const fn output_col() -> usize {
        XorLayout::<F, N, NUM_CHANNELS>::output_col()
    }

    pub fn gen_op(&mut self, mut a: u64, mut b: u64, channel: usize) {
        debug_assert!(log2_ceil(a as usize) <= 1 << N, "a too large");
        debug_assert!(log2_ceil(b as usize) <= 1 << N, "b too large");

        let mut layout = XorLayout::<F, N, NUM_CHANNELS>::from([F::ZERO; 3 + 2 * N + NUM_CHANNELS]);

        layout.a = F::from_canonical_u64(a);
        layout.b = F::from_canonical_u64(b);
        layout.output = F::from_canonical_u64(a ^ b);
        
        if NUM_CHANNELS > 0 {
            assert!(channel < NUM_CHANNELS);
            layout.channel_filters[channel] = F::ONE;
        }

        for i in 0..N {
            layout.a_bits[i] = F::from_canonical_u64(a & 1);
            layout.b_bits[i] = F::from_canonical_u64(b & 1);
            a >>= 1;
            b >>= 1;
        }

        self.trace.push(layout.into());
    }

    pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
        if !is_power_of_two(self.trace.len() as u64) {
            let next_power_of_two = self.trace.len().next_power_of_two();
            self.trace.resize(next_power_of_two, [F::ZERO; 3 + 2 * N + NUM_CHANNELS]);
        }
        trace_rows_to_poly_values(self.trace)
    }
}
