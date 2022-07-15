//! Generates random constants using ChaCha20, seeded with zero.
#![allow(clippy::needless_range_loop)]


#[cfg(any(feature = "test_utils", test))]
use plonky2_field::goldilocks_field::GoldilocksField;
#[cfg(any(feature = "test_utils", test))]
use plonky2_field::types::Field64;
#[cfg(any(feature = "test_utils", test))]
use rand::{Rng, SeedableRng};
#[cfg(any(feature = "test_utils", test))]
use rand_chacha::ChaCha8Rng;

#[cfg(any(feature = "test_utils", test))]
const SAMPLE_RANGE_END: u64 = GoldilocksField::ORDER;

#[cfg(any(feature = "test_utils", test))]
const N: usize = 12 * 30; // For Poseidon-12

#[cfg(any(feature = "test_utils", test))]
pub(crate) fn main() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut constants = [0u64; N];
    for i in 0..N {
        constants[i] = rng.gen_range(0..SAMPLE_RANGE_END);
    }

    // Print the constants in the format we prefer in our code.
    for chunk in constants.chunks(4) {
        for (i, c) in chunk.iter().enumerate() {
            print!("{:#018x},", c);
            if i != chunk.len() - 1 {
                print!(" ");
            }
        }
        println!();
    }
}

#[cfg(not(any(feature = "test_utils", test)))]
pub(crate) fn main() {}
