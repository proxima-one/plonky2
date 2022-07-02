pub mod poseidon;
pub mod poseidon_goldilocks;

pub use plonky2_field::goldilocks_field::GoldilocksField;
pub use poseidon::{Poseidon, SPONGE_WIDTH};

pub fn poseidon_goldilocks(
    input: [GoldilocksField; SPONGE_WIDTH],
) -> [GoldilocksField; SPONGE_WIDTH] {
    GoldilocksField::poseidon(input)
}
