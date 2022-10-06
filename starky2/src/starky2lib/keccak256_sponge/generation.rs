use plonky2::field::{types::PrimeField64, polynomial::PolynomialValues};
use arrayref::array_ref;
use std::borrow::BorrowMut;

use crate::util::{trace_rows_to_poly_values, to_u32_array_be, to_u32_array_le};

use super::layout::{KECCAK_256_NUM_COLS, KECCAK_RATE_U32S, KECCAK_WIDTH_U32S, Keccak256SpongeRow, KECCAK_RATE_BYTES};
use tiny_keccak::keccakf;

pub struct Keccak256SpongeGenerator<F: PrimeField64> {
	trace: Vec<[F; KECCAK_256_NUM_COLS]>,
	state: [u32; KECCAK_WIDTH_U32S],
	hash_idx: u16,
	block_idx: u16,
}

impl<F: PrimeField64> Keccak256SpongeGenerator<F> {
	pub fn new() -> Self {
		Self {
			trace: Vec::new(),
			state: [0; KECCAK_WIDTH_U32S],
			hash_idx: 0,
			block_idx: 0,
		}
	}

	/// pad out the trace to a fixed size. Useful for simplifying recursion circuitry.
	pub fn pad_to_num_rows(&mut self, n_log: usize) {
		// TODO: padding rows aren't all zero - figure out what they should be.
		self.trace.resize(1 << n_log, [F::ZERO; KECCAK_256_NUM_COLS]);
	}

	pub fn to_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
		self.gen_lookup_table();
		trace_rows_to_poly_values(self.trace)
	}

	/// adds a keccak256 hash to the trace, returning the `hash_idx` (for lookup usage) and the resulting hash
	/// Assumes padding has already been applied to the input.
	pub fn gen_hash_nopad(&mut self, blocks: &[[u32; KECCAK_RATE_U32S]]) -> (u16, [u32; 8]) {
		self.init_sponge();
		for block in blocks {
			self.gen_absorb_block(block)
		}

		let res = self.gen_squeeze();


		(self.hash_idx, *array_ref![res, 0, 8])
	}

	fn init_sponge(&mut self) {
		self.state = [0; KECCAK_WIDTH_U32S];
		self.hash_idx += 1;
		self.block_idx = 0;
	}

	fn gen_absorb_block(&mut self, block: &[u32; KECCAK_RATE_U32S]) {
		let mut row = Keccak256SpongeRow::new();

		row.mode_bits = [F::ZERO, F::ONE];
		row.input_filter = F::ONE;
		row.output_filter = F::ZERO;
		row.invoke_permutation_filter = F::ONE;

		row.block_idx_bytes[0] = F::from_canonical_u8((self.block_idx & 0xFF) as u8);
		row.block_idx_bytes[1] = F::from_canonical_u8((self.block_idx >> 8) as u8);
		row.hash_idx_bytes[0] = F::from_canonical_u8((self.hash_idx & 0xFF) as u8);
		row.hash_idx_bytes[1] = F::from_canonical_u8((self.hash_idx >> 8) as u8);
		
		for (i, word) in self.state.map(|word| F::from_canonical_u32(word)).into_iter().enumerate() {
			if i < KECCAK_RATE_U32S {
				row.curr_state_rate[i] = word;
			} else {
				row.curr_state_capacity[i - KECCAK_RATE_U32S] = word
			}
		}

		row.input_block = block.map(|word| F::from_canonical_u32(word));
		row.input_block_encoded = row.input_block.map(|word| word + F::from_canonical_u32(1 << 16) * F::from_canonical_u16(self.hash_idx) + F::from_canonical_u64(1 << 48) * F::from_canonical_u16(self.block_idx));
		let xored = block.zip(*array_ref![self.state, 0, KECCAK_RATE_U32S]).map(|(input_block_word, state_word)| {
			input_block_word ^ state_word
		});
		row.xored_state_rate = xored.map(F::from_canonical_u32);

		self.xor_in_input(block);
		keccakf_u32s(&mut self.state);
		self.block_idx += 1;

		self.trace.push(row.into())
	}

	fn xor_in_input(&mut self, input: &[u32; KECCAK_RATE_U32S]) {
		for (word, &input) in self.state.iter_mut().take(KECCAK_RATE_U32S).zip(input) {
			*word ^= input
		}
	}

	fn gen_squeeze(&mut self) -> [u32; KECCAK_RATE_U32S] {
		let mut row = Keccak256SpongeRow::new();

		row.mode_bits = [F::ONE, F::ZERO];
		row.input_filter = F::ZERO;
		row.output_filter = F::ONE;
		row.invoke_permutation_filter = F::ONE;

		row.block_idx_bytes[0] = F::from_canonical_u8((self.block_idx & 0xFF) as u8);
		row.block_idx_bytes[1] = F::from_canonical_u8((self.block_idx >> 8) as u8);
		row.hash_idx_bytes[0] = F::from_canonical_u8((self.hash_idx & 0xFF) as u8);
		row.hash_idx_bytes[1] = F::from_canonical_u8((self.hash_idx >> 8) as u8);

		for (i, word) in self.state.map(|word| F::from_canonical_u32(word)).into_iter().enumerate() {
			if i < KECCAK_RATE_U32S {
				row.curr_state_rate[i] = word;
			} else {
				row.curr_state_capacity[i - KECCAK_RATE_U32S] = word
			}
		}

		row.xored_state_rate = [F::ZERO; KECCAK_RATE_U32S];
	
		self.block_idx += 1;
		self.trace.push(row.into());

		let res = *array_ref![self.state, 0, KECCAK_RATE_U32S];
		keccakf_u32s(&mut self.state);
		res
	}

	pub fn gen_lookup_table(&mut self) {
		for (i, row) in self.trace.iter_mut().enumerate() {
			let row: &mut Keccak256SpongeRow<F> = row.borrow_mut();

			let mut u8_val = i % (1 << 8);
			let u7_val = i % (1 << 7);

			row.u8_lookup = F::from_canonical_u8(u8_val as u8);
			row.u7_lookup = F::from_canonical_u8(u7_val as u8);
	
			for bit in 0..8 {
				row.u8_lookup_bits[bit] = F::from_canonical_u8((u8_val & 1) as u8);
				u8_val >>= 1;
			}
		}
	}

}

/// Like tiny-keccak's `keccakf`, but deals with `u32` limbs instead of `u64` limbs.
pub fn keccakf_u32s(state_u32s: &mut [u32; 50]) {
    let mut state_u64s: [u64; 25] = std::array::from_fn(|i| {
        let lo = state_u32s[i * 2] as u64;
        let hi = state_u32s[i * 2 + 1] as u64;
        lo | (hi << 32)
    });
    keccakf(&mut state_u64s);
    *state_u32s = std::array::from_fn(|i| {
        let u64_limb = state_u64s[i / 2];
        let is_hi = i % 2;
        (u64_limb >> (is_hi * 32)) as u32
    });
}

pub fn pad101(data: &[u8]) -> Vec<u8> {
	let mut data = data.to_vec();
	if data.len() % KECCAK_RATE_BYTES == KECCAK_RATE_BYTES - 1 {
		data.push(0b10000001)
	} else {
		data.push(1);
		let padded_len = ((data.len() + KECCAK_RATE_BYTES - 1) / KECCAK_RATE_BYTES) * KECCAK_RATE_BYTES;
		data.resize(padded_len - 1, 0);
		data.push(0b10000000);
	}

	data	
}

pub fn to_le_blocks(data: &[u8]) -> Vec<[u32; KECCAK_RATE_U32S]> {
	assert!(data.len() % KECCAK_RATE_BYTES == 0);

	data.chunks_exact(KECCAK_RATE_BYTES).map(|chunk| {
		to_u32_array_le(*array_ref![chunk, 0, KECCAK_RATE_BYTES])
	}).collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use plonky2::field::goldilocks_field::GoldilocksField;
	use tiny_keccak::{Hasher, Keccak};


	#[test]
	fn test_gen_hash_simple() {
		type F = GoldilocksField;

		let mut generator = Keccak256SpongeGenerator::<F>::new();


		let data = to_le_blocks(&pad101(b"hello"));
		let (_id, computed_hash_u32) = generator.gen_hash_nopad(data.as_slice());
		let computed_hash: Vec<u8> = computed_hash_u32.into_iter().flat_map(|x| x.to_le_bytes()).collect();

		let mut correct_hash = [0u8; 32];
		let mut hasher = Keccak::v256();
		hasher.update(b"hello");
		hasher.finalize(&mut correct_hash);

		println!("computed hash: {:x?}", computed_hash);
		println!("correct hash: {:x?}", correct_hash);
		assert_eq!(&computed_hash, &correct_hash);
	}
	
}