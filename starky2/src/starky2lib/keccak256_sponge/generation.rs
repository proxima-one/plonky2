use plonky2::field::types::PrimeField64;
use arrayref::array_ref;
use std::borrow::BorrowMut;

use super::layout::{KECCAK_256_NUM_COLS, KECCAK_RATE_U32S, KECCAK_WIDTH_U32S, Keccak256SpongeRow};
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

	/// adds a keccak256 hash to the trace, returning the `hash_idx` (for lookup usage) and the resulting hash
	/// Assumes padding has already been applied to the input.
	pub fn gen_hash_nopad(&mut self, blocks: &[&[u32; KECCAK_RATE_U32S]]) -> (u16, [u32; 8]) {
		self.init_sponge();
		for block in blocks {
			self.gen_absorb_block(block)
		}

		self.gen_squeeze();


		(self.hash_idx, *array_ref![self.state, 0, 8])
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
		let xored = block.zip(*array_ref![self.state, 0, KECCAK_RATE_U32S]).map(|(input_block_word, state_word)| {
			input_block_word ^ state_word
		});
		row.xored_state_rate = xored.map(F::from_canonical_u32);

		keccakf_u32s(&mut self.state);
		self.block_idx += 1;

		self.trace.push(row.into())
	}

	fn gen_squeeze(&mut self) {
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
	}

	fn gen_lut(&mut self) {
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
        let hi = state_u32s[i * 2] as u64;
        let lo = state_u32s[i * 2 + 1] as u64;
        lo | (hi << 32)
    });
    keccakf(&mut state_u64s);
    *state_u32s = std::array::from_fn(|i| {
        let u64_limb = state_u64s[i / 2];
        let is_hi = 1 - (i % 2);
        (u64_limb >> (is_hi * 32)) as u32
    });
}
