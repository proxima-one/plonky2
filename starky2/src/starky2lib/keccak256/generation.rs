use plonky2::field::types::PrimeField64;
use arrayref::array_ref;
use crate::util::{to_u32_vec_le, bit_decompose_n_le};

use super::layout::{KECCAK_256_NUM_COLS, KECCAK_RATE_U32S, KECCAK_WIDTH_U32S, Keccak256Layout};
use tiny_keccak::keccakf;

pub struct Keccak256StarkGenerator<F: PrimeField64> {
	trace: Vec<[F; KECCAK_256_NUM_COLS]>,
	state: [u32; KECCAK_WIDTH_U32S],
	hash_idx: usize,
	block_idx: usize,
}

impl<F: PrimeField64> Keccak256StarkGenerator<F> {
	pub fn new() -> Self {
		Self {
			trace: Vec::new(),
			state: [0; KECCAK_WIDTH_U32S],
			hash_idx: 0,
			block_idx: 0,
		}
	}

	pub fn pad_to_num_rows(&mut self, n_log: usize) {
		self.trace.resize(1 << n_log, [F::ZERO; KECCAK_256_NUM_COLS]);
	}

	pub fn gen_hash_le(&mut self, input: &[u8]) -> [u8; 32] {
		let words = to_u32_vec_le(input);
		self.init_hash();
		for block in words.chunks(KECCAK_RATE_U32S) {
			if block.len() != KECCAK_RATE_U32S {
				self.gen_absorb_block_last(block)
			}
			self.gen_absorb_block_full(block.try_into().unwrap())
		}

		self.gen_finalize_hash();

		let mut res = [0; 32];
		for (i, &chunk) in self.state[..8].iter().enumerate() {
			res[i * 4..(i + 1) * 4].copy_from_slice(&chunk.to_le_bytes());
		}

		res
	}

	fn init_hash(&mut self) {
		self.state = [0; KECCAK_WIDTH_U32S];
		self.hash_idx += 1;
		self.block_idx = 0;
	}

	fn gen_absorb_block_full(&mut self, block: [u32; KECCAK_RATE_U32S]) {
		let mut row = Keccak256Layout::new();

		row.mode_bit_0 = F::ONE;
		row.mode_bit_1 = F::ZERO;
		row.input_filter = F::ONE;
		row.output_filter = F::ZERO;
		row.invoke_permutation_filter = F::ONE;
		row.invoke_xor_filter = F::ONE;
		row.block_idx = F::from_canonical_u64(self.block_idx as u64);
		row.hash_idx = F::from_canonical_u64(self.hash_idx as u64);
		row.block_len = F::from_canonical_u64((KECCAK_RATE_U32S * 32) as u64);
		for (i, bit) in bit_decompose_n_le(KECCAK_RATE_U32S * 32, 5).into_iter().map(F::from_canonical_u8).enumerate() {
			row.lower_5_bits_of_len[i] = bit;
		}
		row.len_floor_div_32 = F::from_canonical_u64(KECCAK_RATE_U32S as u64);
		
		row.curr_state = self.state.map(|word| F::from_canonical_u32(word));
		row.input_block = block.map(|word| F::from_canonical_u32(word));
		let curr_rate_state_xord = block.zip(*array_ref![self.state, 0, KECCAK_RATE_U32S]).map(|(input_block_word, state_word)| {
			input_block_word ^ state_word
		});
		row.curr_rate_state_xord = curr_rate_state_xord.map(F::from_canonical_u32);

		keccakf_u32s(&mut self.state);
		self.block_idx += 1;

		self.trace.push(row.into())
	}

	fn gen_absorb_block_last(&mut self, block: &[u32]) {
		debug_assert!(block.len() <= KECCAK_RATE_U32S);
		let mut row = Keccak256Layout::new();

		row.mode_bit_0 = F::ONE;
		row.mode_bit_1 = F::ZERO;
		row.input_filter = F::ONE;
		row.output_filter = F::ZERO;
		row.invoke_permutation_filter = F::ONE;
		row.invoke_xor_filter = F::ONE;
		row.block_idx = F::from_canonical_u64(self.block_idx as u64);
		row.block_len = F::from_canonical_u64((block.len() * 32) as u64);
		for (i, bit) in bit_decompose_n_le(block.len(), 5).into_iter().map(F::from_canonical_u8).enumerate() {
			row.lower_5_bits_of_len[i] = bit;
		}
		row.len_floor_div_32 = F::from_canonical_u64(block.len() as u64);
		
		row.curr_state = self.state.map(|word| F::from_canonical_u32(word));

		for (i, word) in block.iter().map(|&word| F::from_canonical_u32(word)).enumerate() {
			row.input_block[i] = word;
		}

		for (i, word) in block.iter().enumerate() {
			let xord = self.state[i] ^ word;
			row.curr_rate_state_xord[i] = F::from_canonical_u32(xord);
		}

		// TODO padding selectors

		
		keccakf_u32s(&mut self.state);
		self.trace.push(row.into());
	}

	fn gen_finalize_hash(&mut self) {
		let mut row = Keccak256Layout::new();
		row.mode_bit_0 = F::ZERO;
		row.mode_bit_1 = F::ONE;
		row.input_filter = F::ZERO;
		row.output_filter = F::ONE;
		row.invoke_permutation_filter = F::ZERO;
		row.invoke_xor_filter = F::ZERO;
		row.block_idx = F::ZERO; 
		row.block_len = F::ZERO;
		row.lower_5_bits_of_len = [F::ZERO; 5];
		row.len_floor_div_32 = F::ZERO;

		row.curr_state = self.state.map(|word| F::from_canonical_u32(word));
		row.curr_rate_state_xord = [F::ZERO; KECCAK_RATE_U32S];

		self.trace.push(row.into());
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
