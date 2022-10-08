use std::borrow::{Borrow, BorrowMut};

use arrayref::array_ref;
use plonky2::field::{polynomial::PolynomialValues, types::PrimeField64};
use plonky2_util::log2_ceil;
use tiny_keccak::keccakf;

use super::layout::*;
use crate::{
    lookup::permuted_cols,
    util::{to_u32_array_le, trace_rows_to_poly_values},
};

// minimum number of rows for this table. This is necessary because it uses an 8-bit lookup table
const LOG_MIN_ROWS: usize = 8;

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

    pub fn pad_to_num_rows(&mut self, n_log: usize) {
        // TODO: padding rows aren't all zero - figure out what they should be.
        let n_log = n_log.max(LOG_MIN_ROWS);
        let target_len = 1 << n_log;
        if target_len > self.trace.len() {
            self.eval_padding(target_len);
        }
    }

    fn eval_padding(&mut self, target_len: usize) {
        while self.trace.len() < target_len {
            let prev_row: &Keccak256SpongeRow<F> = self.trace.last().unwrap().borrow();
            let mut curr_row = Keccak256SpongeRow::new();

            curr_row.hash_idx_bytes = prev_row.hash_idx_bytes;
            curr_row.input_block = [F::ZERO; KECCAK_RATE_U32S];
            curr_row.input_block_encoded = curr_row.input_block.map(|word| {
                word + F::from_canonical_u64(1 << 32) * F::from_canonical_u16(self.hash_idx)
            });
            curr_row.curr_state_rate = *array_ref![prev_row.new_state, 0, KECCAK_RATE_U32S];
            curr_row.curr_state_capacity =
                *array_ref![prev_row.new_state, KECCAK_RATE_U32S, KECCAK_CAPACITY_U32S];
            curr_row.xored_state_rate = curr_row.curr_state_rate;
            self.trace.push(curr_row.into());
        }
    }

    pub fn into_polynomial_values(mut self) -> Vec<PolynomialValues<F>> {
        println!("pre-pad length: {}", self.trace.len());
        let target_len_bits = log2_ceil(self.trace.len());
        self.pad_to_num_rows(target_len_bits);
        println!("post-pad length: {}", self.trace.len());

        self.gen_lookup_table();

        let mut cols = trace_rows_to_poly_values(self.trace);
        Self::set_permuted_cols(&mut cols);
        cols
    }

    fn set_permuted_cols(cols: &mut Vec<PolynomialValues<F>>) {
        let pairs = [
            (block_idx_bytes_start_col(), u8_lut_col()),
            (block_idx_bytes_start_col() + 1, u7_lut_col()),
            (hash_idx_bytes_start_col(), u8_lut_col()),
            (hash_idx_bytes_start_col() + 1, u8_lut_col()),
        ];

        let permuted_pairs = [
            (block_idx_bytes_permuted_start_col(), u8_lut_permuted_col()),
            (
                block_idx_bytes_permuted_start_col() + 1,
                u7_lut_permuted_col(),
            ),
            (hash_idx_bytes_permuted_start_col(), u8_lut_permuted_col()),
            (
                hash_idx_bytes_permuted_start_col() + 1,
                u8_lut_permuted_col(),
            ),
        ];

        for ((input_col, table_col), (permuted_input_col, permuted_table_col)) in
            pairs.zip(permuted_pairs)
        {
            let (permuted_input, permuted_table) =
                permuted_cols::<F>(&cols[input_col].values, &cols[table_col].values);
            cols[permuted_input_col].values = permuted_input;
            cols[permuted_table_col].values = permuted_table;
        }
    }

    fn gen_hash_nopad(
        &mut self,
        blocks: &[[u32; KECCAK_RATE_U32S]],
        trace: bool,
    ) -> (
        u16,
        [u32; 8],
        Option<Vec<[u32; KECCAK_WIDTH_U32S]>>,
        Option<Vec<[[u32; KECCAK_RATE_U32S]; 2]>>,
    ) {
        self.init_sponge();
        let mut permutation_trace = if trace { Some(Vec::new()) } else { None };
        let mut xor_trace = if trace { Some(Vec::new()) } else { None };
        for block in blocks {
            if let Some(ref mut trace) = xor_trace {
                trace.push([*block, *array_ref![self.state, 0, KECCAK_RATE_U32S]]);
            }
            let old_state = self.state;

            let xored_rate = self.gen_absorb_block(block);
            if let Some(ref mut trace) = permutation_trace {
                let mut permutation_input = old_state;
                permutation_input[..KECCAK_RATE_U32S].copy_from_slice(&xored_rate);
                trace.push(permutation_input);
            }
        }

        if let Some(ref mut trace) = permutation_trace {
            trace.push(self.state);
        }

        let res = self.gen_squeeze();

        (
            self.hash_idx,
            *array_ref![res, 0, 8],
            permutation_trace,
            xor_trace,
        )
    }

    /// adds a keccak256 hash to the trace, returning the `hash_idx` (for lookup usage) and the resulting hash
    /// applies padding and breaks down into blockso of `u32`s
    pub fn gen_hash(&mut self, data: &[u8]) -> (u16, [u8; 32]) {
        let data = to_le_blocks(&pad101(data));
        let (id, hash_u32s, _, _) = self.gen_hash_nopad(&data, false);
        let mut res = [0u8; 32];

        for (o, chunk) in res
            .chunks_exact_mut(4)
            .zip(hash_u32s.into_iter().map(|x| x.to_le_bytes()))
        {
            o.copy_from_slice(&chunk)
        }

        (id, res)
    }
    
    /// also returns a trace of the permutation inputs
    /// and xor inputs in the order in which they are "applied"
    pub fn gen_hash_with_trace(
        &mut self,
        data: &[u8],
    ) -> (
        u16,
        [u8; 32],
        Vec<[u32; KECCAK_WIDTH_U32S]>,
        Vec<[[u32; KECCAK_RATE_U32S]; 2]>,
    ) {
        let data = to_le_blocks(&pad101(data));
        let (id, hash_u32s, state_trace, xor_trace) = self.gen_hash_nopad(&data, true);
        let mut res = [0u8; 32];

        for (o, chunk) in res
            .chunks_exact_mut(4)
            .zip(hash_u32s.into_iter().map(|x| x.to_le_bytes()))
        {
            o.copy_from_slice(&chunk)
        }

        (id, res, state_trace.unwrap(), xor_trace.unwrap())
    }

    fn init_sponge(&mut self) {
        self.state = [0; KECCAK_WIDTH_U32S];
        self.hash_idx += 1;
        self.block_idx = 0;
    }

    fn gen_absorb_block(&mut self, block: &[u32; KECCAK_RATE_U32S]) -> [u32; KECCAK_RATE_U32S] {
        let mut row = Keccak256SpongeRow::new();

        row.mode_bits = [F::ONE, F::ZERO];
        row.input_filter = F::ONE;
        row.output_filter = F::ZERO;
        row.invoke_permutation_filter = F::ONE;

        row.block_idx_bytes[0] = F::from_canonical_u8((self.block_idx & 0xFF) as u8);
        row.block_idx_bytes[1] = F::from_canonical_u8((self.block_idx >> 8) as u8);
        row.hash_idx_bytes[0] = F::from_canonical_u8((self.hash_idx & 0xFF) as u8);
        row.hash_idx_bytes[1] = F::from_canonical_u8((self.hash_idx >> 8) as u8);

        for i in 0..KECCAK_RATE_U32S {
            row.curr_state_rate[i] = F::from_canonical_u32(self.state[i]);
        }
        for i in 0..KECCAK_CAPACITY_U32S {
            row.curr_state_capacity[i] = F::from_canonical_u32(self.state[i + KECCAK_RATE_U32S]);
        }

        row.input_block = block.map(F::from_canonical_u32);
        row.input_block_encoded = row.input_block.map(|word| {
            word + F::from_canonical_u64(1 << 32) * F::from_canonical_u16(self.hash_idx)
                + F::from_canonical_u64(1 << 48) * F::from_canonical_u16(self.block_idx)
        });

        self.xor_in_input(block);
        let xored = *array_ref![self.state, 0, KECCAK_RATE_U32S];
        row.xored_state_rate = xored.map(F::from_canonical_u32);

        keccakf_u32s(&mut self.state);
        self.block_idx += 1;

        row.new_state = self.state.map(F::from_canonical_u32);
        self.trace.push(row.into());
        xored
    }

    fn xor_in_input(&mut self, input: &[u32; KECCAK_RATE_U32S]) {
        for (word, &input) in self.state.iter_mut().take(KECCAK_RATE_U32S).zip(input) {
            *word ^= input
        }
    }

    fn gen_squeeze(&mut self) -> [u32; KECCAK_RATE_U32S] {
        let mut row = Keccak256SpongeRow::new();

        row.input_block = [F::ZERO; KECCAK_RATE_U32S];
        row.input_block_encoded = row.input_block.map(|word| {
            word + F::from_canonical_u64(1 << 32) * F::from_canonical_u16(self.hash_idx)
                + F::from_canonical_u64(1 << 48) * F::from_canonical_u16(self.block_idx)
        });

        row.mode_bits = [F::ZERO, F::ONE];
        row.input_filter = F::ZERO;
        row.output_filter = F::ONE;
        row.invoke_permutation_filter = F::ONE;

        row.block_idx_bytes[0] = F::from_canonical_u8((self.block_idx & 0xFF) as u8);
        row.block_idx_bytes[1] = F::from_canonical_u8((self.block_idx >> 8) as u8);
        row.hash_idx_bytes[0] = F::from_canonical_u8((self.hash_idx & 0xFF) as u8);
        row.hash_idx_bytes[1] = F::from_canonical_u8((self.hash_idx >> 8) as u8);

        for i in 0..KECCAK_RATE_U32S {
            row.curr_state_rate[i] = F::from_canonical_u32(self.state[i]);
        }
        for i in 0..KECCAK_CAPACITY_U32S {
            row.curr_state_capacity[i] = F::from_canonical_u32(self.state[i + KECCAK_RATE_U32S]);
        }

        row.xored_state_rate = row.curr_state_rate;

        let res = *array_ref![self.state, 0, KECCAK_RATE_U32S];

        keccakf_u32s(&mut self.state);
        row.new_state = self.state.map(F::from_canonical_u32);

        self.block_idx += 1;
        self.trace.push(row.into());

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
        let padded_len =
            ((data.len() + KECCAK_RATE_BYTES - 1) / KECCAK_RATE_BYTES) * KECCAK_RATE_BYTES;
        data.resize(padded_len - 1, 0);
        data.push(0b10000000);
    }

    data
}

pub fn to_le_blocks(data: &[u8]) -> Vec<[u32; KECCAK_RATE_U32S]> {
    assert!(data.len() % KECCAK_RATE_BYTES == 0);

    data.chunks_exact(KECCAK_RATE_BYTES)
        .map(|chunk| to_u32_array_le(*array_ref![chunk, 0, KECCAK_RATE_BYTES]))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use plonky2::field::goldilocks_field::GoldilocksField;
    use tiny_keccak::{Hasher, Keccak};

    use super::*;

    #[test]
    fn test_gen_hash_single_block() {
        type F = GoldilocksField;

        let mut generator = Keccak256SpongeGenerator::<F>::new();

        let (_id, computed_hash) = generator.gen_hash(b"hello");

        let mut correct_hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(b"hello");
        hasher.finalize(&mut correct_hash);

        println!("computed hash: {:x?}", computed_hash);
        println!("correct hash: {:x?}", correct_hash);
        assert_eq!(&computed_hash, &correct_hash);
    }

    #[test]
    fn test_gen_hash_multi_block() {
        type F = GoldilocksField;

        let mut generator = Keccak256SpongeGenerator::<F>::new();
        let data = b"Timbs for my hooligans in Brooklyn (that's right)
            Dead right, if the head right, Biggie there e'ry night
            Poppa been smooth since days of Underoos
            Never lose, never choose to, bruise crews who
            Do somethin' to us (come on), talk go through us (through us)";

        let (_id, computed_hash) = generator.gen_hash(data);

        let mut correct_hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(data);
        hasher.finalize(&mut correct_hash);

        println!("computed hash: {:x?}", computed_hash);
        println!("correct hash: {:x?}", correct_hash);
        assert_eq!(&computed_hash, &correct_hash);
    }

    #[test]
    fn test_gen_lookups() {
        type F = GoldilocksField;

        let mut generator = Keccak256SpongeGenerator::<F>::new();

        let _ = generator
            .gen_hash(b"we don't play / we gon rock it till the wheels fall off / hold up hey");

        let cols = generator.into_polynomial_values();

        let mut u8_table = HashSet::<F>::new();
        let mut u7_table = HashSet::<F>::new();
        for row in 0..cols[0].len() {
            let u8_val = cols[u8_lut_permuted_col()].values[row];
            u8_table.insert(u8_val);

            let u7_val = cols[u7_lut_permuted_col()].values[row];
            u7_table.insert(u7_val);
        }

        for row in 0..cols[0].len() {
            let val = cols[block_idx_bytes_permuted_start_col()].values[row];
            assert!(u8_table.contains(&val));

            let val = cols[block_idx_bytes_permuted_start_col() + 1].values[row];
            assert!(u7_table.contains(&val));

            let val = cols[hash_idx_bytes_permuted_start_col()].values[row];
            assert!(u8_table.contains(&val));

            let val = cols[hash_idx_bytes_permuted_start_col() + 1].values[row];
            assert!(u8_table.contains(&val));
        }
    }
}
