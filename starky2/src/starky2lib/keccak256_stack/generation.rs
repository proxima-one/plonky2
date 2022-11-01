use std::borrow::{Borrow, BorrowMut};

use arrayref::array_ref;
use plonky2::field::{polynomial::PolynomialValues, types::PrimeField64};
use plonky2_util::log2_ceil;
use tiny_keccak::keccakf;

use super::layout::*;
use crate::{
    lookup::permuted_cols,
    starky2lib::keccak256_sponge::generation::keccakf_u32s,
    starky2lib::{stack::generation::StackOp, util::u32_byte_recomp_field_le},
    util::{to_u32_array_le, trace_rows_to_poly_values},
};

// minimum number of rows for this table. This is necessary because it uses a size 136 lookup table, and the next power of two is 256
const LOG_MIN_ROWS: usize = 8;

pub struct Keccak256StackGenerator<F: PrimeField64> {
    trace: Vec<Keccak256StackRow<F>>,
    state: [u32; KECCAK_WIDTH_U32S],
    opcode: Keccak256StackOpcode,
    stack: Keccak256InputStack<F>,
    output_memory: Vec<F>,
    op_id: usize,
    is_last_block: bool,
    len: usize,
}

enum Keccak256StackOpcode {
    ABSORB,
    SQUEEZE,
    HALT,
}

pub struct Keccak256InputStack<F: PrimeField64> {
    stack: Vec<F>,
    sp: usize,
}

impl<F: PrimeField64> Keccak256InputStack<F> {
    pub(crate) fn pop(&mut self) -> F {
        let val = self.stack.pop().unwrap();
        val
    }

    pub fn from_items(vals: &[Vec<u8>]) -> Self {
        let mut stack = vec![F::ZERO];
        for (i, val) in vals.iter().enumerate() {
            for byte in val.iter().rev() {
                stack.push(F::from_canonical_u64(*byte as u64));
            }
            stack.push(F::from_canonical_u64(val.len() as u64));
            stack.push(F::from_canonical_u64(i as u64));
        }
        stack[0] = F::from_canonical_usize(stack.len() - 1);

        Self { stack, sp: 0 }
    }

    pub fn load_sp(&mut self) {
        self.sp = self.stack[0].to_canonical_u64() as usize;
    }

    fn sp(&self) -> usize {
        self.sp
    }
}

impl<F: PrimeField64> Keccak256StackGenerator<F> {
    pub fn new(stack: Keccak256InputStack<F>) -> Self {
        Self {
            trace: vec![],
            state: [0; KECCAK_WIDTH_U32S],
            opcode: Keccak256StackOpcode::ABSORB,
            output_memory: vec![],
            op_id: 0,
            is_last_block: false,
            len: 0,
            stack,
        }
    }

    fn gen_new_item(&mut self, row: &mut Keccak256StackRow<F>) {
        row.op_id_stack_filter = F::ONE;
        row.op_id_addr = F::from_canonical_u64(self.stack.sp() as u64);
        let op_id = self.stack.pop();
        row.op_id = op_id;

        row.len_stack_filter = F::ONE;
        row.len_addr = F::from_canonical_u64(self.stack.sp() as u64);
        let len = self.stack.pop();
        row.len = len;

        self.state = [0; KECCAK_WIDTH_U32S];

        self.op_id = op_id.to_canonical_u64() as usize;
        self.len = len.to_canonical_u64() as usize;
    }

    fn gen_row(&self, row: &mut Keccak256StackRow<F>) {
        row.opcode = match self.opcode {
            Keccak256StackOpcode::HALT => [F::ZERO, F::ZERO],
            Keccak256StackOpcode::ABSORB => [F::ONE, F::ZERO],
            Keccak256StackOpcode::SQUEEZE => [F::ZERO, F::ONE],
        };

        row.invoke_permutation_filter = match self.opcode {
            Keccak256StackOpcode::ABSORB | Keccak256StackOpcode::SQUEEZE => F::ONE,
            _ => F::ONE,
        };

        for i in 0..KECCAK_RATE_U32S {
            row.curr_state_rate[i] = F::from_canonical_u32(self.state[i]);
        }
        for i in 0..KECCAK_CAPACITY_U32S {
            row.curr_state_capacity[i] = F::from_canonical_u32(self.state[i + KECCAK_RATE_U32S]);
        }

        row.op_id = F::from_canonical_u64(self.op_id as u64);
        self.gen_decomps(row);
        row.len = F::from_canonical_u64(self.len as u64);
        row.is_last_block = F::from_bool(self.is_last_block);

        row.lut_136 = F::from_canonical_usize(self.trace.len() % 136);
        row.lut_136_is_135 = F::from_bool(self.trace.len() % 136 == 135);
        row.lut_136_minus_135_inv = if self.trace.len() % 136 == 135 {
            F::ZERO
        } else {
            (row.lut_136 - F::from_canonical_u64(135)).inverse()
        };
    }

    fn xor_in_input(&mut self, row: &mut Keccak256StackRow<F>) {
        for (i, (word, input)) in self
            .state
            .iter_mut()
            .take(KECCAK_RATE_U32S)
            .zip(row.input_block)
            .enumerate()
        {
            let input = input.to_canonical_u64() as u32;
            *word ^= input;
            row.xored_state_rate[i] = F::from_canonical_u32(*word);
        }
    }

    fn load_first_sp(&mut self, row: &mut Keccak256StackRow<F>) {
        self.stack.load_sp();
        row.sp_init = F::from_canonical_u64(self.stack.sp() as u64);
        row.sp_init_stack_filter = F::ONE;
    }

    fn gen_invoke_permutation(&mut self, row: &mut Keccak256StackRow<F>) {
        keccakf_u32s(&mut self.state);
        row.new_state = self.state.map(F::from_canonical_u32);
    }

    fn gen_decomps(&self, row: &mut Keccak256StackRow<F>) {
        for i in 0..KECCAK_RATE_U32S {
            row.input_block[i] =
                u32_byte_recomp_field_le(*array_ref![row.input_block_bytes, 4 * i, 4]);
        }
    }

    fn gen_pop_n_bytes(&mut self, row: &mut Keccak256StackRow<F>, n: usize) {
        for i in 0..n {
            row.stack_filters[i] = F::ONE;
            row.input_block_addrs[i] = F::from_canonical_usize(self.stack.sp());
            row.input_block_bytes[i] = self.stack.pop();
        }
    }

    fn gen_padding_bytes(&self, row: &mut Keccak256StackRow<F>, start_idx: usize) {
        if start_idx == KECCAK_RATE_BYTES - 1 {
            row.input_block_bytes[start_idx] = F::from_canonical_u8(0b1000_0001);
        } else {
            row.input_block_bytes[start_idx] = F::from_canonical_u8(0b0000_0001);
            row.input_block_bytes[KECCAK_RATE_BYTES - 1] = F::from_canonical_u8(0b1000_0000);
            for i in start_idx + 1..KECCAK_RATE_BYTES - 1 {
                row.input_block_bytes[i] = F::ZERO;
            }
        }
    }

    fn gen_pop_block(&mut self, row: &mut Keccak256StackRow<F>) {
        match self.opcode {
            Keccak256StackOpcode::ABSORB => {
                if self.len >= KECCAK_RATE_BYTES {
                    self.gen_pop_n_bytes(row, KECCAK_RATE_BYTES);
                    self.len -= KECCAK_RATE_BYTES;
                } else {
                    self.is_last_block = true;
                    self.gen_pop_n_bytes(row, self.len);
                    self.gen_padding_bytes(row, self.len);
                    row.rc_136 = F::from_canonical_usize(self.len);
                }
            }
            _ => {}
        }
    }

    fn gen_output(&mut self, row: &mut Keccak256StackRow<F>) -> [u8; 32] {
        let mut res = [0u8; 32];
        let hash_u32s = *array_ref![self.state, 0, 8];
        for (o, chunk) in res
            .chunks_exact_mut(4)
            .zip(hash_u32s.into_iter().map(|x| x.to_le_bytes()))
        {
            o.copy_from_slice(&chunk);
        }

        if self.op_id * 32 >= self.output_memory.len() {
            self.output_memory.resize((self.op_id + 1) * 32, F::ZERO);
        }

        for i in 0..32 {
            self.output_memory[self.op_id * 32 + i] = F::from_canonical_u8(res[i]);
        }

        for i in 0..32 {
            row.output_mem_addrs[i] = F::from_canonical_usize(self.op_id + i);
            row.output_mem_values[i] = F::from_canonical_u8(res[i]);
        }
        row.output_mem_filter = F::ONE;

        res
    }

    fn gen_luts(trace_values: &mut [PolynomialValues<F>]) {
        for ((input, input_permuted), (table, table_permuted)) in lookup_pairs() {
            let (input_values_permuted, table_values_permuted) =
                permuted_cols(&trace_values[input].values, &trace_values[table].values);
            trace_values[input_permuted] = PolynomialValues::new(input_values_permuted);
            trace_values[table_permuted] = PolynomialValues::new(table_values_permuted);
        }
    }

    fn gen_state_machine(&mut self) {
        // in the STARK, this is checked by checking if the previous row was ABSORB
        let mut is_new_item = true;
        loop {
            match self.opcode {
                Keccak256StackOpcode::ABSORB => {
                    let mut row = Keccak256StackRow::new();
                    if self.trace.len() == 0 {
                        self.load_first_sp(&mut row);
                    }

                    if is_new_item {
                        self.gen_new_item(&mut row);
                        is_new_item = false;
                    }

                    self.gen_pop_block(&mut row);
                    self.gen_row(&mut row);
                    self.xor_in_input(&mut row);
                    self.gen_invoke_permutation(&mut row);
                    self.trace.push(row);

                    if self.is_last_block {
                        self.opcode = Keccak256StackOpcode::SQUEEZE;
                    } else {
                        self.opcode = Keccak256StackOpcode::ABSORB;
                    }
                }
                Keccak256StackOpcode::SQUEEZE => {
                    let mut row = Keccak256StackRow::new();
                    self.gen_row(&mut row);
                    row.xored_state_rate = row.curr_state_rate;
                    self.gen_output(&mut row);
                    self.gen_invoke_permutation(&mut row);
                    self.trace.push(row);

                    if self.op_id == 0 {
                        self.opcode = Keccak256StackOpcode::HALT;
                    } else {
                        self.opcode = Keccak256StackOpcode::ABSORB;
                        is_new_item = true;
                    }
                }
                Keccak256StackOpcode::HALT => {
                    let mut row = Keccak256StackRow::new();
                    self.gen_row(&mut row);
                    self.trace.push(row);
                    break;
                }
            }
        }
    }

    pub fn pad_to_num_rows(&mut self, n_log: usize) {
        let n_log = n_log.max(LOG_MIN_ROWS);
        let target_len = 1 << n_log;
        let mut padding_row = Keccak256StackRow::new();
        self.gen_row(&mut padding_row);
        if self.trace.len() < target_len {
            self.trace.resize(target_len, padding_row);
        }
    }

    pub fn generate(&mut self) {
        self.gen_state_machine();
        self.pad_to_num_rows(LOG_MIN_ROWS);
    }

    pub fn into_polynomial_values(self) -> Vec<PolynomialValues<F>> {
        let rows: Vec<[F; KECCAK_256_STACK_NUM_COLS]> =
            self.trace.into_iter().map(|row| row.into()).collect();
        let mut values = trace_rows_to_poly_values(rows);
        Self::gen_luts(&mut values);
        values
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use tiny_keccak::{Hasher, Keccak};

    use super::*;

    #[test]
    fn test_gen_hash_single_block() {
        type F = GoldilocksField;

        let items = vec![b"hello".to_vec()];
        let stack = Keccak256InputStack::from_items(&items);
        let mut generator = Keccak256StackGenerator::<F>::new(stack);
        generator.generate();

        let output_mem = generator.output_memory;
        let computed_hash = output_mem[0..32]
            .into_iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect::<Vec<u8>>();

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

        let items = vec![b"Timbs for my hooligans in Brooklyn (that's right)
            Dead right, if the head right, Biggie there e'ry night
            Poppa been smooth since days of Underoos
            Never lose, never choose to, bruise crews who
            Do somethin' to us (come on), talk go through us (through us)"
            .to_vec()];
        let stack = Keccak256InputStack::from_items(&items);
        let mut generator = Keccak256StackGenerator::<F>::new(stack);
        generator.generate();

        let output_mem = generator.output_memory;
        let computed_hash = output_mem[0..32]
            .into_iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect::<Vec<u8>>();

        let mut correct_hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(&items[0]);
        hasher.finalize(&mut correct_hash);

        println!("computed hash: {:x?}", computed_hash);
        println!("correct hash: {:x?}", correct_hash);
        assert_eq!(&computed_hash, &correct_hash);
    }

    #[test]
    fn test_gen_multiple_hashes() {
        type F = GoldilocksField;

        let items = vec![
            b"I can fill ya wit' real millionaire shit (I can fill ya)".to_vec(),
            b"Escargot, my car go one-sixty, swiftly (come on)".to_vec(),
            b"Wreck it, buy a new one".to_vec(),
            b"Your crew run-run-run, your crew run-run".to_vec(),
        ];
        let stack = Keccak256InputStack::from_items(&items);
        let mut generator = Keccak256StackGenerator::<F>::new(stack);
        generator.generate();

        let output_mem = generator.output_memory;
        for i in 0..items.len() {
            let computed_hash = output_mem[i * 32..(i + 1) * 32]
                .into_iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect::<Vec<u8>>();

            let mut correct_hash = [0u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(&items[i]);
            hasher.finalize(&mut correct_hash);

            println!("computed hash: {:x?}", computed_hash);
            println!("correct hash: {:x?}", correct_hash);
            assert_eq!(&computed_hash, &correct_hash);
        }
    }
}
