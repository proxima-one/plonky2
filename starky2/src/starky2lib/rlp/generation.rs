use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::PrimeField64;
use plonky2_util::log2_ceil;
use rlp::{Encodable, RlpStream};

use super::layout::*;
use crate::{
    lookup::permuted_cols, starky2lib::stack::generation::StackOp, util::trace_rows_to_poly_values,
};

pub struct RlpStarkGenerator<F: PrimeField64> {
    pub stark_trace: Vec<RlpRow<F>>,

    pub output_stack: Vec<F>,

    pub call_stack: Vec<F>,
    pub call_stack_trace: Vec<StackOp<F>>,

    pub input_memory: Vec<F>,

    op_id: u64,
    pc: usize,
    count: usize,
    content_len: usize,
    list_count: usize,
    depth: usize,
    next: usize,
    is_last: bool,
    opcode: RlpOpcode,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RlpOpcode {
    NewEntry,
    List,
    Recurse,
    Return,
    StrPush,
    StrPrefix,
    ListPrefix,
    EndEntry,
    Halt,
}

impl<F: PrimeField64> Default for RlpStarkGenerator<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField64> RlpStarkGenerator<F> {
    pub fn new() -> Self {
        Self {
            stark_trace: Vec::new(),
            output_stack: Vec::new(),
            call_stack: Vec::new(),
            call_stack_trace: Vec::new(),
            input_memory: Vec::new(),
            pc: 0,
            op_id: 0,
            count: 0,
            content_len: 0,
            list_count: 0,
            next: 0,
            depth: 0,
            is_last: false,
            opcode: RlpOpcode::NewEntry,
        }
    }

    pub fn gen_input_memory(&mut self, items: &[RlpItem]) {
        let vals = RlpItem::items_to_memory_values::<F>(items);
        self.input_memory = vals;
    }

    // returns an trace of accesses to be used to generate an ro-memory STARK
    // for the input memory
    // this should be called after the trace has been generated but before it is converted
    // to polynomial values
    pub fn input_memory_trace(&self) -> Vec<(F, F)> {
        self.input_memory
            .iter()
            .enumerate()
            .map(|(i, v)| (F::from_canonical_u64(i as u64), *v))
            .collect()
    }

    // returns a trace of stack operations for the RLP's call stack.
    // This is used to generate a stack STARK for it
    pub fn call_stack_trace(&self) -> Vec<StackOp<F>> {
        self.call_stack_trace.clone()
    }

    pub fn output_stack(&self) -> &[F] {
        &self.output_stack
    }

    pub fn generate(&mut self, items: &[RlpItem]) {
        self.gen_input_memory(items);
        self.gen_trace(None);
    }

    pub fn generate_with_target_len(&mut self, items: &[RlpItem], log2_target_len: usize) {
        self.gen_input_memory(items);
        self.gen_trace(Some(log2_target_len));
    }

    fn gen_row(&self) -> RlpRow<F> {
        let mut row = RlpRow::new();

        // primary
        row.op_id = F::from_canonical_u64(self.op_id);
        row.pc = F::from_canonical_u64(self.pc as u64);
        row.count = F::from_canonical_u64(self.count as u64);
        row.content_len = F::from_canonical_u64(self.content_len as u64);
        row.list_count = F::from_canonical_u64(self.list_count as u64);
        row.next = F::from_canonical_u64(self.next as u64);
        row.depth = F::from_canonical_u64(self.depth as u64);
        row.is_last = F::from_canonical_u64(self.is_last as u64);

        row.opcode = match self.opcode {
            RlpOpcode::NewEntry => [F::ZERO; 8],
            RlpOpcode::List => [
                F::ONE,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::Recurse => [
                F::ZERO,
                F::ONE,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::Return => [
                F::ZERO,
                F::ZERO,
                F::ONE,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::StrPush => [
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ONE,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::StrPrefix => [
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ONE,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::ListPrefix => [
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ONE,
                F::ZERO,
                F::ZERO,
            ],
            RlpOpcode::EndEntry => [
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ONE,
                F::ZERO,
            ],
            RlpOpcode::Halt => [
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ONE,
            ],
        };

        // advice
        row.depth_is_zero = F::from_bool(self.depth == 0);
        row.depth_inv = if self.depth == 0 {
            F::ZERO
        } else {
            row.depth.inverse()
        };

        row.content_len_is_zero = F::from_bool(self.content_len == 0);
        row.content_len_inv = if self.content_len == 0 {
            F::ZERO
        } else {
            row.content_len.inverse()
        };

        row.list_count_is_zero = F::from_bool(self.list_count == 0);
        row.list_count_inv = if self.list_count == 0 {
            F::ZERO
        } else {
            row.list_count.inverse()
        };

        row.content_len_minus_count_is_zero = F::from_bool(self.content_len == self.count);
        row.content_len_minus_count_inv = if self.content_len == self.count {
            F::ZERO
        } else {
            (row.content_len - row.count).inverse()
        };

        row.content_len_minus_list_count_is_zero =
            F::from_bool(self.content_len == self.list_count);
        row.content_len_minus_list_count_inv = if self.content_len == self.list_count {
            F::ZERO
        } else {
            (row.content_len - row.list_count).inverse()
        };

        // prefix flags
        let mut own_encoding_case = false;
        row.prefix_case_flags = match (self.opcode, self.count) {
            (RlpOpcode::StrPrefix, 1) => {
                let b = self.output_stack.last().unwrap().to_canonical_u64();
                assert!(b < 256);
                if b < 127 {
                    own_encoding_case = true;
                    [F::ZERO; 4]
                } else {
                    [F::ONE, F::ZERO, F::ZERO, F::ZERO]
                }
            }
            (RlpOpcode::StrPrefix, 0..=55) => [F::ONE, F::ZERO, F::ZERO, F::ZERO],
            (RlpOpcode::StrPrefix, _) => [F::ZERO, F::ONE, F::ZERO, F::ZERO],
            (RlpOpcode::ListPrefix, 0..=55) => [F::ZERO, F::ZERO, F::ONE, F::ZERO],
            (RlpOpcode::ListPrefix, _) => [F::ZERO, F::ZERO, F::ZERO, F::ONE],
            _ => [F::ZERO; 4],
        };

        // byte decomp
        let mut count = self.count as u64;
        for i in 1..5 {
            row.rc_u8s[i] = F::from_canonical_u64(count & 0xFF);
            count >>= 8;
        }

        // base-56 decomp
        let mut count = self.count as u64;
        for i in 0..6 {
            row.rc_56_limbs[i] = F::from_canonical_u64(count % 56);
            count /= 56;
        }

        // inv check for upper limb sum
        let upper_limb_sum = (1..6).map(|i| row.rc_56_limbs[i]).sum::<F>();
        row.upper_limbs_sum_inv = if upper_limb_sum == F::ZERO {
            F::ZERO
        } else {
            upper_limb_sum.inverse()
        };
        row.count_in_range = F::from_bool(upper_limb_sum == F::ZERO);

        // log256 flag
        let bytes = if self.count == 1 {
            1
        } else {
            (log2_ceil(self.count) + 7) / 8
        };

        row.log256_flags = match bytes {
            0 => [F::ZERO; 4],
            1 => [F::ONE, F::ZERO, F::ZERO, F::ZERO],
            2 => [F::ZERO, F::ONE, F::ZERO, F::ZERO],
            3 => [F::ZERO, F::ZERO, F::ONE, F::ZERO],
            4 => [F::ZERO, F::ZERO, F::ZERO, F::ONE],
            _ => unreachable!(),
        };

        let top_byte_idx = if bytes == 0 { 1 } else { bytes };
        row.top_byte_inv = if row.rc_u8s[top_byte_idx] == F::ZERO {
            F::ZERO
        } else {
            row.rc_u8s[top_byte_idx].inverse()
        };

        row.count_is_one = F::from_bool(self.count == 1);
        row.count_minus_one_inv = if self.count == 1 {
            F::ZERO
        } else {
            (row.count - F::ONE).inverse()
        };

        row.prefix_case_tmp = F::from_bool(
            matches!(self.opcode, RlpOpcode::StrPrefix)
                && row.prefix_case_flags[0] == F::ONE
                && self.count == 1,
        );
        row.prefix_case_tmp_2 = F::from_bool(
            matches!(self.opcode, RlpOpcode::StrPrefix)
                && !own_encoding_case
                && row.prefix_case_flags[0] == F::ZERO,
        );
        row.prefix_case_tmp_3 =
            F::from_bool(matches!(self.opcode, RlpOpcode::StrPrefix)) * row.prefix_case_flags[1];
        row.prefix_case_tmp_4 =
            F::from_bool(matches!(self.opcode, RlpOpcode::ListPrefix)) * row.prefix_case_flags[3];
        row.end_entry_tmp = F::from_bool(self.opcode == RlpOpcode::EndEntry && self.depth == 0);

        // LUT counts
        let row_idx = self.stark_trace.len() as u64;
        row.count_127 = F::from_canonical_u64(row_idx % 128);
        row.count_u8 = F::from_canonical_u64(row_idx % 256);
        row.count_56 = F::from_canonical_u64(row_idx % 56);

        row.count_127_minus_127_inv = if row.count_127 == F::from_canonical_u64(127) {
            F::ZERO
        } else {
            (row.count_127 - F::from_canonical_u64(127)).inverse()
        };
        row.count_127_is_127 = F::from_bool(row.count_127 == F::from_canonical_u64(127));

        row.count_u8_minus_255_inv = if row.count_u8 == F::from_canonical_u64(255) {
            F::ZERO
        } else {
            (row.count_u8 - F::from_canonical_u64(255)).inverse()
        };
        row.count_u8_is_255 = F::from_bool(row.count_u8 == F::from_canonical_u64(255));

        row.count_56_minus_55_inv = if row.count_56 == F::from_canonical_u64(55) {
            F::ZERO
        } else {
            (row.count_56 - F::from_canonical_u64(55)).inverse()
        };
        row.count_56_is_55 = F::from_bool(row.count_56 == F::from_canonical_u64(55));

        row
    }

    fn gen_padding(&mut self, log2_target_len: usize) {
        assert!(matches!(self.opcode, RlpOpcode::Halt));

        let target_len = (1 << log2_target_len).max(self.stark_trace.len().next_power_of_two());
        while self.stark_trace.len() < target_len {
            let mut row = self.gen_row();
            self.gen_stack_timestamps(&mut row);
            self.stark_trace.push(row);
        }
    }

    fn gen_luts(values: &mut [PolynomialValues<F>]) {
        let pairs = rc_56_cols().zip(std::iter::repeat(lut_56_col()));
        let pairs = pairs.chain(rc_u8_cols().zip(std::iter::repeat(lut_u8_col())));
        let pairs = pairs.chain(std::iter::once((rc_127_col(), lut_127_col())));

        let pairs_permuted = rc_56_permuted_cols().zip(lut_56_permuted_cols());
        let pairs_permuted =
            pairs_permuted.chain(rc_u8_permuted_cols().zip(lut_u8_permuted_cols()));
        let pairs_permuted = pairs_permuted.chain(std::iter::once((
            rc_127_permuted_col(),
            lut_127_permuted_col(),
        )));

        for ((input_col, table_col), (input_col_permuted, table_col_permuted)) in
            pairs.zip(pairs_permuted)
        {
            let (input, table) =
                permuted_cols(&values[input_col].values, &values[table_col].values);
            values[input_col_permuted] = PolynomialValues::new(input);
            values[table_col_permuted] = PolynomialValues::new(table);
        }
    }

    pub fn gen_trace(&mut self, log2_target_len: Option<usize>) {
        self.gen_state_machine();
        self.gen_padding(log2_target_len.unwrap_or(0));
        for row in self.stark_trace.iter().filter(|r| r.opcode[3] == F::ONE) {
            assert_eq!(row.rc_u8s[0], row.input_memory[0][1]);
        }
    }

    pub fn into_polynomial_values(self) -> Vec<PolynomialValues<F>> {
        let rows: Vec<[F; RLP_NUM_COLS]> =
            self.stark_trace.into_iter().map(|row| row.into()).collect();
        let mut values = trace_rows_to_poly_values(rows);
        Self::gen_luts(&mut values);
        values
    }

    fn gen_state_machine(&mut self) {
        loop {
            let mut row = self.gen_row();
            match self.opcode {
                RlpOpcode::NewEntry => {
                    let next = self.read_pc_advance(&mut row, 0);
                    let is_last = self.read_pc_advance(&mut row, 1);
                    if self.depth == 0 {
                        self.next = next.to_canonical_u64() as usize;
                        self.is_last = match is_last.to_canonical_u64() {
                            // convert to u64 since associated consts not allowed in patterns yet
                            0 => false,
                            1 => true,
                            _ => panic!("is_last must be 0 or 1"),
                        }
                    }

                    let is_list = match self.read_pc_advance(&mut row, 2).to_canonical_u64() {
                        // convert to u64 since associated consts not allowed in patterns yet
                        0 => false,
                        1 => true,
                        _ => panic!("is_list must be 0 or 1"),
                    };

                    let op_id_read = self.read_pc_advance(&mut row, 3).to_canonical_u64();
                    assert!(op_id_read == self.op_id);

                    self.content_len =
                        self.read_pc_advance(&mut row, 4).to_canonical_u64() as usize;
                    self.count = 0;
                    self.list_count = 0;

                    match is_list {
                        true => {
                            if self.content_len == 0 {
                                self.opcode = RlpOpcode::ListPrefix;
                            } else {
                                self.opcode = RlpOpcode::List;
                            }
                        }
                        false => {
                            if self.content_len == 0 {
                                self.opcode = RlpOpcode::StrPrefix;
                            } else {
                                self.opcode = RlpOpcode::StrPush;
                            }
                        }
                    }
                }
                RlpOpcode::StrPush => {
                    let val = self.read_pc_advance(&mut row, 0);
                    row.rc_u8s[0] = val;
                    self.push_output_stack(val, &mut row, 0);
                    self.count += 1;
                    if self.content_len == self.count {
                        self.opcode = RlpOpcode::StrPrefix;
                    }
                }
                RlpOpcode::StrPrefix => {
                    // in the STARK, output_stack.last() is accessed via the "previous" row
                    // this still works for empty string as len != 1 in that case, so first_val doesn't matter
                    let first_val = self.output_stack.last().unwrap();
                    let first_val = first_val.to_canonical_u64() as u8;
                    let prefix = compute_str_prefix(self.count, first_val);
                    if prefix.is_empty() {
                        row.rc_127 = F::from_canonical_u8(first_val);
                    }

                    for (channel, b) in prefix.into_iter().enumerate().rev() {
                        self.push_output_stack(
                            F::from_canonical_u64(b as u64),
                            &mut row,
                            4 - channel,
                        );
                        self.count += 1;
                    }
                    self.opcode = RlpOpcode::EndEntry;
                }
                RlpOpcode::List => {
                    // push current list count onto the stack. This is used so the returning state can
                    // tell when to stop recursing
                    self.push_call_stack(
                        F::from_canonical_u64(self.list_count as u64),
                        &mut row,
                        0,
                    );
                    // read pointer from the table and push it onto the stack
                    let inner_addr = self.read_pc_advance(&mut row, 0);
                    self.push_call_stack(inner_addr, &mut row, 1);
                    self.list_count += 1;
                    if self.list_count == self.content_len {
                        self.opcode = RlpOpcode::Recurse;
                    }
                }
                RlpOpcode::ListPrefix => {
                    let prefix = compute_list_prefix(self.count);
                    for (channel, b) in prefix.into_iter().enumerate().rev() {
                        self.push_output_stack(
                            F::from_canonical_u64(b as u64),
                            &mut row,
                            4 - channel,
                        );
                        self.count += 1;
                    }
                    self.opcode = RlpOpcode::EndEntry;
                }
                RlpOpcode::EndEntry => {
                    // if we're at the top level, finalize the entry's output and proceed to
                    // the next item to be encoded if is_last is false. otherwise halt
                    // if we're not at the top level, return up a level
                    if self.depth == 0 {
                        // push encoded output len (count) to output stack
                        self.push_output_stack(
                            F::from_canonical_u64(self.count as u64),
                            &mut row,
                            0,
                        );
                        // push op_id to the output stack
                        self.push_output_stack(F::from_canonical_u64(self.op_id), &mut row, 1);

                        self.op_id += 1;
                        if self.is_last {
                            self.opcode = RlpOpcode::Halt;
                        } else {
                            self.pc = self.next;
                            self.opcode = RlpOpcode::NewEntry;
                        }
                    } else {
                        self.opcode = RlpOpcode::Return;
                    }
                }
                RlpOpcode::Recurse => {
                    // pop addr from call stack
                    // before: [prev_list_count, prev_list_addr, list_count, list_addr]
                    // after: [prev_list_count, prev_list_addr, list_count]
                    let dst = self.pop_call_stack(&mut row, 0);
                    // push count to call stack
                    // after: [prev_list_count, prev_list_addr, list_count, count]
                    self.push_call_stack(F::from_canonical_u64(self.count as u64), &mut row, 1);
                    // push pc to call stack
                    // after: [prev_list_count, prev_list_addr, list_count, count, pc]
                    self.push_call_stack(F::from_canonical_u64(self.pc as u64), &mut row, 2);

                    // jump to the new entry
                    self.pc = dst.to_canonical_u64() as usize;
                    // increment depth
                    self.depth += 1;
                    // set new state to NewEntry
                    self.opcode = RlpOpcode::NewEntry;
                }
                RlpOpcode::Return => {
                    // before: [prev_list_count, prev_list_addr, list_count, count, pc]
                    let old_pc = self.pop_call_stack(&mut row, 0);
                    // before: [prev_list_count, prev_list_addr, list_count, count]
                    let old_count = self.pop_call_stack(&mut row, 1);
                    // before: [prev_list_count, prev_list_addr, list_count]
                    // after: [prev_list_count, prev_list_addr_addr] - the start point for Recurse state if it's not the last step
                    let old_list_count = self.pop_call_stack(&mut row, 2);

                    self.count += old_count.to_canonical_u64() as usize;
                    self.list_count = old_list_count.to_canonical_u64() as usize;
                    // jump back to the next element of the list & decrement depth
                    self.pc = old_pc.to_canonical_u64() as usize;
                    self.depth -= 1;

                    if self.list_count == 0 {
                        self.opcode = RlpOpcode::ListPrefix;
                    } else {
                        self.opcode = RlpOpcode::Recurse;
                    }
                }
                RlpOpcode::Halt => {
                    self.prepend_stack_top(&mut row);
                    self.gen_stack_timestamps(&mut row);
                    self.gen_output_stack_incrs(&mut row);
                    self.stark_trace.push(row);
                    return;
                }
            };
            self.gen_stack_timestamps(&mut row);
            self.gen_output_stack_addrs(&mut row);
            self.stark_trace.push(row);
        }
    }

    fn prepend_stack_top(&mut self, row: &mut RlpRow<F>) {
        let top = F::from_canonical_u64(self.output_stack.len() as u64);
        let prev_row = self.stark_trace.last().unwrap();
        let top_prev_row = prev_row.output_stack[4][0];
        assert_eq!(top, top_prev_row);

        self.output_stack.insert(0, top);
        row.output_stack_filters[0] = F::ONE;
        row.output_stack[0][0] = F::ZERO;
        row.output_stack[0][1] = top;
    }

    fn gen_output_stack_incrs(&mut self, row: &mut RlpRow<F>) {
        for i in 1..5 {
            row.output_stack[i][0] = if row.output_stack_filters[i] == F::ONE {
                row.output_stack[i - 1][0] + F::ONE
            } else {
                row.output_stack[i - 1][0]
            };
        }
    }

    fn gen_output_stack_addrs(&mut self, row: &mut RlpRow<F>) {
        if self.stark_trace.is_empty() {
            row.output_stack[0][0] = F::ZERO;
        } else {
            let prev_row = self.stark_trace.last().unwrap();
            row.output_stack[0][0] = if row.output_stack_filters[0] == F::ONE {
                prev_row.output_stack[4][0] + F::ONE
            } else {
                prev_row.output_stack[4][0]
            };
        }
        self.gen_output_stack_incrs(row);
    }

    fn gen_stack_timestamps(&mut self, row: &mut RlpRow<F>) {
        if self.stark_trace.is_empty() {
            row.call_stack[0][2] = F::ONE;
        } else {
            let prev_row = self.stark_trace.last().unwrap();
            row.call_stack[0][2] = if row.call_stack_filters[0] == F::ONE {
                prev_row.call_stack[2][2] + F::ONE
            } else {
                prev_row.call_stack[2][2]
            };
        }
        for i in 1..3 {
            row.call_stack[i][2] = if row.call_stack_filters[i] == F::ONE {
                row.call_stack[i - 1][2] + F::ONE
            } else {
                row.call_stack[i - 1][2]
            };
        }
    }

    fn read_pc_advance(&mut self, row: &mut RlpRow<F>, channel: usize) -> F {
        let val = self.input_memory[self.pc];
        row.input_memory[channel][0] = F::from_canonical_u64(self.pc as u64);
        row.input_memory[channel][1] = val;
        row.input_memory_filters[channel] = F::from_bool(true);
        self.pc += 1;
        val
    }

    fn push_call_stack(&mut self, val: F, row: &mut RlpRow<F>, channel: usize) {
        self.call_stack.push(val);
        self.call_stack_trace.push(StackOp::Push(val));

        row.call_stack[channel][0] = F::from_bool(false);
        row.call_stack[channel][1] = val;
        row.call_stack_filters[channel] = F::from_bool(true);
    }

    fn pop_call_stack(&mut self, row: &mut RlpRow<F>, channel: usize) -> F {
        let val = self.call_stack.pop().unwrap();
        self.call_stack_trace.push(StackOp::Pop(val));

        row.call_stack[channel][0] = F::from_bool(true);
        row.call_stack[channel][1] = val;
        row.call_stack_filters[channel] = F::from_bool(true);
        val
    }

    fn push_output_stack(&mut self, val: F, row: &mut RlpRow<F>, channel: usize) {
        self.output_stack.push(val);

        row.output_stack[channel][1] = val;
        row.output_stack_filters[channel] = F::from_bool(true);
    }
}

pub fn compute_str_prefix(len: usize, first_val: u8) -> Vec<u8> {
    match (len, first_val) {
        (1, 0x00..=0x7F) => vec![],
        (0..=55, _) => vec![0x80 + len as u8],
        _ => {
            let mut len_bytes = len.to_be_bytes().to_vec();
            let mut i = 0;
            while len_bytes[i] == 0 {
                i += 1;
            }
            len_bytes = len_bytes[i..].to_vec();
            let mut prefix = vec![0xB7 + len_bytes.len() as u8];
            prefix.append(&mut len_bytes);
            prefix
        }
    }
}

pub fn compute_list_prefix(len: usize) -> Vec<u8> {
    match len {
        0..=55 => {
            vec![0xC0 + len as u8]
        }
        _ => {
            let mut len_bytes = len.to_be_bytes().to_vec();
            let mut i = 0;
            while len_bytes[i] == 0 {
                i += 1;
            }
            len_bytes = len_bytes[i..].to_vec();
            let mut prefix = vec![0xF7 + len_bytes.len() as u8];
            prefix.append(&mut len_bytes);
            prefix
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem {
    List(Vec<Box<RlpItem>>),
    Str(Vec<u8>),
}

impl RlpItem {
    pub fn list_from_vec(items: Vec<RlpItem>) -> RlpItem {
        let mut list = Vec::new();
        for item in items {
            list.push(Box::new(item));
        }
        RlpItem::List(list)
    }
    // must call this all at once - cannot update this incrementally
    // this panics if it is called with an empty list
    // TODO: use an error instead.
    pub fn items_to_memory_values<F: PrimeField64>(items: &[Self]) -> Vec<F> {
        let mut trace = Vec::new();
        let mut is_last_ptr_opt = None;
        for (i, item) in items.iter().enumerate() {
            let is_last_ptr = Self::item_to_memory_values(item, &mut trace, i as u64);
            is_last_ptr_opt = Some(is_last_ptr);
        }

        if let Some(is_last_ptr) = is_last_ptr_opt {
            trace[is_last_ptr] = F::ONE;
        } else {
            // this should not be called with an empty list
            panic!("enmpty list!")
        }

        trace
    }

    // returns pointer to the cell containing is_last
    fn item_to_memory_values<F: PrimeField64>(
        item: &Self,
        trace: &mut Vec<F>,
        op_id: u64,
    ) -> usize {
        let next_item_ptr = trace.len();
        // next_item
        // set to zero (dummy), set it after we recurse
        trace.push(F::ZERO);
        // is_last
        // set it to false, but return a pointer to it so the caller can set it
        let is_last_addr = trace.len();
        trace.push(F::ZERO);

        match item {
            RlpItem::List(items) => {
                // is_list: true
                trace.push(F::ONE);

                // id: op_id
                trace.push(F::from_canonical_u64(op_id));

                // len: len of the *list*
                trace.push(F::from_canonical_u64(items.len() as u64));

                // content:
                // to populate this, we iterate over the list twice:
                // first time is to initialize the empty table of ptrs to child entries
                // the second time is to 1) add the children to the trace and 2) set table entries accordingly
                let mut recursive_ptrs = Vec::new();
                for _ in 0..items.len() {
                    recursive_ptrs.push(trace.len());
                    trace.push(F::ZERO);
                }

                for (item, ptr) in items.iter().zip(recursive_ptrs.into_iter()) {
                    // set pointer to the next cell, which will start the next recursive entry
                    trace[ptr] = F::from_canonical_u64(trace.len() as u64);
                    // don't care about is_last_ptr for child entries - only for top-level
                    Self::item_to_memory_values(item, trace, op_id);
                }

                // set next_item ptr
                trace[next_item_ptr] = F::from_canonical_u64(trace.len() as u64);
            }
            RlpItem::Str(s) => {
                // is_list: false
                trace.push(F::ZERO);

                // id: op_id
                trace.push(F::from_canonical_u64(op_id));

                // len: len of the *string*, in bytes
                trace.push(F::from_canonical_u64(s.len() as u64));

                // content: the string as bytes, reversed
                for &b in s.iter().rev() {
                    trace.push(F::from_canonical_u8(b));
                }

                // set next item ptr
                trace[next_item_ptr] = F::from_canonical_u64(trace.len() as u64);
            }
        }
        is_last_addr
    }

    pub fn try_as_byte_str(&self) -> Result<Vec<u8>, &'static str> {
        match self {
            RlpItem::Str(s) => Ok(s.clone()),
            _ => Err("not a byte string"),
        }
    }

    pub fn try_as_list(&self) -> Result<Vec<RlpItem>, &'static str> {
        match self {
            RlpItem::List(l) => Ok(l.iter().map(|x| *x.clone()).collect()),
            _ => Err("not a list"),
        }
    }
}

impl Encodable for RlpItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            RlpItem::List(items) => {
                s.append_list::<Self, Box<Self>>(items);
            }
            RlpItem::Str(buf) => {
                buf.rlp_append(s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;

    use plonky2::field::goldilocks_field::GoldilocksField;
    use rlp::encode;

    use super::*;

    type F = GoldilocksField;

    macro_rules! test_rlp_str_entry {
        ($s:expr, $mem:expr, $is_last:expr, $id:expr, $offset:expr) => {{
            let (head, tail) = $mem.split_at(5);

            // next_item
            assert_eq!(head[0] as usize, $s.len() + 5 + $offset);
            // is_last_item
            assert_eq!(head[1], if $is_last { 1 } else { 0 });
            // is_list
            assert_eq!(head[2], 0);
            // id
            assert_eq!(head[3], $id);
            // len
            assert_eq!(head[4] as usize, $s.len());

            // check entry content is s reversed
            assert!(tail.len() >= $s.len());
            let content = &tail[..$s.len()];
            for (b, b_expected) in content
                .iter()
                .map(|x| u8::try_from(*x).unwrap())
                .zip($s.iter().copied().rev())
            {
                assert_eq!(b, b_expected)
            }

            $s.len() + 5
        }};
    }

    #[test]
    fn test_rlp_item_single_string() {
        let s = b"I met a metaphorical girl in a metaphorical word";
        let items = vec![RlpItem::Str(s.to_vec())];
        let mem = RlpItem::items_to_memory_values::<F>(&items);
        let mem = mem
            .into_iter()
            .map(|v| v.to_canonical_u64())
            .collect::<Vec<_>>();
        test_rlp_str_entry!(s, mem, true, 0, 0);
    }

    #[test]
    fn test_rlp_item_multiple_strings() {
        let ss = vec![
            b"I used to rap like i had some marbles in my mouth".to_vec(),
            b"But the stones turned precious when they all came out".to_vec(),
            b"On a string of deep thought that could never be bought".to_vec(),
        ];

        let items = ss
            .iter()
            .map(|v| RlpItem::Str(v.clone()))
            .collect::<Vec<_>>();
        let mem = RlpItem::items_to_memory_values::<F>(&items);
        let mem = mem
            .into_iter()
            .map(|v| v.to_canonical_u64())
            .collect::<Vec<_>>();
        let mut m = &mem[..];
        let mut offset = 0;
        for i in 0..items.len() - 1 {
            let len = test_rlp_str_entry!(&ss[i], m, false, i as u64, offset);
            m = &m[len..];
            offset += len;
        }
        test_rlp_str_entry!(ss.last().unwrap(), m, true, ss.len() as u64 - 1, offset);
    }

    #[test]
    fn test_rlp_one_layer_list() {
        let ss = vec![
            b"I used to rap like i had some marbles in my mouth".to_vec(),
            b"But the stones turned precious when they all came out".to_vec(),
            b"On a string of deep thought that could never be bought".to_vec(),
        ];

        let item = RlpItem::list_from_vec(ss.iter().cloned().map(RlpItem::Str).collect());
        let mem = RlpItem::items_to_memory_values::<F>(&[item]);
        let mem = mem
            .into_iter()
            .map(|v| v.to_canonical_u64())
            .collect::<Vec<_>>();

        let (head, tail) = mem.split_at(5);
        // next item
        assert_eq!(head[0] as usize, mem.len());
        // is_last_item
        assert_eq!(head[1], 1);
        // is_list
        assert_eq!(head[2], 1);
        // id
        assert_eq!(head[3], 0);
        // len
        assert_eq!(head[4], 3);

        for i in 0..3 {
            let offset = tail[i] as usize;
            let s_entry = &mem[offset..];

            // is_last set to false always for child values
            // id the same for all child values
            test_rlp_str_entry!(&ss[i], s_entry, false, 0, offset);
        }
    }

    #[test]
    fn test_rlp_multi_layer_list() {
        let items = vec![
            RlpItem::Str(b"After six come seven and eight".to_vec()),
            RlpItem::Str(b"Access code to the pearly gates".to_vec()),
            RlpItem::List(vec![
                Box::new(RlpItem::Str(b"They say heaven can wait".to_vec())),
                Box::new(RlpItem::Str(b"And you speak of fate".to_vec())),
                Box::new(RlpItem::Str(b"A finale to a play for my mate".to_vec())),
            ]),
            RlpItem::Str(b"I see the angels draw the drapes".to_vec()),
        ];

        let item = RlpItem::List(items.iter().cloned().map(Box::new).collect());
        let mem = RlpItem::items_to_memory_values::<F>(&[item]);
        let mem = mem
            .into_iter()
            .map(|v| v.to_canonical_u64())
            .collect::<Vec<_>>();
        let (head, tail) = mem.split_at(5);

        // check outer entry
        // next_item
        assert_eq!(head[0] as usize, mem.len());
        // is_last_item
        assert_eq!(head[1], 1);
        // is_list
        assert_eq!(head[2], 1);
        // id
        assert_eq!(head[3], 0);
        // len
        assert_eq!(head[4], 4);

        // check first two depth-1 entries
        let s = match items[0] {
            RlpItem::Str(ref s) => s,
            _ => panic!("unexpected item type"),
        };
        let offset = tail[0] as usize;
        let s_entry = &mem[offset..];
        test_rlp_str_entry!(s, s_entry, false, 0, offset);

        let s = match items[1] {
            RlpItem::Str(ref s) => s,
            _ => panic!("unexpected item type"),
        };
        let offset = tail[1] as usize;
        let s_entry = &mem[offset..];
        test_rlp_str_entry!(s, s_entry, false, 0, offset);

        // check depth-2 entry
        let list = match items[2] {
            RlpItem::List(ref list) => list,
            _ => panic!("unexpected item type"),
        };
        let offset = tail[2] as usize;
        let next_offset = tail[3] as usize;
        let list_entry = &mem[offset..];
        let (list_head, list_tail) = list_entry.split_at(5);
        // next_item
        assert_eq!(list_head[0] as usize, next_offset);
        // is_last_item
        assert_eq!(list_head[1], 0);
        // is_list
        assert_eq!(list_head[2], 1);
        // id
        assert_eq!(list_head[3], 0);
        // len
        assert_eq!(list_head[4], 3);
        // check inner strings
        for i in 0..3 {
            let offset = list_tail[i] as usize;
            let s_entry = &mem[offset..];
            let s = match *list[i] {
                RlpItem::Str(ref s) => s,
                _ => panic!("unexpected item type"),
            };
            test_rlp_str_entry!(s, s_entry, false, 0, offset);
        }

        // check last depth-1 entry
        let s = match items[3] {
            RlpItem::Str(ref s) => s,
            _ => panic!("unexpected item type"),
        };
        let offset = tail[3] as usize;
        let s_entry = &mem[offset..];
        test_rlp_str_entry!(s, s_entry, false, 0, offset);
    }

    #[test]
    fn test_state_machine() {
        let input = vec![
            RlpItem::Str(b"Relax".to_vec()),
            RlpItem::Str(b"Here we go, part two".to_vec()),
            RlpItem::Str(b"Checking out!".to_vec()),
            RlpItem::list_from_vec(vec![
                RlpItem::list_from_vec(vec![
                    RlpItem::Str(b"Once again, now where do I start, dear love".to_vec()),
                    RlpItem::Str(b"Dumb struck with the pure luck to find you here".to_vec()),
                    RlpItem::Str(b"Every morn' I awake from a cavernous night".to_vec()),
                    RlpItem::Str(b"Sometimes still pondering the previous plight".to_vec()),
                ]),
                RlpItem::Str(b"Seems life done changed long time no speak".to_vec()),
                RlpItem::Str(b"Nowadays I often forget the day of the week".to_vec()),
            ]),
            RlpItem::list_from_vec(vec![
                RlpItem::Str(b"Taking it by stride if you know what I mean".to_vec()),
                RlpItem::Str(b"No harm done, no offense taken by me".to_vec()),
                RlpItem::Str(b"So let's rap, we'll catch up to par, what's the haps?".to_vec()),
            ]),
            RlpItem::Str(
                b"C'est la vie, as they say L.O.V.E evidently, see every song has a sequel
Never same, everything but the name, all fresh just like back then, how we do everyday
C'est la vie, as they say L.O.V.E eloquently, see every dream has a part two
Never same, you got to keep it tight, all fresh just like back then, now hear me out"
                    .to_vec(),
            ),
            // special cases
            RlpItem::List(vec![]),
            RlpItem::Str(vec![]),
            RlpItem::Str(vec![0x08]),
        ];

        let mut generator = RlpStarkGenerator::<F>::new();
        generator.generate(&input);
        let output = generator
            .output_stack()
            .into_iter()
            .map(|v| v.to_canonical_u64())
            .collect::<Vec<_>>();
        assert!(output.len() > 0);

        struct RlpReader {
            sp: usize,
            output_mem: Vec<u64>,
        }

        impl RlpReader {
            fn new(output_mem: Vec<u64>) -> Self {
                RlpReader {
                    sp: output_mem.len() - 1,
                    output_mem: output_mem,
                }
            }

            fn pop(&mut self) -> u64 {
                let v = self.output_mem[self.sp];
                println!("sp: {}, v: {}", self.sp, v);
                self.sp -= 1;
                v
            }

            fn sp(&self) -> usize {
                self.sp
            }
        }

        let sp = output[0] as usize;
        assert_eq!(output.len(), sp + 1);

        let mut reader = RlpReader::new(output);
        let mut outputs = Vec::new();

        while reader.sp() >= 3 {
            let op_id = reader.pop();
            let len = reader.pop();
            let mut output = Vec::new();
            for _ in 0..len {
                let b = reader.pop();
                assert!(b < 256);
                output.push(b as u8);
            }
            outputs.push((op_id, output));
        }

        assert!(outputs.iter().map(|(op_id, _)| Reverse(op_id)).is_sorted());

        let outputs = outputs
            .into_iter()
            .rev()
            .map(|(_, output)| output)
            .collect::<Vec<_>>();

        let correct_outputs = input.iter().map(encode);
        for (output, correct_output) in outputs.into_iter().zip(correct_outputs) {
            assert_eq!(output, correct_output.into_vec());
        }
    }
}
