/// a STARK for the ethereum RLP-encoding of recursive structured data types (i.e. lists and strings) using two memories and a call stack

use std::borrow::Borrow;
use std::marker::PhantomData;

use plonky2::field::{
    extension::{Extendable, FieldExtension},
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::starky2lib::gadgets::ConstraintConsumerFiltered;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};
use crate::{lookup::eval_lookups, stark::Stark};

pub mod generation;
pub mod layout;

use layout::*;

pub struct RlpStark<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> RlpStark<F, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Default for RlpStark<F, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for RlpStark<F, D> {
    fn num_columns(&self) -> usize {
        layout::RLP_NUM_COLS
    }

    fn num_public_inputs(&self) -> usize {
        0
    }

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let stack_pop = P::ONES;
        let stack_push = P::ZEROS;

        let as_arr: &[P; layout::RLP_NUM_COLS] = vars.local_values.try_into().unwrap();
        let curr_row: &RlpRow<P> = as_arr.borrow();

        let as_arr: &[P; layout::RLP_NUM_COLS] = vars.next_values.try_into().unwrap();
        let next_row: &RlpRow<P> = as_arr.borrow();


        // initial op_id is 0
        yield_constr.constraint_first_row(curr_row.op_id);
        // initial pc is 0
        yield_constr.constraint_first_row(curr_row.pc);
        // initial count is 0
        yield_constr.constraint_first_row(curr_row.count);

        // binary check opcode
        for i in 0..8 {
            yield_constr.constraint((P::ONES - curr_row.opcode[i]) * curr_row.opcode[i]);
        }

        // check opcode at-most-one-hot encoding
        let opcode_bit_sum = (0..8).map(|i| curr_row.opcode[i]).sum::<P>();
        yield_constr.constraint((P::ONES - opcode_bit_sum) * opcode_bit_sum);

        // unpack opcodes
        let opcode_is_new_entry = P::ONES - opcode_bit_sum;
        let opcode_is_list = curr_row.opcode[0];
        let opcode_is_recurse = curr_row.opcode[1];
        let opcode_is_return = curr_row.opcode[2];
        let opcode_is_str_push = curr_row.opcode[3];
        let opcode_is_str_prefix = curr_row.opcode[4];
        let opcode_is_list_prefix = curr_row.opcode[5];
        let opcode_is_end_entry = curr_row.opcode[6];
        let opcode_is_halt = curr_row.opcode[7];

        let next_opcode_bit_sum = (0..8).map(|i| next_row.opcode[i]).sum::<P>();
        let next_opcode_is_new_entry = P::ONES - next_opcode_bit_sum;
        let next_opcode_is_list = next_row.opcode[0];
        let next_opcode_is_recurse = next_row.opcode[1];
        let next_opcode_is_return = next_row.opcode[2];
        let next_opcode_is_str_push = next_row.opcode[3];
        let next_opcode_is_str_prefix = next_row.opcode[4];
        let next_opcode_is_list_prefix = next_row.opcode[5];
        let next_opcode_is_halt = next_row.opcode[7];

        // initial opcode is new entry
        yield_constr.constraint_first_row(P::ONES - opcode_is_new_entry);

        // binary check input memory ctl filters
        for i in 0..5 {
            yield_constr.constraint(
                (P::ONES - curr_row.input_memory_filters[i]) * curr_row.input_memory_filters[i],
            );
        }

        // set input memory filters according to current opcode
        // NewEntry: 0..5
        // List: 0
        // Recurse: None
        // Return: None
        // StrPush: 0
        // StrPrefix: None
        // ListPrefix: None
        // EndEntry: None
        // Halt: None
        let set_filter_0 = opcode_is_new_entry + opcode_is_list + opcode_is_str_push;
        let set_all_filters = opcode_is_new_entry;

        yield_constr.constraint(set_filter_0 - curr_row.input_memory_filters[0]);
        for i in 1..5 {
            yield_constr.constraint(set_all_filters - curr_row.input_memory_filters[i]);
        }

        // set call stack filters according to current opcode
        // NewEntry: None,
        // List: 0..1,
        // Recurse: 0..2,
        // Return: 0..2,
        // StrPush: None,
        // StrPrefix: None,
        // ListPrefix: None,
        // EndEntry: None,
        // Halt: None
        let set_filters_0_and_1 = opcode_is_list + opcode_is_recurse + opcode_is_return;
        let set_filter_2 = opcode_is_recurse + opcode_is_return;
        yield_constr.constraint(set_filters_0_and_1 - curr_row.call_stack_filters[0]);
        yield_constr.constraint(set_filters_0_and_1 - curr_row.call_stack_filters[1]);
        yield_constr.constraint(set_filter_2 - curr_row.call_stack_filters[2]);

        // check call stack timestamp starts at 1
        yield_constr.constraint_first_row(P::ONES - curr_row.call_stack[0][2]);

        // check call stack timestamps increment properly
        yield_constr.constraint_transition_filtered(
            next_row.call_stack[0][2] - curr_row.call_stack[2][2] - P::ONES,
            next_row.call_stack_filters[0],
        );
        yield_constr.constraint_transition_filtered(
            next_row.call_stack[0][2] - curr_row.call_stack[2][2],
            P::ONES - next_row.call_stack_filters[0],
        );
        for i in 1..3 {
            yield_constr.constraint_filtered(
                curr_row.call_stack[i][2] - curr_row.call_stack[i - 1][2] - P::ONES,
                curr_row.call_stack_filters[i],
            );
            yield_constr.constraint_filtered(
                curr_row.call_stack[i][2] - curr_row.call_stack[i - 1][2],
                P::ONES - curr_row.call_stack_filters[i],
            );
        }

        // set output "stack" filters according to current opcode
        // NewEntry: None,
        // List: None,
        // Recurse: None,
        // Return: None,
        // StrPush: 0,
        // StrPrefix: filters checked separately
        // ListPrefix: filters checked separately
        // EndEntry: 0..1 if depth_is_zero (checked below)
        // Halt: None
        let is_end_entry_and_depth_is_zero = opcode_is_end_entry * curr_row.depth_is_zero;
        let set_filter_0 = opcode_is_str_push + is_end_entry_and_depth_is_zero;
        let set_filter_1 = is_end_entry_and_depth_is_zero;
        yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[0], set_filter_0);
        yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[1], set_filter_1);
        // turn off other output stack filters for all non-prefix opcodes
        let opcode_is_not_prefix = P::ONES - opcode_is_str_prefix - opcode_is_list_prefix;
        yield_constr.constraint_filtered(curr_row.output_stack_filters[2], opcode_is_not_prefix);
        yield_constr.constraint_filtered(curr_row.output_stack_filters[3], opcode_is_not_prefix);
        yield_constr.constraint_filtered(curr_row.output_stack_filters[4], opcode_is_not_prefix);

        // check output "stack" addresses start at 0. It is incremented before written, so address 0 won't be checked until the halt state below
        yield_constr.constraint_first_row(curr_row.output_stack[0][0]);

        // check output "stack" addresses increment properly, but ignore these checks during the halt state
        yield_constr.constraint_transition_filtered(
            next_row.output_stack[0][0] - curr_row.output_stack[4][0] - P::ONES,
            next_row.output_stack_filters[0] * (P::ONES - next_opcode_is_halt),
        );
        yield_constr.constraint_transition_filtered(
            next_row.output_stack[0][0] - curr_row.output_stack[4][0],
            (P::ONES - next_row.output_stack_filters[0]) * (P::ONES - next_opcode_is_halt),
        );
        for i in 1..5 {
            yield_constr.constraint_filtered(
                curr_row.output_stack[i][0] - curr_row.output_stack[i - 1][0] - P::ONES,
                curr_row.output_stack_filters[i],
            );
            yield_constr.constraint_filtered(
                curr_row.output_stack[i][0] - curr_row.output_stack[i - 1][0],
                P::ONES - curr_row.output_stack_filters[i],
            );
        }

        // NewEntry

        // read entry metadata from input memory
        // next next = [pc] if depth_is_zero
        yield_constr.constraint_filtered(
            curr_row.input_memory[0][0] - curr_row.pc,
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[0][1] - next_row.next,
            opcode_is_new_entry * curr_row.depth_is_zero,
        );
        // next is_last = [pc + 1] if depth_is_zero
        let mut offset = P::ONES;
        yield_constr.constraint_filtered(
            curr_row.input_memory[1][0] - (curr_row.pc + offset),
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[1][1] - next_row.is_last,
            opcode_is_new_entry * curr_row.depth_is_zero,
        );
        // is_list = [pc + 2]
        offset += P::ONES;
        yield_constr.constraint_filtered(
            curr_row.input_memory[2][0] - (curr_row.pc + offset),
            opcode_is_new_entry,
        );
        let is_list = curr_row.input_memory[2][1];
        // next op_id = [pc + 3]
        // note that we *also* check op_id doesn't change here below. This amounts to checking that the op_id read from memory is the one the state machine expects
        offset += P::ONES;
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[3][0] - (curr_row.pc + offset),
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[3][1] - next_row.op_id,
            opcode_is_new_entry,
        );
        // next content_len = [pc + 4]
        offset += P::ONES;
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[4][0] - (curr_row.pc + offset),
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            curr_row.input_memory[4][1] - next_row.content_len,
            opcode_is_new_entry,
        );

        // set next pc to pc + 5
        offset += P::ONES;
        yield_constr.constraint_transition_filtered(
            next_row.pc - (curr_row.pc + offset),
            opcode_is_new_entry,
        );
        // next count = 0
        yield_constr.constraint_transition_filtered(next_row.count, opcode_is_new_entry);
        // next list_count = 0
        yield_constr.constraint_transition_filtered(next_row.list_count, opcode_is_new_entry);

        // binary check is_list
        yield_constr.constraint_filtered((P::ONES - is_list) * is_list, opcode_is_new_entry);
        // if is_list and content len read from memory is 0, then transition to ListPrefix
        // else if is_list, transition to List
        // else if not is_list and content len is zero, transition to StrPrefix
        // else transition to StrPush
        let is_list_and_content_len_is_zero = is_list * next_row.content_len_is_zero;
        let is_list_and_content_len_is_nonzero = is_list * (P::ONES - next_row.content_len_is_zero);
        let is_not_list_and_content_len_is_zero =
            (P::ONES - is_list) * next_row.content_len_is_zero;
        let is_not_list_and_content_len_is_nonzero =
            (P::ONES - is_list) * (P::ONES - next_row.content_len_is_zero);
        yield_constr.constraint_transition_filtered(
            next_opcode_is_list_prefix - is_list_and_content_len_is_zero,
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_list - is_list_and_content_len_is_nonzero,
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_str_prefix - is_not_list_and_content_len_is_zero,
            opcode_is_new_entry,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_str_push - is_not_list_and_content_len_is_nonzero,
            opcode_is_new_entry,
        );

        // check content_len_is_zero via content_len_inv
        let prod = curr_row.content_len * curr_row.content_len_inv;
        // binary check content_len_is_zero
        yield_constr
            .constraint((P::ONES - curr_row.content_len_is_zero) * curr_row.content_len_is_zero);
        // if content_len_is_zero is set, then content_len and content_len_inv must both be zero
        yield_constr.constraint_filtered(curr_row.content_len, curr_row.content_len_is_zero);
        yield_constr.constraint_filtered(curr_row.content_len_inv, curr_row.content_len_is_zero);

        // if content_len_is_zero is not set, then prod must be 1
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.content_len_is_zero);

        // List

        // push current list count onto the stack
        yield_constr.constraint_filtered(curr_row.call_stack[0][0] - stack_push, opcode_is_list);
        yield_constr.constraint_filtered(
            curr_row.call_stack[0][1] - curr_row.list_count,
            opcode_is_list,
        );
        // read child addr from the table, push it on the stack
        yield_constr.constraint_filtered(curr_row.input_memory[0][0] - curr_row.pc, opcode_is_list);
        let child_addr = curr_row.input_memory[0][1];
        yield_constr.constraint_filtered(curr_row.call_stack[1][0] - stack_push, opcode_is_list);
        yield_constr.constraint_filtered(curr_row.call_stack[1][1] - child_addr, opcode_is_list);

        // increment pc
        yield_constr
            .constraint_transition_filtered(next_row.pc - (curr_row.pc + P::ONES), opcode_is_list);
        // increment list count
        yield_constr.constraint_transition_filtered(
            next_row.list_count - (curr_row.list_count + P::ONES),
            opcode_is_list,
        );

        // if next_row.list_count == next_row.content_len (next_row.content_len_minus_list_count_is_zero), then transition to Recurse
        // otherwise, transition to List
        yield_constr.constraint_transition_filtered(
            next_opcode_is_recurse - next_row.content_len_minus_list_count_is_zero,
            opcode_is_list,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_list - (P::ONES - next_row.content_len_minus_list_count_is_zero),
            opcode_is_list,
        );

        // check content_len_minus_list_count_is_zero via content_len_minus_list_count_inv
        let content_len_minus_list_count = curr_row.content_len - curr_row.list_count;
        let prod = content_len_minus_list_count * curr_row.content_len_minus_list_count_inv;
        // binary check content_len_minus_list_count_is_zero
        yield_constr.constraint(
            (P::ONES - curr_row.content_len_minus_list_count_is_zero)
                * curr_row.content_len_minus_list_count_is_zero,
        );
        // if content_len_minus_list_count_is_zero is set, then content_len_minus_list_count and content_len_minus_list_count_inv must both be zero
        yield_constr.constraint_filtered(
            content_len_minus_list_count,
            curr_row.content_len_minus_list_count_is_zero,
        );
        yield_constr.constraint_filtered(
            curr_row.content_len_minus_list_count_inv,
            curr_row.content_len_minus_list_count_is_zero,
        );
        // otherwise, prod must be 1
        yield_constr.constraint_filtered(
            P::ONES - prod,
            P::ONES - curr_row.content_len_minus_list_count_is_zero,
        );

        // Recurse

        // pop the "dst" address to jump to from the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[0][0] - stack_pop, opcode_is_recurse);
        let dst = curr_row.call_stack[0][1];

        // push count to the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[1][0] - stack_push, opcode_is_recurse);
        yield_constr.constraint_filtered(
            curr_row.call_stack[1][1] - curr_row.count,
            opcode_is_recurse,
        );

        // push pc to the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[2][0] - stack_push, opcode_is_recurse);
        yield_constr
            .constraint_filtered(curr_row.call_stack[2][1] - curr_row.pc, opcode_is_recurse);

        // set next pc to dst
        yield_constr.constraint_transition_filtered(next_row.pc - dst, opcode_is_recurse);
        // increment depth
        yield_constr.constraint_transition_filtered(
            next_row.depth - (curr_row.depth + P::ONES),
            opcode_is_recurse,
        );
        // transition to NewEntry
        yield_constr
            .constraint_transition_filtered(P::ONES - next_opcode_is_new_entry, opcode_is_recurse);

        // Return

        // pop "old_pc" from the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[0][0] - stack_pop, opcode_is_return);
        let old_pc = curr_row.call_stack[0][1];

        // pop "old count" from the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[1][0] - stack_pop, opcode_is_return);
        let old_count = curr_row.call_stack[1][1];

        // pop "old list count" from the call stack
        yield_constr.constraint_filtered(curr_row.call_stack[2][0] - stack_pop, opcode_is_return);
        let old_list_count = curr_row.call_stack[2][1];

        // add "old count" to count
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + old_count),
            opcode_is_return,
        );
        // set list_count to old_list_count
        yield_constr
            .constraint_transition_filtered(next_row.list_count - old_list_count, opcode_is_return);
        // set pc to old_pc
        yield_constr.constraint_transition_filtered(next_row.pc - old_pc, opcode_is_return);
        // decrement depth
        yield_constr.constraint_transition_filtered(
            next_row.depth - (curr_row.depth - P::ONES),
            opcode_is_return,
        );

        // if next row's list count (i.e. the one that was popped) is zero, then transition to ListPrefix
        // otherwise, transition to recurse
        yield_constr.constraint_transition_filtered(
            next_opcode_is_list_prefix - next_row.list_count_is_zero,
            opcode_is_return,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_recurse - (P::ONES - next_row.list_count_is_zero),
            opcode_is_return,
        );

        // check list_count_is_zero via list_count_inv
        let list_count = curr_row.list_count;
        let prod = list_count * curr_row.list_count_inv;
        // if list_count_is_zero is set, then list_count and list_count_inv must both be zero
        yield_constr.constraint_filtered(list_count, curr_row.list_count_is_zero);
        yield_constr.constraint_filtered(curr_row.list_count_inv, curr_row.list_count_is_zero);
        // otherwise, prod must be 1
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.list_count_is_zero);

        // StrPush
        // read val from input_memory at pc
        yield_constr.constraint_filtered(
            curr_row.input_memory[0][0] - curr_row.pc,
            opcode_is_str_push,
        );
        let val = curr_row.input_memory[0][1];
        // range check val to be a u8 by copying it into a range-checked cell
        yield_constr.constraint_filtered(curr_row.rc_u8s[0] - val, opcode_is_str_push);
        // increment pc
        yield_constr.constraint_filtered(next_row.pc - (curr_row.pc + P::ONES), opcode_is_str_push);
        // push val to output stack
        yield_constr.constraint_filtered(curr_row.output_stack[0][1] - val, opcode_is_str_push);
        // increment count
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + P::ONES),
            opcode_is_str_push,
        );
        // if content_len = next row's count (i.e. content_len_minus_count_is_zero), then transition to StrPrefix
        // otherwise, transition to StrPush
        yield_constr.constraint_transition_filtered(
            next_opcode_is_str_prefix - next_row.content_len_minus_count_is_zero,
            opcode_is_str_push,
        );
        yield_constr.constraint_transition_filtered(
            next_opcode_is_str_push - (P::ONES - next_row.content_len_minus_count_is_zero),
            opcode_is_str_push,
        );

        // check content_len_minus_count_is_zero via content_len_minus_count_inv
        let content_len_minus_count = curr_row.content_len - curr_row.count;
        let prod = content_len_minus_count * curr_row.content_len_minus_count_inv;
        // binary check content_len_minus_count_is_zero
        yield_constr.constraint(
            curr_row.content_len_minus_count_is_zero
                * (P::ONES - curr_row.content_len_minus_count_is_zero),
        );
        // if content_len_minus_count_is_zero is set, then content_len_minus_count and content_len_minus_count_inv must both be zero
        yield_constr.constraint_filtered(
            content_len_minus_count,
            curr_row.content_len_minus_count_is_zero,
        );
        yield_constr.constraint_filtered(
            curr_row.content_len_minus_count_inv,
            curr_row.content_len_minus_count_is_zero,
        );
        // otherwise, prod must be 1
        yield_constr.constraint_filtered(
            P::ONES - prod,
            P::ONES - curr_row.content_len_minus_count_is_zero,
        );

        // prefix case flags
        // binary check flags
        for i in 0..4 {
            yield_constr.constraint(
                (P::ONES - curr_row.prefix_case_flags[i]) * curr_row.prefix_case_flags[i],
            );
        }
        // binary check their sum
        let prefix_case_flag_sum = (0..4).map(|i| curr_row.prefix_case_flags[i]).sum::<P>();
        let next_prefix_case_flag_sum = (0..4).map(|i| next_row.prefix_case_flags[i]).sum::<P>();
        yield_constr.constraint((P::ONES - prefix_case_flag_sum) * prefix_case_flag_sum);

        // unpack
        let next_prefix_single_byte_case = P::ONES - next_prefix_case_flag_sum;
        let prefix_string_in_range_case = curr_row.prefix_case_flags[0];
        let prefix_string_out_of_range_case = curr_row.prefix_case_flags[1];
        let prefix_list_in_range_case = curr_row.prefix_case_flags[2];

        // check if count <= 55 using base-56 decomp
        let upper_limb_sum = (1..6).map(|i| curr_row.rc_56_limbs[i]).sum::<P>();
        let prod = upper_limb_sum * curr_row.upper_limbs_sum_inv;
        yield_constr.constraint((P::ONES - curr_row.count_in_range) * curr_row.count_in_range);
        yield_constr.constraint_filtered(upper_limb_sum, curr_row.count_in_range);
        yield_constr.constraint_filtered(curr_row.upper_limbs_sum_inv, curr_row.count_in_range);
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_in_range);

        // binary check log256 flags
        for i in 0..4 {
            yield_constr
                .constraint((P::ONES - curr_row.log256_flags[i]) * curr_row.log256_flags[i]);
        }
        // binary check their sum
        let log256_flag_sum = (0..4).map(|i| curr_row.log256_flags[i]).sum::<P>();
        yield_constr.constraint((P::ONES - log256_flag_sum) * log256_flag_sum);

        // unpack log256 flags
        let len_len_is_0 = P::ONES - log256_flag_sum;
        let len_len_is_1 = curr_row.log256_flags[0];
        let len_len_is_2 = curr_row.log256_flags[1];
        let len_len_is_3 = curr_row.log256_flags[2];
        let len_len_is_4 = curr_row.log256_flags[3];

        let is_calculating_prefix = opcode_is_str_prefix + opcode_is_list_prefix;
        // check len lens
        // if len len is 0, then count must be zero when calculating a prefix
        yield_constr.constraint_filtered(curr_row.count, len_len_is_0 * is_calculating_prefix);
        // if len len is 0, then every limb must be zero
        for i in 1..5 {
            yield_constr
                .constraint_filtered(curr_row.rc_u8s[i], len_len_is_0 * is_calculating_prefix);
        }
        // if len len is 1, then every limb but the least-significant one must be zero when calculating a prefix
        // AND the least-significant limb must be nonzero (checked via inverse)
        for i in 1..4 {
            yield_constr
                .constraint_filtered(curr_row.rc_u8s[i + 1], len_len_is_1 * is_calculating_prefix);
        }
        yield_constr.constraint_filtered(
            P::ONES - curr_row.rc_u8s[1] * curr_row.top_byte_inv,
            len_len_is_1,
        );

        // if len len is 2, then the upper two limbs must be zero when calculating a prefix
        // AND the second-least-significant limb must be nonzero (checked via inverse)
        for i in 2..4 {
            yield_constr
                .constraint_filtered(curr_row.rc_u8s[i + 1], len_len_is_2 * is_calculating_prefix);
        }
        yield_constr.constraint_filtered(
            P::ONES - curr_row.rc_u8s[2] * curr_row.top_byte_inv,
            len_len_is_2,
        );

        // if len len is 3, then the most significant limb must be zero
        // AND the second-most-significant limb must be nonzero (checked via inverse)
        yield_constr.constraint_filtered(curr_row.rc_u8s[4], len_len_is_3 * is_calculating_prefix);
        yield_constr.constraint_filtered(
            P::ONES - curr_row.rc_u8s[3] * curr_row.top_byte_inv,
            len_len_is_3,
        );

        // if len len is 4, then the most significant limb must be nonzero
        yield_constr.constraint_filtered(
            P::ONES - curr_row.rc_u8s[4] * curr_row.top_byte_inv,
            len_len_is_4,
        );

        // set tmps for str_prefix and list_prefix
        yield_constr.constraint(
            curr_row.prefix_case_tmp_3 - opcode_is_str_prefix * prefix_string_out_of_range_case,
        );

        // StrPrefix
        // check that count = content_len
        yield_constr
            .constraint_filtered(curr_row.count - curr_row.content_len, opcode_is_str_prefix);
        // prefix len cases:
        // if count is 1 and first byte in range 0..127: no prefix
        yield_constr.constraint_filtered(curr_row.count - P::ONES, curr_row.count_is_one);
        yield_constr.constraint_transition_filtered(
            P::ONES - next_row.count_is_one,
            next_opcode_is_str_prefix * next_prefix_single_byte_case,
        );
        let first_byte = curr_row.input_memory[0][1];
        yield_constr.constraint_transition_filtered(
            next_row.rc_127 - first_byte,
            next_opcode_is_str_prefix * next_prefix_single_byte_case,
        );
        // to prevent the prover from claiming it's the next case (not single byte) when it's actually this case
        // we place first_byte - 127 into the rc'd cell if the prover claims it's the next case AND count is 1
        yield_constr.constraint(
            curr_row.prefix_case_tmp
                - opcode_is_str_prefix * prefix_string_in_range_case * curr_row.count_is_one,
        );
        yield_constr.constraint_transition_filtered(
            next_row.rc_127 - (first_byte - FE::from_canonical_u8(0x80)),
            curr_row.prefix_case_tmp,
        );
        // check count_is_1 via inverse
        let count_minus_one = curr_row.count - P::ONES;
        let prod = count_minus_one * curr_row.count_minus_one_inv;
        // if count_is_one, then count_minus_1 = 0 and count_minus_1_inv = 0
        yield_constr.constraint_filtered(count_minus_one, curr_row.count_is_one);
        yield_constr.constraint_filtered(curr_row.count_minus_one_inv, curr_row.count_is_one);
        // if not count_is_one, then prod = 1
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_is_one);

        // else if count <=55 then prefix is 1 byte with value 0x80 + count
        // ensure count is in range if this mode is selected
        yield_constr.constraint_filtered(
            P::ONES - curr_row.count_in_range,
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        // set stack filters
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[4],
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[3],
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[2],
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[1],
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[0],
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        // push prefix to output stack
        let prefix = curr_row.count + FE::from_canonical_u8(0x80);
        yield_constr.constraint_filtered(
            curr_row.output_stack[4][1] - prefix,
            opcode_is_str_prefix * prefix_string_in_range_case,
        );

        // else if count >55 and log256_is_1 then prefix is 2 bytes with value 0xB8, count. log256_is_2 => 3 bytes, etc
        // ensure count is not in range if this mode is selected
        yield_constr.constraint_filtered(curr_row.count_in_range, curr_row.prefix_case_tmp_3);
        // ensure log256_is_1 if this mode is selected
        yield_constr.constraint_filtered(P::ONES - len_len_is_1, curr_row.prefix_case_tmp_3);
        // set stack filters
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[4],
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[3],
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[2] - len_len_is_2 - len_len_is_3 - len_len_is_4,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[1] - len_len_is_3 - len_len_is_4,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[0] - len_len_is_4,
            curr_row.prefix_case_tmp_3,
        );
        // push prefix to output stack
        let first_byte = len_len_is_1 * FE::from_canonical_u8(0xB8)
            + len_len_is_2 * FE::from_canonical_u8(0xB9)
            + len_len_is_3 * FE::from_canonical_u8(0xBA)
            + len_len_is_4 * FE::from_canonical_u8(0xBB);
        let second_byte = len_len_is_1 * curr_row.rc_u8s[1]
            + len_len_is_2 * curr_row.rc_u8s[2]
            + len_len_is_3 * curr_row.rc_u8s[3]
            + len_len_is_4 * curr_row.rc_u8s[4];
        let third_byte = len_len_is_2 * curr_row.rc_u8s[1]
            + len_len_is_3 * curr_row.rc_u8s[2]
            + len_len_is_4 * curr_row.rc_u8s[3];
        let fourth_byte = len_len_is_3 * curr_row.rc_u8s[1] + len_len_is_4 * curr_row.rc_u8s[2];
        let fifth_byte = len_len_is_4 * curr_row.rc_u8s[1];
        yield_constr.constraint_filtered(
            curr_row.output_stack[0][1] - fifth_byte,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[1][1] - fourth_byte,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[2][1] - third_byte,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[3][1] - second_byte,
            curr_row.prefix_case_tmp_3,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[4][1] - first_byte,
            curr_row.prefix_case_tmp_3,
        );

        // increment count by number of bytes in prefix
        // since we need to distinguish between the single byte case and the <=55 case, we appyl this constraint via the "next" row
        let prefix_len = len_len_is_1 * FE::from_canonical_u8(2)
            + len_len_is_2 * FE::from_canonical_u8(3)
            + len_len_is_3 * FE::from_canonical_u8(4)
            + len_len_is_4 * FE::from_canonical_u8(5);
        let next_prefix_string_in_range_case = next_row.prefix_case_flags[0];
        yield_constr.constraint_transition(
            next_row.prefix_case_tmp_2
                - next_opcode_is_str_prefix
                    * (P::ONES - next_prefix_single_byte_case)
                    * (P::ONES - next_prefix_string_in_range_case),
        );
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + prefix_len),
            curr_row.prefix_case_tmp_2,
        );
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + P::ONES),
            opcode_is_str_prefix * prefix_string_in_range_case,
        );
        // don't change count in single byte case

        // ListPrefix
        // if count is <= 55 then prefix is 0xC0 + count
        yield_constr.constraint_filtered(
            P::ONES - curr_row.count_in_range,
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        // set stack filters
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[4],
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[3],
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[2],
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[1],
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[0],
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        // push prefix to output stack
        let prefix = curr_row.count + FE::from_canonical_u8(0xC0);
        yield_constr.constraint_filtered(
            curr_row.output_stack[4][1] - prefix,
            opcode_is_list_prefix * prefix_list_in_range_case,
        );

        // else if count >55 and log256_is_1 then prefix is 2 bytes with value 0xF8, count. log256_is_2 => 3 bytes, etc
        // ensure count not in range if this mode is selected
        yield_constr.constraint_filtered(curr_row.count_in_range, curr_row.prefix_case_tmp_4);
        // set stack filters
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[4],
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            P::ONES - curr_row.output_stack_filters[3],
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[2] - len_len_is_2 - len_len_is_3 - len_len_is_4,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[1] - len_len_is_3 - len_len_is_4,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack_filters[0] - len_len_is_4,
            curr_row.prefix_case_tmp_4,
        );
        // push prefix to output stack
        let first_byte = len_len_is_1 * FE::from_canonical_u8(0xF8)
            + len_len_is_2 * FE::from_canonical_u8(0xF9)
            + len_len_is_3 * FE::from_canonical_u8(0xFA)
            + len_len_is_4 * FE::from_canonical_u8(0xFB);
        yield_constr.constraint_filtered(
            curr_row.output_stack[0][1] - fifth_byte,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[1][1] - fourth_byte,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[2][1] - third_byte,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[3][1] - second_byte,
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[4][1] - first_byte,
            curr_row.prefix_case_tmp_4,
        );

        // increment count by number of bytes in prefix
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + prefix_len),
            curr_row.prefix_case_tmp_4,
        );
        yield_constr.constraint_transition_filtered(
            next_row.count - (curr_row.count + P::ONES),
            opcode_is_list_prefix * prefix_list_in_range_case,
        );
        // don't change count in single byte case

        // EndEntry
        // check depth_is_zero via inv check
        // binary check depth_is_zero
        yield_constr.constraint((P::ONES - curr_row.depth_is_zero) * curr_row.depth_is_zero);
        let prod = curr_row.depth * curr_row.depth_inv;
        // if depth_is_zero, then both depth and depth_inv must be zero
        yield_constr.constraint_filtered(curr_row.depth, curr_row.depth_is_zero);
        yield_constr.constraint_filtered(curr_row.depth_inv, curr_row.depth_is_zero);
        // otherwise, prod must be 1
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.depth_is_zero);

        // if depth is zero, push count and op_id to the stack
        yield_constr.constraint_filtered(
            curr_row.output_stack[0][1] - curr_row.count,
            is_end_entry_and_depth_is_zero,
        );
        yield_constr.constraint_filtered(
            curr_row.output_stack[1][1] - curr_row.op_id,
            is_end_entry_and_depth_is_zero,
        );
        // increment op_id
        yield_constr.constraint_transition_filtered(
            next_row.op_id - (curr_row.op_id + P::ONES),
            is_end_entry_and_depth_is_zero,
        );
        // otherwisem, op_id should stay the same
        yield_constr.constraint_transition_filtered(
            next_row.op_id - curr_row.op_id,
            P::ONES - is_end_entry_and_depth_is_zero,
        );
        // binary check is_last
        yield_constr.constraint((P::ONES - curr_row.is_last) * curr_row.is_last);

        // if depth is not zero, transition to Return
        // else if depth is is_last, then transition to Halt
        // else, set pc to next and transition to NewEntry
        yield_constr.constraint(curr_row.end_entry_tmp - is_end_entry_and_depth_is_zero);
        yield_constr.constraint_transition_filtered(
            P::ONES - next_opcode_is_return,
            (P::ONES - curr_row.depth_is_zero) * opcode_is_end_entry,
        );
        yield_constr.constraint_transition_filtered(
            P::ONES - next_opcode_is_halt,
            curr_row.end_entry_tmp * curr_row.is_last,
        );
        yield_constr.constraint_transition_filtered(
            next_row.pc - curr_row.next,
            curr_row.end_entry_tmp * (P::ONES - curr_row.is_last),
        );

        // Halt
        // nothing should change during halt
        // EXCEPT for the first halt row, during which we set the output_stack[0] = curr_output_stack.len() - 1. so that the consumer can consume the output as a "stack"
        // and be guaranteed that the "len" is set correctly
        let next_is_first_halt = (P::ONES - opcode_is_halt) * next_opcode_is_halt;
        yield_constr.constraint_transition_filtered(
            P::ONES - next_row.output_stack_filters[0],
            next_is_first_halt,
        );
        yield_constr
            .constraint_transition_filtered(next_row.output_stack[0][0], next_is_first_halt);
        yield_constr.constraint_transition_filtered(
            next_row.output_stack[0][1] - curr_row.output_stack[4][0],
            next_is_first_halt,
        );

        yield_constr
            .constraint_transition_filtered(curr_row.op_id - next_row.op_id, opcode_is_halt);
        yield_constr.constraint_transition_filtered(curr_row.pc - next_row.pc, opcode_is_halt);
        yield_constr
            .constraint_transition_filtered(curr_row.count - next_row.count, opcode_is_halt);
        yield_constr.constraint_transition_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_halt,
        );
        yield_constr.constraint_transition_filtered(
            curr_row.list_count - next_row.list_count,
            opcode_is_halt,
        );
        yield_constr
            .constraint_transition_filtered(curr_row.depth - next_row.depth, opcode_is_halt);
        yield_constr.constraint_transition_filtered(curr_row.next - next_row.next, opcode_is_halt);
        for i in 0..8 {
            yield_constr.constraint_transition_filtered(
                curr_row.opcode[i] - next_row.opcode[i],
                opcode_is_halt,
            );
        }

        // base-56 decomp
        let recomp = (0..6).rev().fold(P::ZEROS, |acc, i| {
            acc * FE::from_canonical_u8(56) + curr_row.rc_56_limbs[i]
        });
        yield_constr.constraint(curr_row.count - recomp);
        for (i, j) in rc_56_permuted_cols().zip(lut_56_permuted_cols()) {
            eval_lookups(&vars, yield_constr, i, j);
        }

        // byte decomp
        let recomp = (0..4)
            .map(|i| curr_row.rc_u8s[i + 1] * FE::from_canonical_u64(1 << (i * 8)))
            .sum::<P>();
        yield_constr.constraint(curr_row.count - recomp);
        for (i, j) in rc_u8_permuted_cols().zip(lut_u8_permuted_cols()) {
            eval_lookups(&vars, yield_constr, i, j);
        }

        // 7-bit (127) lookup
        eval_lookups(
            &vars,
            yield_constr,
            rc_127_permuted_col(),
            lut_127_permuted_col(),
        );

        // build luts

        // counters start at 0
        yield_constr.constraint_first_row(curr_row.count_127);
        yield_constr.constraint_first_row(curr_row.count_u8);
        yield_constr.constraint_first_row(curr_row.count_56);

        // if count_127_is_127, set it to 0, otherwise increment it
        yield_constr.constraint_transition_filtered(next_row.count_127, curr_row.count_127_is_127);
        yield_constr.constraint_transition_filtered(
            next_row.count_127 - curr_row.count_127 - P::ONES,
            P::ONES - curr_row.count_127_is_127,
        );

        // if count_u8_is_255, set it to 0, otherwise increment it
        yield_constr.constraint_transition_filtered(next_row.count_u8, curr_row.count_u8_is_255);
        yield_constr.constraint_transition_filtered(
            next_row.count_u8 - curr_row.count_u8 - P::ONES,
            P::ONES - curr_row.count_u8_is_255,
        );

        // if count_56_is_55, set it to 0, otherwise increment it
        yield_constr.constraint_transition_filtered(next_row.count_56, curr_row.count_56_is_55);
        yield_constr.constraint_transition_filtered(
            next_row.count_56 - curr_row.count_56 - P::ONES,
            P::ONES - curr_row.count_56_is_55,
        );

        // check count_127_is_127 via inv
        let count_127_minus_127 = curr_row.count_127 - FE::from_canonical_u64(127);
        let prod = count_127_minus_127 * curr_row.count_127_minus_127_inv;
        // binary check count_127_is_127
        yield_constr.constraint((P::ONES - curr_row.count_127_is_127) * curr_row.count_127_is_127);

        // if count_127_is_127 is set, then both count_127_minus_127 and its inv must be zero
        yield_constr.constraint_filtered(count_127_minus_127, curr_row.count_127_is_127);
        yield_constr
            .constraint_filtered(curr_row.count_127_minus_127_inv, curr_row.count_127_is_127);
        // otherwise, prod must be one
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_127_is_127);

        // check count_u8_is_255 via inv
        let count_u8_minus_255 = curr_row.count_u8 - FE::from_canonical_u8(255);
        let prod = count_u8_minus_255 * curr_row.count_u8_minus_255_inv;
        // binary count_u8_is_255
        yield_constr.constraint((P::ONES - curr_row.count_u8_is_255) * curr_row.count_u8_is_255);
        // if count_u8_is_255 is set, then both count_u8_minus_255 and its inv must be zero
        yield_constr.constraint_filtered(count_u8_minus_255, curr_row.count_u8_is_255);
        yield_constr.constraint_filtered(curr_row.count_u8_minus_255_inv, curr_row.count_u8_is_255);
        // otherwise, prod must be one
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_u8_is_255);

        // check count_56_is_55 via inv
        let count_56_minus_55 = curr_row.count_56 - FE::from_canonical_u8(55);
        let prod = count_56_minus_55 * curr_row.count_56_minus_55_inv;
        // binary check count_56_is_55
        yield_constr.constraint((P::ONES - curr_row.count_56_is_55) * curr_row.count_56_is_55);
        // if count_56_is_55 is set, then both count_56_minus_55 and its inv must be zero
        yield_constr.constraint_filtered(count_56_minus_55, curr_row.count_56_is_55);
        yield_constr.constraint_filtered(curr_row.count_56_minus_55_inv, curr_row.count_56_is_55);
        // otherwise, prod must be one
        yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_56_is_55);

        // ensure things that shouldn't change stay the same
        // NewEntry
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_new_entry);

        // List
        // count should stay the same
        yield_constr.constraint_filtered(curr_row.count - next_row.count, opcode_is_list);
        // content_len should stay the same
        yield_constr
            .constraint_filtered(curr_row.content_len - next_row.content_len, opcode_is_list);
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_list);
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_list);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_list);

        // StrPush
        // content_len should tsay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_str_push,
        );
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_str_push);
        // list_count should stay the same
        yield_constr.constraint_filtered(
            curr_row.list_count - next_row.list_count,
            opcode_is_str_push,
        );
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_str_push);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_str_push);

        // ListPrefix
        // pc should stay the same
        yield_constr.constraint_filtered(curr_row.pc - next_row.pc, opcode_is_list_prefix);
        // content_len should stay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_list_prefix,
        );
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_list_prefix);
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_list_prefix);
        // is_last should stay the same
        yield_constr
            .constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_list_prefix);
        // list_count should stay the same
        yield_constr.constraint_filtered(
            curr_row.list_count - next_row.list_count,
            opcode_is_list_prefix,
        );

        // StrPrefix
        // pc should stay the same
        yield_constr.constraint_filtered(curr_row.pc - next_row.pc, opcode_is_str_prefix);
        // content_len should stay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_str_prefix,
        );
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_str_prefix);
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_str_prefix);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_str_prefix);
        // list_count should stay the same
        yield_constr.constraint_filtered(
            curr_row.list_count - next_row.list_count,
            opcode_is_str_prefix,
        );

        // Recurse
        // content_len should stay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_recurse,
        );
        // list_count should stay the same
        yield_constr
            .constraint_filtered(curr_row.list_count - next_row.list_count, opcode_is_recurse);
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_recurse);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_recurse);

        // Return
        // content_len should stay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_return,
        );
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_return);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_return);

        // EndEntry
        // content_len should stay the same
        yield_constr.constraint_filtered(
            curr_row.content_len - next_row.content_len,
            opcode_is_end_entry,
        );
        // count should stay the same
        yield_constr.constraint_filtered(curr_row.count - next_row.count, opcode_is_end_entry);
        // next should stay the same
        yield_constr.constraint_filtered(curr_row.next - next_row.next, opcode_is_end_entry);
        // is_last should stay the same
        yield_constr.constraint_filtered(curr_row.is_last - next_row.is_last, opcode_is_end_entry);
        // depth should stay the same
        yield_constr.constraint_filtered(curr_row.depth - next_row.depth, opcode_is_end_entry);
        // list_count should stay the same
        yield_constr.constraint_filtered(
            curr_row.list_count - next_row.list_count,
            opcode_is_end_entry,
        );
    }

    fn eval_ext_circuit(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
        _vars: StarkEvaluationTargets<D>,
        _yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::stark_testing::test_stark_low_degree;
    use crate::starky2lib::rlp::generation::{RlpItem, RlpStarkGenerator};
    use crate::verifier::verify_stark_proof_no_ctl;

    fn test_rlp_items() -> Vec<RlpItem> {
        vec![
            RlpItem::List(vec![]),
            RlpItem::Str(vec![]),
            RlpItem::Str(vec![0x08]),
            RlpItem::list_from_vec(vec![
                RlpItem::list_from_vec(vec![
                    RlpItem::Str(b"let everything happen to you".to_vec()),
                    RlpItem::Str(b"beauty and terror".to_vec()),
                    RlpItem::Str(b"just keep going".to_vec()),
                    RlpItem::Str(b"no feeling is final".to_vec()),
                ]),
                RlpItem::Str(b"Rainer Maria Rilke".to_vec()),
            ]),
            RlpItem::list_from_vec(vec![
                RlpItem::list_from_vec(vec![
                    RlpItem::Str(b"If I send this void away".to_vec()),
                    RlpItem::Str(b"Have I lost a part of me?".to_vec()),
                    RlpItem::Str(b"When you wake you're bargaining".to_vec()),
                    RlpItem::Str(b"For the promise to come back".to_vec()),
                ]),
                RlpItem::list_from_vec(vec![
                    RlpItem::Str(b"'Cause getting made you want more".to_vec()),
                    RlpItem::Str(b"And hoping made you hurt more".to_vec()),
                    RlpItem::Str(b"Oh there must be".to_vec()),
                    RlpItem::Str(b"Something wrong with me".to_vec()),
                    RlpItem::Str(b"And getting made you want more".to_vec()),
                    RlpItem::Str(b"And hoping made you hurt more".to_vec()),
                    RlpItem::Str(b"Someone tell me".to_vec()),
                    RlpItem::Str(b"Something comforting".to_vec()),
                ]),
                RlpItem::Str(
                    b"Something comforting
						Something comforting
						Something comforting
						Something comforting
						Something comforting
						Something comforting
						Something comforting
						Something comforting"
                        .to_vec(),
                ),
            ]),
        ]
    }

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = RlpStark<F, D>;

        let stark = S::new();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_rlp_stark() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = RlpStark<F, D>;

        let mut generator = RlpStarkGenerator::new();
        let items = test_rlp_items();
        generator.generate(&items);

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, &[], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)?;
        Ok(())
    }
}
