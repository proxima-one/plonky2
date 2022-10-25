/// STARK that checks rlp encodings using two memories
use plonky2::field::{
	extension::{Extendable, FieldExtension},
	packed::PackedField
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use std::marker::PhantomData;
use std::borrow::Borrow;
use crate::{stark::Stark, lookup::eval_lookups};
use crate::vars::{StarkEvaluationVars, StarkEvaluationTargets};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

pub mod layout;
pub mod generation;

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

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for RlpStark<F, D> {
	const COLUMNS: usize = layout::RLP_NUM_COLS;
	const PUBLIC_INPUTS: usize = 0;

	fn eval_packed_generic<FE, P, const D2: usize>(
		&self,
		vars: crate::vars::StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
		yield_constr: &mut crate::constraint_consumer::ConstraintConsumer<P>,
	) where
		FE: FieldExtension<D2, BaseField = F>,
		P: PackedField<Scalar = FE>
	{
		let stack_pop = P::ONES;
		let stack_push = P::ZEROS;

		let curr_row: &RlpRow<P> = vars.local_values.borrow();
		let next_row: &RlpRow<P> = vars.next_values.borrow();

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
		let next_opcode_is_end_entry = next_row.opcode[6];
		let next_opcode_is_halt = next_row.opcode[7];

		// initial opcode is new entry
		yield_constr.constraint_first_row(P::ONES - opcode_is_new_entry);

		// binary check input memory ctl filters
		for i in 0..5 {
			yield_constr.constraint((P::ONES - curr_row.input_memory_filters[i]) * curr_row.input_memory_filters[i]);
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
		for i in 0..5 {
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

		// set output stack filters according to current opcode
		// NewEntry: None,
		// List: None,
		// Recurse: None,
		// Return: None,
		// StrPush: 0,
		// StrPrefix: filters checked separately
		// ListPrefix: filters checked separately 
		// EndEntry: 0..1 if depth_is_zero (checked below)
		// Halt: None
		// prefix flags are checked below
		let is_end_entry_and_depth_is_zero = opcode_is_end_entry * curr_row.depth_is_zero;
		let prefix_flag_sum = (0..4).map(|i| curr_row.prefix_case_flags[i]).sum::<P>();
		let set_filter_0 = opcode_is_str_push + is_end_entry_and_depth_is_zero
			+ prefix_flag_sum * (opcode_is_str_prefix + opcode_is_list_prefix);
		let set_filter_1 = is_end_entry_and_depth_is_zero;
		yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[0], set_filter_0);
		yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[1], set_filter_1);

		// NewEntry

		// read entry metadata from input memory
		// next next = [pc]
		yield_constr.constraint(curr_row.input_memory[0][0] - curr_row.pc);
		yield_constr.constraint_transition_filtered(curr_row.input_memory[0][1] - next_row.next, opcode_is_new_entry);
		// next is_last = [pc + 1]
		let mut offset = P::ONES;
		yield_constr.constraint_transition_filtered(curr_row.input_memory[1][0] - (curr_row.pc + offset), opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(curr_row.input_memory[1][1] - next_row.is_last, opcode_is_new_entry);
		// is_list = [pc + 2]
		offset += P::ONES;
		yield_constr.constraint_transition_filtered(curr_row.input_memory[2][1] - (curr_row.pc + offset), opcode_is_new_entry);
		let is_list = curr_row.input_memory[2][2];
		// next op_id = [pc + 3]
		offset += P::ONES;
		yield_constr.constraint_transition_filtered(curr_row.input_memory[3][0] - (curr_row.pc + offset), opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(curr_row.input_memory[3][1] - next_row.op_id, opcode_is_new_entry);
		// next content_len = [pc + 4]
		offset += P::ONES;
		yield_constr.constraint_transition_filtered(curr_row.input_memory[4][0] - (curr_row.pc + offset), opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(curr_row.input_memory[4][1] - next_row.content_len, opcode_is_new_entry);

		// set next pc to pc + 5
		offset += P::ONES;
		yield_constr.constraint_transition_filtered(next_row.pc - (curr_row.pc + offset), opcode_is_new_entry);
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
		let is_not_list_and_content_len_is_zero = (P::ONES - is_list) * next_row.content_len_is_zero;
		let is_not_list_and_content_len_is_nonzero = (P::ONES - is_list) * (P::ONES - next_row.content_len_is_zero);
		let is_not_list = P::ONES - is_list;
		yield_constr.constraint_transition_filtered(next_opcode_is_list_prefix - is_list_and_content_len_is_zero, opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(next_opcode_is_list - is_list_and_content_len_is_nonzero, opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(next_opcode_is_str_prefix - is_not_list_and_content_len_is_zero, opcode_is_new_entry);
		yield_constr.constraint_transition_filtered(next_opcode_is_str_push - is_not_list_and_content_len_is_nonzero, opcode_is_new_entry);		

		// check content_len_is_zero via content_len_inv
		let prod = curr_row.content_len * curr_row.content_len_inv;
		// binary check prod
		yield_constr.constraint((P::ONES - prod) * prod);
		// if content_len_is_zero is set, then content_len and content_len_inv must both be zero
		yield_constr.constraint_filtered(curr_row.content_len, curr_row.content_len_is_zero);
		yield_constr.constraint_filtered(curr_row.content_len_inv, curr_row.content_len_is_zero);

		// if content_len_is_zero is not set, then prod must be 1
		yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.content_len_is_zero);

		// List

		// push current list count onto the stack
		yield_constr.constraint_filtered(curr_row.call_stack[0][0] - stack_push, opcode_is_list);
		yield_constr.constraint_filtered(curr_row.call_stack[0][1] - curr_row.list_count, opcode_is_list);
		// read child addr from the table, push it on the stack
		yield_constr.constraint_filtered(curr_row.input_memory[0][0] - curr_row.pc, opcode_is_list);
		let child_addr = curr_row.input_memory[0][1];
		yield_constr.constraint_filtered(curr_row.call_stack[1][0] - stack_push, opcode_is_list);
		yield_constr.constraint_filtered(curr_row.call_stack[1][1] - child_addr, opcode_is_list);

		// increment pc
		yield_constr.constraint_transition_filtered(next_row.pc - (curr_row.pc + P::ONES), opcode_is_list);
		// increment list count
		yield_constr.constraint_transition_filtered(next_row.list_count - (curr_row.list_count + P::ONES), opcode_is_list);

		// if next_row.list_count == next_row.content_len (next_row.content_len_minus_list_count_is_zero), then transition to Recurse
		// otherwise, transition to List
		yield_constr.constraint_transition_filtered(next_opcode_is_recurse - next_row.content_len_minus_list_count_is_zero, opcode_is_list);
		yield_constr.constraint_transition_filtered(next_opcode_is_list - (P::ONES - next_row.content_len_minus_list_count_is_zero), opcode_is_list);

		// check content_len_minus_list_count_is_zero via content_len_minus_list_count_inv
		let content_len_minus_list_count = next_row.content_len - next_row.list_count;
		let prod = content_len_minus_list_count * curr_row.content_len_minus_list_count_inv;
		// binary check prod
		yield_constr.constraint((P::ONES - prod) * prod);
		// if content_len_minus_list_count_is_zero is set, then content_len_minus_list_count and content_len_minus_list_count_inv must both be zero
		yield_constr.constraint_filtered(content_len_minus_list_count, curr_row.content_len_minus_list_count_is_zero);
		yield_constr.constraint_filtered(curr_row.content_len_minus_list_count_inv, curr_row.content_len_minus_list_count_is_zero);
		// otherwise, prod must be 1
		yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.content_len_minus_list_count_is_zero);

		// Recurse

		// pop the "dst" address to jump to from the call stack
		yield_constr.constraint_filtered(curr_row.call_stack[0][0] - stack_pop, opcode_is_recurse);
		let dst = curr_row.call_stack[0][1];
		
		// push count to the call stack
		yield_constr.constraint_filtered(curr_row.call_stack[1][0] - stack_push, opcode_is_recurse);
		yield_constr.constraint_filtered(curr_row.call_stack[1][1] - curr_row.list_count, opcode_is_recurse);

		// push pc to the call stack
		yield_constr.constraint_filtered(curr_row.call_stack[2][0] - stack_push, opcode_is_recurse);
		yield_constr.constraint_filtered(curr_row.call_stack[2][1] - curr_row.pc, opcode_is_recurse);

		// set next pc to dst
		yield_constr.constraint_transition_filtered(next_row.pc - dst, opcode_is_recurse);
		// increment depth
		yield_constr.constraint_transition_filtered(next_row.depth - (curr_row.depth + P::ONES), opcode_is_recurse);
		// transition to NewEntry
		yield_constr.constraint_transition_filtered(next_opcode_is_new_entry, opcode_is_recurse);

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
		yield_constr.constraint_transition_filtered(next_row.count - (curr_row.count + old_count), opcode_is_return);
		// set list_count to old_list_count
		yield_constr.constraint_transition_filtered(next_row.list_count - old_list_count, opcode_is_return);
		// set pc to old_pc
		yield_constr.constraint_transition_filtered(next_row.pc - old_pc, opcode_is_return);
		// decrement depth
		yield_constr.constraint_transition_filtered(next_row.depth - (curr_row.depth - P::ONES), opcode_is_return);

		// if next row's list count (i.e. the one that was popped) is zero, then transition to ListPrefix
		// otherwise, transition to recurse
		yield_constr.constraint_transition_filtered(next_opcode_is_list_prefix - next_row.list_count_is_zero, opcode_is_return);
		yield_constr.constraint_transition_filtered(next_opcode_is_recurse - (P::ONES - next_row.list_count_is_zero), opcode_is_return);

		// check list_count_is_zero via list_count_inv
		let list_count = next_row.list_count;
		let prod = list_count * curr_row.list_count_inv;
		// binary check prod
		yield_constr.constraint((P::ONES - prod) * prod);
		// if list_count_is_zero is set, then list_count and list_count_inv must both be zero
		yield_constr.constraint_filtered(list_count, curr_row.list_count_is_zero);
		yield_constr.constraint_filtered(curr_row.list_count_inv, curr_row.list_count_is_zero);
		// otherwise, prod must be 1
		yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.list_count_is_zero);

		// StrPush
		// read val from input_memory at pc
		yield_constr.constraint_filtered(curr_row.input_memory[0][0] - curr_row.pc, opcode_is_str_push);
		let val = curr_row.input_memory[0][1];
		// range check val to be a u8 by copying it into a range-checked cell
		yield_constr.constraint_filtered(curr_row.rc_u8s[0] - val, opcode_is_str_push);
		// increment pc
		yield_constr.constraint_filtered(next_row.pc - (curr_row.pc + P::ONES), opcode_is_str_push);
		// push val to output stack
		yield_constr.constraint_filtered(next_row.output_stack[0][0] - stack_push, opcode_is_str_push);
		yield_constr.constraint_filtered(next_row.output_stack[0][1] - val, opcode_is_str_push);
		// increment count
		yield_constr.constraint_transition_filtered(next_row.count - (curr_row.count + P::ONES), opcode_is_str_push);
		// if content_len = next row's count (i.e. content_len_minus_count_is_zero), then transition to StrPrefix
		// otherwise, transition to StrPush
		yield_constr.constraint_transition_filtered(next_opcode_is_str_prefix - next_row.content_len_minus_count_is_zero, opcode_is_str_push);
		yield_constr.constraint_transition_filtered(next_opcode_is_str_push - (P::ONES - next_row.content_len_minus_count_is_zero), opcode_is_str_push);

		// check content_len_minus_count_is_zero via content_len_minus_count_inv
		let content_len_minus_count = next_row.content_len - next_row.count;
		let prod = content_len_minus_count * curr_row.content_len_minus_count_inv;
		// binary check prod
		yield_constr.constraint((P::ONES - prod) * prod);
		// if content_len_minus_count_is_zero is set, then content_len_minus_count and content_len_minus_count_inv must both be zero
		yield_constr.constraint_filtered(content_len_minus_count, curr_row.content_len_minus_count_is_zero);
		yield_constr.constraint_filtered(curr_row.content_len_minus_count_inv, curr_row.content_len_minus_count_is_zero);
		// otherwise, prod must be 1
		yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.content_len_minus_count_is_zero);

		// prefix case flags
		// binary check flags
		for i in 0..4 {
			yield_constr.constraint((P::ONES - curr_row.prefix_case_flags[i]) * curr_row.prefix_case_flags[i]);
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
		let prefix_list_out_of_range_case = curr_row.prefix_case_flags[3];

		// check if count <= 55 using base-55 decomp
		let upper_limb_sum = (1..6).map(|i| curr_row.rc_55_limbs[i]).sum::<P>();
		let prod = upper_limb_sum * curr_row.upper_limbs_sum_inv;
		yield_constr.constraint((P::ONES - prod) * prod);
		yield_constr.constraint_filtered(upper_limb_sum, curr_row.count_in_range);
		yield_constr.constraint_filtered(curr_row.upper_limbs_sum_inv, curr_row.count_in_range);
		yield_constr.constraint_filtered(P::ONES - prod, P::ONES - curr_row.count_in_range);

		// binary check log256 flags
		for i in 0..4 {
			yield_constr.constraint((P::ONES - curr_row.log256_flags[i]) * curr_row.log256_flags[i]);
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

		// check len lens
		// if len len is 0, then count must be zero
		yield_constr.constraint_filtered(curr_row.count, len_len_is_0);
		// if len len is 0, then every limb must be zero
		for i in 0..4 {
			yield_constr.constraint_filtered(curr_row.rc_u8s[i + 1], len_len_is_0);
		}
		// if len len is 1, then every limb but the least-significant one must be zero
		// AND the least-significant limb must be nonzero (checked via inverse)
		for i in 1..4 {
			yield_constr.constraint_filtered(curr_row.rc_u8s[i + 1], len_len_is_1);
		}
		yield_constr.constraint_filtered(P::ONES - curr_row.rc_u8s[1] * curr_row.top_byte_inv, len_len_is_1);

		// if len len is 2, then the upper two limbs must be zero
		// AND the second-least-significant limb must be nonzero (checked via inverse)
		for i in 2..4 {
			yield_constr.constraint_filtered(curr_row.rc_u8s[i + 1], len_len_is_2);
		}
		yield_constr.constraint_filtered(P::ONES - curr_row.rc_u8s[2] * curr_row.top_byte_inv, len_len_is_2);

		// if len len is 3, then the most significant limb must be zero
		// AND the second-most-significant limb must be nonzero (checked via inverse)
		yield_constr.constraint_filtered(curr_row.rc_u8s[5], len_len_is_3);
		yield_constr.constraint_filtered(P::ONES - curr_row.rc_u8s[4] * curr_row.top_byte_inv, len_len_is_3);

		// if len len is 4, then the most significant limb must be nonzero
		yield_constr.constraint_filtered(P::ONES - curr_row.rc_u8s[5] * curr_row.top_byte_inv, len_len_is_4);


		// StrPrefix
		// check that count = content_len
		yield_constr.constraint_filtered(curr_row.count - curr_row.content_len, opcode_is_str_prefix);
		// prefix len cases:
		// if count is 1 and first byte in range 0..127: no prefix
		yield_constr.constraint_filtered(curr_row.count - P::ONES, curr_row.count_is_one);
		yield_constr.constraint_transition_filtered(P::ONES - next_row.count_is_one, next_prefix_single_byte_case);
		let first_byte = curr_row.input_memory[0][1];
		yield_constr.constraint_transition_filtered(next_row.rc_127 - first_byte, opcode_is_str_prefix * next_prefix_single_byte_case);
		// to prevent the prover from claiming it's the next case (not single byte) when it's actually this case
		// we place first_byte - 127 into the rc'd cell if the prover claims it's the next case AND count is 1
		yield_constr.constraint(curr_row.prefix_case_tmp - opcode_is_str_prefix * prefix_string_in_range_case * curr_row.count_is_one);
		yield_constr.constraint_transition_filtered(next_row.rc_127 - (first_byte - FE::from_canonical_u8(0x80)), curr_row.prefix_case_tmp);
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
		yield_constr.constraint_filtered(P::ONES - curr_row.count_in_range, opcode_is_str_prefix * prefix_string_in_range_case);
		// set stack filters
		yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[0], opcode_is_str_prefix * prefix_string_in_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack_filters[1], opcode_is_str_prefix * prefix_string_in_range_case);
		// push prefix to output stack
		let prefix = curr_row.count + FE::from_canonical_u8(0x80);
		yield_constr.constraint_filtered(curr_row.output_stack[0][0] - stack_push, opcode_is_str_prefix * prefix_string_in_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[0][1] - prefix, opcode_is_str_prefix * prefix_string_in_range_case);

		// else if count >55 and log256_is_1 then prefix is 2 bytes with value 0xB8, count. log256_is_2 => 3 bytes, etc
		// ensure count is not in range if this mode is selected
		yield_constr.constraint_filtered(curr_row.count_in_range, opcode_is_str_prefix * prefix_string_out_of_range_case);
		// ensure log256_is_1 if this mode is selected
		yield_constr.constraint_filtered(P::ONES - len_len_is_1, opcode_is_str_prefix * prefix_string_out_of_range_case);
		// set stack filters
		yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[0], opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(P::ONES - curr_row.output_stack_filters[4], opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack_filters[3] - len_len_is_2 - len_len_is_3 - len_len_is_4, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack_filters[2] - len_len_is_3 - len_len_is_4, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack_filters[1] - len_len_is_4, opcode_is_str_prefix * prefix_string_out_of_range_case);
		// push prefix to output stack
		// TODO: timestamps for stack ops
		let first_byte = len_len_is_1 * FE::from_canonical_u8(0xB8) + len_len_is_2 * FE::from_canonical_u8(0xB9) + len_len_is_3 * FE::from_canonical_u8(0xBA) + len_len_is_4 * FE::from_canonical_u8(0xBB);
		yield_constr.constraint_filtered(curr_row.output_stack[0][0] - stack_push, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[0][1] - first_byte, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[4][0] - stack_push, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[4][1] - curr_row.rc_u8s[0], opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[3][0] - stack_push, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[3][1] - curr_row.rc_u8s[1], opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[2][0] - stack_push, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[2][1] - curr_row.rc_u8s[2], opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[1][0] - stack_push, opcode_is_str_prefix * prefix_string_out_of_range_case);
		yield_constr.constraint_filtered(curr_row.output_stack[1][1] - curr_row.rc_u8s[3], opcode_is_str_prefix * prefix_string_out_of_range_case);

		// increment count by number of bytes in prefix
		let prefix_len = len_len_is_1 * FE::from_canonical_u8(1) + len_len_is_2 * FE::from_canonical_u8(2) + len_len_is_3 * FE::from_canonical_u8(3) + len_len_is_4 * FE::from_canonical_u8(4);
		let next_prefix_string_in_range_case = next_row.prefix_case_flags[0];
		// ! this feels like a hack, but it's the easiest way I can think of to do it atm
		yield_constr.constraint_transition(next_row.prefix_case_tmp_2 - next_opcode_is_str_prefix * (P::ONES - next_prefix_single_byte_case) * (P::ONES - next_prefix_string_in_range_case));
		yield_constr.constraint_transition_filtered(next_row.count - (curr_row.count + prefix_len + P::ONES), curr_row.prefix_case_tmp_2);
		yield_constr.constraint_transition_filtered(next_row.count - (curr_row.count + P::ONES), opcode_is_str_prefix * prefix_string_in_range_case);
		// don't change count in single byte case
		
		// ListPrefix
		// check that count = content_len
		// if count is <= 55 then prefix is 0xC0 + count
		// else if count >55 and log256_is_1 then prefix is 0xF8, count
		// else if cuont >55 and log256_is_2 then prefix is 0xF9, count_1, count_0
		// else if count >55 and log256_is_3 then prefix is 0xFA, count_2, count_1, count_0
		// else if count >55 and log256_is_4 then prefix is 0xFB, count_3, count_2, count_1, count_0

		// EntryEnd
		// Halt

		// base-55 decomp
		let recomp = (0..6).rev().fold(P::ZEROS, |acc, i| acc * FE::from_canonical_u8(55) + curr_row.rc_55_limbs[i]);
		yield_constr.constraint(curr_row.count - recomp);
		for i in 0..6 {
			eval_lookups(&vars, yield_constr, RC_55_LIMBS_PERMUTED_START + i, LUT_55_LIMBS_PERMUTED_START + i);
		}
		
		// byte decomp
		let recomp = (0..4).map(|i| curr_row.rc_u8s[i + 1] * FE::from_canonical_u64(1 << i * 8)).sum::<P>();
		yield_constr.constraint(curr_row.count - recomp);
		for i in 0..4 {
			eval_lookups(&vars, yield_constr, RC_U8_PERMUTED_START + i, LUT_U8_PERMUTED_START + i);
		}

		// ensure things that shouldn't change stay the same
		yield_constr.constraint_transition_filtered(next_row.depth - (curr_row.depth + P::ONES), opcode_is_recurse);
		// keep depth the same when not recursing
		yield_constr.constraint_transition_filtered(next_row.depth - curr_row.depth, P::ONES - opcode_is_recurse);
	}

	fn eval_ext_circuit(
		&self,
		_builder: &mut CircuitBuilder<F, D>,
		_vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
		_yield_constr: &mut RecursiveConstraintConsumer<F, D>,
	) {
		todo!()
	}

	fn constraint_degree(&self) -> usize {
		3
	}
	
	
}