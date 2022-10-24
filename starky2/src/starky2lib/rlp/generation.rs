use plonky2::field::types::PrimeField64;
use super::layout::*;
use crate::starky2lib::stack::generation::StackOp;

pub struct RlpStarkGenerator<F: PrimeField64, const NUM_CHANNELS: usize> {
	pub stark_trace: Vec<RlpRow<F, NUM_CHANNELS>>,

	pub output_stack: Vec<F>,
	pub output_stack_trace: Vec<StackOp<F>>,

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
	state: RlpSMState
}

enum RlpSMState {
	NEW_ENTRY,
	LIST,
	RECURSE,
	RETURN,
	STR_PUSH,
	STR_PREFIX,
	LIST_PREFIX,
	END_ENTRY,
	HALT,
}

impl<F: PrimeField64, const NUM_CHANNELS: usize> RlpStarkGenerator<F, NUM_CHANNELS> {
	pub fn new() -> Self {
		Self {
			stark_trace: Vec::new(),
			output_stack: Vec::new(),
			output_stack_trace: Vec::new(),
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
			state: RlpSMState::NEW_ENTRY
		}
	}

	pub fn gen_input_memory(&mut self, items: &[RlpItem]) {
		let vals = RlpItem::items_to_memory_trace::<F>(items);
		self.input_memory = vals.clone();
	}

	// returns an trace of accesses to be used to generate an ro-memory STARK
	// for the input memory
	// this should be called after the trace has been generated but before it is converted
	// to polynomial values
	pub fn input_memory_trace(&self) -> Vec<(F, F)> {
		self.input_memory.iter().enumerate().map(|(i, v)| (F::from_canonical_u64(i as u64), *v)).collect()
	}

	// returns a trace of stack operations for the RLP's call stack.
	// This is used to generate a stack STARK for it
	pub fn call_stack_trace(&self) -> Vec<StackOp<F>> {
		self.call_stack_trace.clone()
	}

	// returns a trace of stack operations for the RLP's output stack.
	// This is used to generate a stack STARK for it
	pub fn output_stack_trace(&self) -> Vec<StackOp<F>> {
		self.output_stack_trace.clone()
	}

	pub fn generate(&mut self, items: &[RlpItem]) {
		self.gen_input_memory(items);
		self.gen_state_machine();
	}

	fn gen_state_machine(&mut self) {
		loop {
			match self.state {
				RlpSMState::NEW_ENTRY => {
					let next = self.read_pc_advance();
					let is_last = self.read_pc_advance();
					if self.depth == 0 {
						self.next = next.to_canonical_u64() as usize;
						self.is_last = match is_last.to_canonical_u64() {
							// convert to u64 since associated consts not allowed in patterns yet
							0 => false,
							1 => true,
							_ => panic!("is_last must be 0 or 1")
						}
					}

					let is_list = match self.read_pc_advance().to_canonical_u64() {
						// convert to u64 since associated consts not allowed in patterns yet
						0 => false,
						1 => true,
						_ => panic!("is_list must be 0 or 1")
					};

					let op_id_read = self.read_pc_advance().to_canonical_u64();
					assert!(op_id_read == self.op_id);


					self.content_len = self.read_pc_advance().to_canonical_u64() as usize;
					self.count = 0;
					self.list_count = 0;
					
					match is_list {
						true => {
							if self.content_len == 0 {
								self.state = RlpSMState::LIST_PREFIX;
							} else {
								self.state = RlpSMState::LIST;	
							}
						},
						false => {
							self.state = RlpSMState::STR_PUSH;
						}
					}
				}
				RlpSMState::STR_PUSH => {
					if self.content_len == self.count {
						self.count = 0;
						self.state = RlpSMState::STR_PREFIX;
					} else {
						let val = self.read_pc_advance();
						self.push_call_stack(val);
						self.count += 1;
					}
				}
				RlpSMState::STR_PREFIX => {
					// in the STARK, output_stack.last() is accessed via the "previous" row
					let first_val = self.output_stack.last().unwrap();
					let first_val = first_val.to_canonical_u64() as u8;
					let mut prefix = self.compute_str_prefix(self.content_len, first_val);
					for b in prefix.into_iter().rev() {
						self.push_call_stack(F::from_canonical_u64(b as u64));
					}
					self.state = RlpSMState::END_ENTRY;
				}
				RlpSMState::LIST => {
					// push list_counter, pc to call stack
					self.push_call_stack(F::from_canonical_u64(self.list_count as u64));
					self.push_call_stack(F::from_canonical_u64(self.pc as u64));
					self.list_count += 1; // ! bug warning
					if self.list_count == self.content_len {
						self.state = RlpSMState::RECURSE;
					}
				}
				RlpSMState::LIST_PREFIX => {
					let prefix = self.compute_list_prefix(self.count);
					for b in prefix.into_iter().rev() {
						self.push_call_stack(F::from_canonical_u64(b as u64));
					}
					self.state = RlpSMState::END_ENTRY;
				}
				RlpSMState::END_ENTRY => {
					// if we're at the top level, finalize the entry's output and proceed to
					// the next item to be encoded if is_last is false. otherwise halt
					// if we're not at the top level, return up a level
					if self.depth == 0 {
						// push encoded output len (count) to stack
						self.push_output_stack(F::from_canonical_u64(self.count as u64));
						// push op_id to the stack
						self.push_output_stack(F::from_canonical_u64(self.op_id as u64));

						self.op_id += 1;
						if self.is_last {
							self.state = RlpSMState::HALT;
						} else {
							self.pc = self.next;
							self.state = RlpSMState::NEW_ENTRY;
						}
					} else {
						self.state = RlpSMState::RETURN;
					}
				}
				RlpSMState::RECURSE => {
					// pop pc from call stack
					// before: [prev_list_count, prev_pc, list_count, pc]
					// after: [prev_list_count, prev_pc, list_count]
					let new_pc = self.pop_call_stack();
					// push content len to stack
					// after: [prev_list_count, prev_pc, list_count, pc, content_len]
					self.push_call_stack(F::from_canonical_u64(self.content_len as u64));
					// push count to call stack
					// after: [prev_list_count, prev_pc, list_count, pc, content_len, count]
					self.push_call_stack(F::from_canonical_u64(self.count as u64));
					// jump to the new entry 
					self.pc = new_pc.to_canonical_u64() as usize;
					// increment depth
					self.depth += 1;
					// set new state to NEW_ENTRY
					self.state = RlpSMState::NEW_ENTRY;
				}
				RlpSMState::RETURN => {
					// before: [prev_list_count, prev_pc, list_count, pc, content_len, count]
					let old_count = self.pop_call_stack();
					// before: [prev_list_count, prev_pc, list_count, pc, content_len]
					let old_content_len = self.pop_call_stack();
					// before: [prev_list_count, prev_pc, list_count, pc]
					let old_pc = self.pop_call_stack();
					// before: [prev_list_count, prev_pc, list_count,]
					// after: [prev_list_count, prev_pc] - the start point for RECURSE state if it's not the last step
					let old_list_count = self.pop_call_stack();

					self.count += old_count.to_canonical_u64() as usize;
					self.list_count = old_list_count.to_canonical_u64() as usize + 1;
					self.content_len = old_content_len.to_canonical_u64() as usize;
					// jump back to the next element of the list & decrement depth
					self.pc = old_pc.to_canonical_u64() as usize;
					self.depth -= 1;

					// bug warning
					if self.content_len == self.list_count {
						self.state = RlpSMState::LIST_PREFIX;
					} else {
						self.state = RlpSMState::RECURSE;
					}
				}
				RlpSMState::HALT => {
					return;
				}
			}
		}
	}

	fn compute_str_prefix(&mut self, len: usize, first_val: u8) -> Vec<u8> {
		match first_val {
			0x00..=0x7F => {
				vec![]	
			},
			_ => match len {
				0..=55 => {
					vec![0x80 + len as u8]
				},
				_ => {
					// bug warning
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
	}

	fn compute_list_prefix(&mut self, len: usize) -> Vec<u8> {
		match len {
			0..=55 => {
				vec![0xC0 + len as u8]
			},
			_ => {
				// bug warning
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

	fn read_pc_advance(&mut self) -> F {
		let val = self.input_memory[self.pc];
		self.pc += 1;
		val
	}

	fn push_call_stack(&mut self, val: F) {
		self.call_stack.push(val);
		self.call_stack_trace.push(StackOp::Push(val));
	}

	fn pop_call_stack(&mut self) -> F {
		let val = self.call_stack.pop().unwrap();
		self.call_stack_trace.push(StackOp::Pop(val));
		val
	}

	fn push_output_stack(&mut self, val: F) {
		self.output_stack.push(val);
		self.output_stack_trace.push(StackOp::Push(val));
	}

}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem {
	List(Vec<Box<RlpItem>>),
	Str(Vec<u8>)
}

impl RlpItem {
	// must call this all at once - cannot update this incrementally
	// this panics if it is called with an empty list
	// TODO: use an error instead.
	pub fn items_to_memory_trace<F: PrimeField64>(items: &[Self]) -> Vec<F> {
		let mut trace = Vec::new();
		let mut is_last_ptr_opt = None;
		for (i, item) in items.iter().enumerate() {
			let is_last_ptr = Self::item_to_memory_trace(item, &mut trace, i as u64);
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
	fn item_to_memory_trace<F: PrimeField64>(item: &Self, trace: &mut Vec<F>, op_id: u64) -> usize {
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
					Self::item_to_memory_trace(item, trace, op_id);
				}

				// set next_item ptr
				trace[next_item_ptr] = F::from_canonical_u64(trace.len() as u64);
			},
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
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_rlp_item_to_memory_trace() {
		todo!()
	}

	#[test]
	fn test_state_machine() {
		todo!();
	}
}
