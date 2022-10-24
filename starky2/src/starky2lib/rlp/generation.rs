use plonky2::field::types::PrimeField64;
use rlp::{Encodable, RlpStream};
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
			state: RlpSMState::NewEntry
		}
	}

	pub fn gen_input_memory(&mut self, items: &[RlpItem]) {
		let vals = RlpItem::items_to_memory_values::<F>(items);
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

	pub fn output_stack(&self) -> &[F] {
		&self.output_stack
	}

	pub fn generate(&mut self, items: &[RlpItem]) {
		self.gen_input_memory(items);
		self.gen_state_machine();
	}

	fn gen_state_machine(&mut self) {
		loop {
			match self.state {
				RlpSMState::NewEntry => {
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

					println!("next: {:?}, is_last: {:?}", self.next, self.is_last);

					let is_list = match self.read_pc_advance().to_canonical_u64() {
						// convert to u64 since associated consts not allowed in patterns yet
						0 => false,
						1 => true,
						_ => panic!("is_list must be 0 or 1")
					};
					println!("is_list: {:?}", is_list);

					let op_id_read = self.read_pc_advance().to_canonical_u64();
					assert!(op_id_read == self.op_id);


					self.content_len = self.read_pc_advance().to_canonical_u64() as usize;
					self.count = 0;
					self.list_count = 0;
					
					match is_list {
						true => {
							if self.content_len == 0 {
								self.state = RlpSMState::ListPrefix;
							} else {
								self.state = RlpSMState::List;	
							}
						},
						false => {
							self.state = RlpSMState::StrPush;
						}
					}
				}
				RlpSMState::StrPush => {
					if self.content_len == self.count {
						self.state = RlpSMState::StrPrefix;
					} else {
						let val = self.read_pc_advance();
						self.push_output_stack(val);
						self.count += 1;
					}
				}
				RlpSMState::StrPrefix => {
					// in the STARK, output_stack.last() is accessed via the "previous" row
					let first_val = self.output_stack.last().unwrap();
					let first_val = first_val.to_canonical_u64() as u8;
					let prefix = self.compute_str_prefix(self.content_len, first_val);
					for b in prefix.into_iter().rev() {
						self.push_output_stack(F::from_canonical_u64(b as u64));
						self.count += 1;
					}
					self.state = RlpSMState::EndEntry;
				}
				RlpSMState::List => {
					// push current list count onto the stack. This is used so the returning state can
					// tell when to stop recursing
					self.push_call_stack(F::from_canonical_u64(self.list_count as u64));
					// read pointer from the table and push it onto the stack
					let inner_addr = self.read_pc_advance();
					self.push_call_stack(inner_addr);
					self.list_count += 1; // ! bug warning
					if self.list_count == self.content_len {
						self.state = RlpSMState::Recurse;
					}
				}
				RlpSMState::ListPrefix => {
					let prefix = self.compute_list_prefix(self.count);
					for b in prefix.into_iter().rev() {
						self.push_output_stack(F::from_canonical_u64(b as u64));
						self.count += 1;
					}
					self.state = RlpSMState::EndEntry;
				}
				RlpSMState::EndEntry => {
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
							self.state = RlpSMState::Halt;
						} else {
							self.pc = self.next;
							self.state = RlpSMState::NewEntry;
						}
					} else {
						self.state = RlpSMState::Return;
					}
				}
				RlpSMState::Recurse => {
					// pop addr from call stack
					// before: [prev_list_count, prev_list_addr, list_count, list_addr]
					// after: [prev_list_count, prev_list_addr, list_count]
					let dst = self.pop_call_stack();
					// push count to call stack
					// after: [prev_list_count, prev_list_addr, list_count, count]
					self.push_call_stack(F::from_canonical_u64(self.count as u64));
					// push pc to call stack
					// after: [prev_list_count, prev_list_addr, list_count, count, pc]
					self.push_call_stack(F::from_canonical_u64(self.pc as u64));

					// jump to the new entry 
					self.pc = dst.to_canonical_u64() as usize;
					// increment depth
					self.depth += 1;
					// set new state to NewEntry
					self.state = RlpSMState::NewEntry;
				}
				RlpSMState::Return => {
					// before: [prev_list_count, prev_list_addr, list_count, count, pc]
					let old_pc = self.pop_call_stack();
					// before: [prev_list_count, prev_list_addr, list_count, count]
					let old_count = self.pop_call_stack();
					// before: [prev_list_count, prev_list_addr, list_count]
					// after: [prev_list_count, prev_list_addr_addr] - the start point for Recurse state if it's not the last step
					let old_list_count = self.pop_call_stack();

					self.count += old_count.to_canonical_u64() as usize;
					self.list_count = old_list_count.to_canonical_u64() as usize;
					// jump back to the next element of the list & decrement depth
					self.pc = old_pc.to_canonical_u64() as usize;
					self.depth -= 1;

					// bug warning
					if self.list_count == 0 {
						self.state = RlpSMState::ListPrefix;
					} else {
						self.state = RlpSMState::Recurse;
					}
				}
				RlpSMState::Halt => {
					return;
				}
			}
		}
	}

	fn compute_str_prefix(&mut self, len: usize, first_val: u8) -> Vec<u8> {
		match (len, first_val) {
			(1, 0x00..=0x7F) => vec![],
			(0..=55, _) => vec![0x80 + len as u8],
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
	fn item_to_memory_values<F: PrimeField64>(item: &Self, trace: &mut Vec<F>, op_id: u64) -> usize {
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

impl Encodable for RlpItem {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self {
			RlpItem::List(items) => {
				s.append_list::<Self, Box<Self>>(&items);
			},
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
			for (b, b_expected) in content.iter().map(|x| u8::try_from(*x).unwrap()).zip($s.iter().copied().rev()) {
				assert_eq!(b, b_expected)
			}

			$s.len() + 5
		}}
	}

	#[test]
	fn test_rlp_item_single_string() {
		let s = b"I met a metaphorical girl in a metaphorical word";
		let items = vec![
			RlpItem::Str(s.to_vec())
		];
		let mem = RlpItem::items_to_memory_values::<F>(&items);
		let mem = mem.into_iter().map(|v| v.to_canonical_u64()).collect::<Vec<_>>();
		test_rlp_str_entry!(s, mem, true, 0, 0);
	}

	#[test]
	fn test_rlp_item_multiple_strings() {
		let ss = vec![
			b"I used to rap like i had some marbles in my mouth".to_vec(),
			b"But the stones turned precious when they all came out".to_vec(),
			b"On a string of deep thought that could never be bought".to_vec(),
		];

		let items = ss.iter().map(|v| RlpItem::Str(v.clone())).collect::<Vec<_>>();
		let mem = RlpItem::items_to_memory_values::<F>(&items);
		let mem = mem.into_iter().map(|v| v.to_canonical_u64()).collect::<Vec<_>>();
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
		let mem = mem.into_iter().map(|v| v.to_canonical_u64()).collect::<Vec<_>>();
		
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
			RlpItem::List(
				vec![
					Box::new(RlpItem::Str(b"They say heaven can wait".to_vec())),
					Box::new(RlpItem::Str(b"And you speak of fate".to_vec())),
					Box::new(RlpItem::Str(b"A finale to a play for my mate".to_vec())),
				]
			),
			RlpItem::Str(b"I see the angels draw the drapes".to_vec()),
		];

		let item = RlpItem::List(items.iter().cloned().map(Box::new).collect());
		let mem = RlpItem::items_to_memory_values::<F>(&[item]);
		let mem = mem.into_iter().map(|v| v.to_canonical_u64()).collect::<Vec<_>>();
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
		const NUM_CHANNELS: usize = 1;
		let input = vec![
			RlpItem::Str(b"Relax".to_vec()),
			RlpItem::Str(b"Here we go, part two".to_vec()),
			RlpItem::Str(b"Checking out!".to_vec()),
			RlpItem::list_from_vec(
				vec![
					RlpItem::list_from_vec(
						vec![
							RlpItem::Str(b"Once again, now where do I start, dear love".to_vec()),
							RlpItem::Str(b"Dumb struck with the pure luck to find you here".to_vec()),
							RlpItem::Str(b"Every morn' I awake from a cavernous night".to_vec()),
							RlpItem::Str(b"Sometimes still pondering the previous plight".to_vec())
						]
					),
					RlpItem::Str(b"Seems life done changed long time no speak".to_vec()),
					RlpItem::Str(b"Nowadays I often forget the day of the week".to_vec())
				]
			),
			RlpItem::list_from_vec(
				vec![
					RlpItem::Str(b"Taking it by stride if you know what I mean".to_vec()),
					RlpItem::Str(b"No harm done, no offense taken by me".to_vec()),
					RlpItem::Str(b"So let's rap, we'll catch up to par, what's the haps?".to_vec()),
				]
			),
			RlpItem::Str(b"C'est la vie, as they say L.O.V.E evidently".to_vec())
		];

		let mut generator = RlpStarkGenerator::<F, NUM_CHANNELS>::new();
		println!("generating...");
		generator.generate(&input);
		let mut output_stack = generator.output_stack().into_iter().map(|v| v.to_canonical_u64()).collect::<Vec<_>>();

		println!("\nchecking...");
		let mut outputs = Vec::new();
		while output_stack.len() >= 2 {
			let op_id = output_stack.pop().unwrap();
			let len = output_stack.pop().unwrap();
			println!("op_id: {:?}, len: {:?}", op_id, len);
			assert!(len as usize <= output_stack.len());
			let mut output = Vec::new();
			for _ in 0..len {
				let b = output_stack.pop().unwrap();
				assert!(b < 256);
				output.push(b as u8);
			}
			outputs.push((op_id, output));
		}

		assert!(
			outputs.iter().map(|(op_id, _)| Reverse(op_id)).is_sorted()
		);

	
		let outputs = outputs.into_iter().rev().map(|(_, output)| output).collect::<Vec<_>>();

		let correct_outputs = input.iter().map(encode);
		for (output, correct_output) in outputs.into_iter().zip(correct_outputs) {
			assert_eq!(output, correct_output.into_vec());
		}
	}
}
