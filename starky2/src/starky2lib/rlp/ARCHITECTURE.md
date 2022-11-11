# RLP State Machine

The RLP STARK is designed as a state machine utilizing CTLs to three memory starks, two of which are stacks. This document describes the state machine, not the STARK. 

## Memories

This state machine built using three memories:
1. The "input" memory, which contains lists and strings to decode
2. A call stack
3. the "output stack"`, which is a read-only memory we use in a "stack-like" manner containing the RLP-encoded results which may be read by "popping" the entire "stack". We can get away with a read-only memory because we only ever "write" to an address once.

The "input" memory is an instance of the `ro_memory` STARK. The call stack is an instance of the "stack" STARK. the "output stack" is an instance of the "ro_memory" stark. By convention, we say stacks grow "up" - i.e. the top of the stack starts at some base address (0 for the call stack, 1 for the output "stack") and, as items are pushed, the address of the top of the stack increases.

### input memory layout

The decoded memory is a series of entries, where, abstractly, each entry represents a string if the input is a string, or a table offsets to other entries (which may represent lists or strings) if the input is a list. Each entry is represented as the following fields, in order from least to greatest address:
* `next_item`: a cell containing a pointer to the next top-level item to encode. This is ignored when depth != 0.
* `is_last_item`: a binary flag indicating whether or not this is the last item to encode. This is ignored when depth != 0
* `is_list`: a cell containing a boolean flag indicating whether or not the current represents a list
* `id`: a cell containing a unique identifier of the structure. The RLP STARK will ignore this if the current entry isn't a top-level entry. These IDs must start with 0 and increase by 1 with each top-level item to encode
* `len`: a cell indicating the length in cells of the entry's `content`
* `content`:
	* if `is_list` is `1`, then `content` is a possibly-entry series of cells, where each cell is a the address of a child entry in the memory
	* if `is_list` is `0`, then `content` is a possibly-empty byte string stored in reverse order (i.e. the last byte of the string comes first).
		* This to avoid having to re-reverse the string on the output stack

### output stack layout

The "output stack" is actually a read-only memory. But, semantically, we're using it to "push" the output backwards onto the stack and the consumer reads it by "popping" off of the stack. The layout is a single cell containing a pointer to the "top" of the stack followed by a sequence of entries, where the `i`th entry from the bottom of the stack is represented as the following fields, in order from least to greatest address:
* res: result rlp-encoding of item `i`
* len: len of rlp-encoded string (number of elements to pop)
* op_id: `i`

The entry at the top of the stack has the highest `op_id` and the entry at the bottom should have `op_id = 0`.

### call stack layout

Call stack is a stack whose base adress is zero. See the state machine definition below to see how it is used and what goes on it.

## State Machine

THe goal of the state machine is to read entries from the input memory and produce the correct RLP encodings on the output stack in a manner such that the consumer may read them by popping the entire output from the stack.

The state machine exists in one of the following "states", each associated with a single "opcode":
* `NewEntry`: read a new entry's metadata into the state machine and prepare to encode it
* `List`: for a list item, push the child pointers onto the call stack so that they may recursively be encoded
* `Recurse`: recurse backwards through the children of a list item. We recurse backwards because we push the results onto a stack, which will be in reverse order when popped by the consumer
* `Return`: "return" up a level after recursing through children of a list item and accumulate the the length count of the child encodings.
* `StrPrefix`: calculate the prefix for a string entry and push it to the output stack
* `ListPrefix`: calculate the prefix for a list entry and push it to the output stack
* `EndEntry`: Finish processing an entry and either return to the outer (recursive) list entry or proceed to the next top-level entry
* `Halt`: do nothing once the last entry has been fully processed

The state machine keeps the following state variables:
* `op_id`: a monotonically-increasing identifier for a top-level item to be RLP-encoded
* `pc`: a pointer into the input memory
* `count`: a counter used to compute the total length of an RLP item and its children
* `content_len`: length of the `content` field of the entry currently being processed
* `list_count`: an auxilliary counter used when setting up the call stack for recursion so the state machine knows when to stop recursing
* `depth`: the current recursion depth of the state machine
* `next`: pointer to the next top-level entry to encode. ignored if `is_last` is set to `1`

Execution begins in the `NewEntry` state. The following describes what happens during each state. (notation: `[x]` denotes the value in the input memory at the address given by `x`). This can also be seen in the function `gen_state_machine` in [`generation.rs`](./generation.rs):
* `NewEntry`:
	* `next <- [pc]`
	* `is_last <- [pc + 1]`
	* `is_list <- [pc + 2]`
	* `assert op_id = [pc + 3]`
	* `content_len <- [pc + 4]`
	* `pc <- pc + 5`
	* `count <- 0`
	* `list_count <- 0`
	* then:
		* if `is_list = 1` AND `content_len = 0`, then transition to `ListPrefix`
		* if `is_list = 1` AND `content_len != 0`, then transition to `List`
		* if `is_list = 0` AND `content_len = 0`, then transition to `StrPrefix`
		* if `is_list = 0` AND `content_len != 0`, then transition to `StrPush`
* `StrPush`:
	* `output_stack.push([pc])
	* `pc <- pc + 1`
	* `count <- count + 1`
	* then:
		* if `content_len = count`, then transition to `StrPrefix`
		* otherwise stay at `StrPush`
* `StrPrefix`:
	* let `prefix` be the RLP prefix for a byte-string with length `count`
		* note that `prefix` can be 0 bytes long thanks to the brilliant idea of making a single byte in the range `0x00..=0x7F` its own encoding to sometimes shave a byte.
	* `output_stack.push(prefix)`
	* `count <- count + prefix.len()`
	* then:
		* transition to `EndEntry`
* `List`:
	* `output_stack.push(list_count)`
	* `output_stack.push([pc])`
	* `pc <- pc + 1`
	* `list_count <- list_count + 1`
	* then:
		* if `list_count == content_len`, then transition to `Recurse`
		* otherwise stay at `List`
* `ListPrefix`:
	* let `prefix` be the RLP prefix for the list whose total payload (RLP encodings of its children) has length `count`
	* `output_stack.push(prefix)`
	* `count <- count + prefix.len()`
	* then:
		* transition to `EndEntry`
* `Recurse`:
	* let `dst` be the result of `pop_call_stack()`
	* `push_call_stack(count)`
	* `push_call_stack(pc)`
	* `pc <- dst`
	* `depth <- depth + 1`
	* then:
		* transition to `NewEntry`
* `Return`:
	* `pc <- pop_call_stack()`
	* `count <- count + pop_call_stack()`
	* `list_count <- pop_call_stack()`
	* `depth <- depth - 1`
	* then
		* if `list_count = 0`, then transition to `ListPrefix`
		* otherwise go back to `Recurse`	
* `EndEntry`:
	* if `depth = 0`, then:
		* `push_output_stack(count)`
		* `push_output_stack(op_id)`
		* `op_id  <- op_id + 1`
		* if `is_last = 1`, then transition to `Halt`
		* otherwise, then:
			* `pc <- next`
			* transition to `NewEntry`
	* otherwise, simply transition to `Return`
* `Halt:
	* all registers stay exactly the same
	* the "height" of the output "stack" is written to the 0th cell of the output memory. It will point to the last cell in the output memory.

## Potential Improvements

Most of the cost from this STARK comes from reading bytes from the entry memory. We can potentially reduce this cost significantly with the following methods:
	* Have this stark use a second input memory that contains only the string values, and change the entry structure for lists to contain a single index into that memory. This would greatly reduce the costs required for external STARKs to check the entries as they will be much shorter. However it will not reduce the cost for *this* STARK.
	* Consider adding colums to the input/output memories to read and write `N` bytes at once. If RLP string items are long on average (e.g. receipts which are always > 256 bytes), then this will reduce the number rows drastically. However, this comes at the cost of `6N` columns to the trace naively, as each additional cell will require a CTL filter, address, and value column for both the input and output memory. That said, there's probaly a clever way to re-use the CTL filters and value columns, potentially reducing this to `4N`.

Also, this is still a pretty rough prototype. There's probably more efficient ways to express the logic of the state machine and its transitions to shave off a fair amount of columns here and there. For instance, a lot of CTL filter columns can probably be de-duplicated, as typically the same channels are used during the same states.
