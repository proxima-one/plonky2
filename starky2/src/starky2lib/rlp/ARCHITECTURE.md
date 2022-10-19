# RLP STARK Design

## Memories

This stark is built via CTLs to three memories:
1. The "input" memory, which contains lists and strings to decode
2. A call stack
3. the "strstack", which is a stack containing the RLP-encoded results which may be read by popping the entire stack

The "input" memory is an instance of the `ro_memory` STARK. Both stacks are instances of the "ro_stack" STARK. Note that, by convention, the "ro_stack" STARK grows "up" - i.e. the top of the stack starts at address 0 and, as items are pushed, the address of the top of the stack increases.

### input memory layout

The decoded memory is a series of entries, where, abstractly, each entry represents a string if the input is a string, or a table offsets to other entries (which may represent lists or strings) if the input is a list. Each entry is represented as the following fields, in order from least to greatest address:
* `is_list`: a cell containing a boolean flag indicating whether or not the current represents a list
* `id`: a cell containing a unique identifier of the structure. The RLP STARK will ignore this if the current entry isn't a top-level entry. These IDs must start with 0 and increase by 1 with each top-level item to encode
* `len`: a cell indicating the length in cells of the entry's `content`
* `next_toplevel`: a cell containing a pointer to the next top-level item to encode. This is ignored when depth != 0.
* `content`:
	* if `is_list` is `1`, then `content` is a possibly-entry series of cells, where each cell is a the address of a child entry in the memory
	* if `is_list` is `0`, then `content` is a possibly-entry byte-string where each cell corresponds to 1 byte

### strstack layout

The "complete" strstack is sequence of entries, where the `i`th entry from the bottom of the stack is represented as the following fields, in order from least to greatest address:
* res: result rlp-encoding of item `i`
* len: len of rlp-encoded string (number of elements to pop)
* op_id: `i`

### call stack layout

Call stack semantics are specified below in the state machine definition below


