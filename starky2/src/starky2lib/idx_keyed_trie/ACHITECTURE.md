# Indexed-Keyed MPT State Machine

This state machine computes the root hash of an index-keyed merkle patricia trie, as seen in the Ethereum receipt and transaction tries (in particular, it was designed with STARKing these tries in mind). In other words, the "key" for the `i`th leaf value is `RLP(varlen_be(i))`, `varlen_be(i)` returns the big-endian byte representation of `i` with the minimum possible length. Some examples:
* `varlen_be(0) = ""`
* `varlen_be(1) = 0x01`
* `varlen_be(32767) = 0x7FFF`

The state machine uses the following memories:
1. leaf memory
2. hash memory
3. path RLP input memory
4. path RLP output memory
5. node RLP input memory
6. node RLP output memory
7. call stack
8. template memory

uses CTLs to the following STARKs (9 total):
1. one ro-memory STARK for the leaf memory
5. one ro-memory STARK for the hash memory
2. two instances of the RLP STARK - one for paths, the other for nodes
3. two ro-memory STARKs to contain their input entries
4. two ro-memory STARKs to contain the encoded outputs
6. one instance of the `stack` STARK to serve as the call stack
7. one instance of the `keccak256_stack` stark that reads input from the RLP input memory and "Writes" to the hash memory
8. one instance of the read-write memory for the template


has the following public inputs:
1. the claimed root hash of the trie

and the following limitations:
1. the maximum number of leaves is 4096. In the future this could be made more generic, but for our purposes (ethereum TX and receipt tries) this is more than enough (for now)
2. we assume every leaf value is at least 32 bytes. This significantly reduces the (already very high) complexity of the branching logic the state machine needs to express. Luckily for both transactions and receipts, this is guaranteed to be the case for known transaction and receipt types beause they all include `logsBloom`, which is 256 bytes.

### Leaf Memory

the leaf memory consists of three sections:
1. at address 0, a single cell indicating the number of leaves
2. starting at address 1, an array of pointers to leaf contents in the third section, each a single cell
2. the concatenation of every leaf value

### Hash Memory

A memory containing a contiguous array of 32-byte strings representing the keccak256 hash of a node in the trie. This is "produced" by the keccak256_

### RLP memories

RLP memories are as described in the [rlp module](../rlp/ARCHITECTURE.md). For paths, every item is the big-endian representation of the current

### Template Memory

The template memory is a read-write memory that holds the "template", an auxiliary data structre detailed below.

## State Machine

The state machine, at a high level, constructs the trie and computes the root in three phases:
1. In the first phase, the state machine constructs the *uncompressed* trie structure in the template, which is described in greater detail lbelow.
2. In the second phase, the state machine compresses the template into a patricia trie.
3. In the third phase, the state machine traverses the template in reverse-depth-first order and, non-deterministically looking up hashes from the hash memory, constructs an RLP item for each node

The hash corresponding to the greatest `op_id` (i.e. the index of the last node constructed during traversal) is the root hash.

### The Template

The template is an auxiliary data structure used by the state machine to compute the structure of the trie, compress paths, and iterate over its nodes. This and the call stack are the two primary sources of control flow for the state machine.

The template is laid out in the template memory as follows, starting from address zero in ascending order:
1. a single cell that we don't care what it is - this address serves as the `NULL` pointer
	* while `NULL` pointers are something we'd like to avoid, it allows us to differentiate between null and non-null child pointers with only a single memory cell.
2. a series of "entries", which are represented as tagged unions (aka ADTs, disjoint unions, rust enums, etc) with two variants:
	* MaybeLeaf, whose contents are:
		* tag (1 cell): `0x0`
		* kind (2 cells): two binary flags used to tell what kind of node this. Its values are interpreted as follows
			* `00`: leaf
			* `01`: branch
			* `10`: extension
			* other values are illegal
		* plen (1 cell): the length of the "compressed path" for the leaf node, without the hex-prefix.
		* path (6 cells): the "compressed path" for the leaf node, without the hex-prefix.
		* has_val (1 cell): the 
		* val_idx (1 cell): index into the value memory of the corresponding leaf value, if `has_val` is se
		* num_children (1 cell): the number of children of this node
		* children (16 cells): for each nibble in the range `0x0-0xF`, the address of the child entry if there is one, or `0` (pointing to the `NULL` address) otherwise.
	* DefLeaf, whose contents are:
		* tag (1 cell): `0x01`
		* plen (1 cell): the length of the "compressed path" for the leaf node, without the hex-prefix.
		* path (6 cells): the "compressed path" for the leaf node, without the hex-prefix.


### Potential improvements

The vast majority of the STARK's cost comes from reading / writing from byte-oriented memories. There are a few things that can be done to reduce this significantly:
	* Make a variant of the RLP STARK that performs CTLs against the value memory and has a different entry structure, where strings contain an index into the value memory. This is will avoid the trie STARK having to iterate over each value even though the RLP stark does that too.
	* Read more / less bytes from the value memory in a single row. Reading `N` bytes at a time will come at a cost of `3N` columns (address, value, filter) but will significantly reduce the number of rows. 
	* Make variants of memory STARKs with a given "stride" and use those to read many bytes at once with only one address column. This would be especially helpful for the hash memory, which always reads 32 bytes at a time, allowing us to save 32 columns.
	* Just shooting the shit here, but there might be a way to make a CTL that allows one to deterministically "compute" some lookup columns from others in a determinstic manner known to the verifier, where the derived columns are not committed to in the trace. In particular, one column is the "start" address, and the "computed column' only appears in the lookup argument.

Also, this is still a pretty rough prototype. There's probably more efficient ways to express the logic of the state machine and its transitions to shave off a fair amount of columns here and there. For instance, a lot of CTL filter columns can probably be de-duplicated, as typically the same channels are used during the same states.
