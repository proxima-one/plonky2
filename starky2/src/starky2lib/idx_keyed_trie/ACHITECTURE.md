# MPT State Machine

This state machine uses the following memories:
1. leaf memory
2. hash memory
3. path RLP input memory
4. path RLP output stackR
5. node RLP input memory
6. node RLP output stack
7. node map

has the following public inputs:
1. the claimed root hash of the trie
2. the "top" stack pointer of the path RLP output stack. The verifier checks this is the same as the one given by the path RLP stark proof
3. the "top" stack pointer of the node RLP output stack. The verifier checks this is the same as the one given by the path RLP stark proof

and the following limitations:
1. the maximum number of leaves is 4096. In the future this could be made more generic, but for our purposes (ethereum TX and receipt tries) this is more than enough (for now)
2. we assume every leaf value is at least 32 bytes. This significantly reduces the (already very high) complexity of the branching logic the state machine needs to express. Luckily for both transactions and receipts, this is guaranteed to be the case for known transaction and receipt types.

### Leaf Memory

the leaf memory is a series of entries of the form
1. length of value (in bytes)
2. byte string containing the leaf values

### Hash Memory

A memory containing a contiguous array of 32-byte strings representing the keccak256 hash of a node in the trie.

### path RLP input memory

the path input RLP memory is an RLP input memory as defined in the [rlp module](../rlp/ARCHITECTURE.md). For this specific case, each entry is a byte string corresponding to the big-endian, varialble-length represetation of the index of the corresponding leaf. Note that this means the index `0` maps to the empty string (this is ethereum's choice, not mine).

### path RLP output stack

the output 

### Node Map

The node map is a memory that is used to map (partial) paths to the RLP input memory entry and their hashes. It is a contiguous array of two-cell entries, where the cells are interpreted as follows:
1. pointer to a node's list entry in the node RLP input memory
2. pointer to the node's hash in the hash memory

Given the a (partial) path, the corresponding index into the node map is calculated as follows:
1. let `first_vals` be a length-6 constant array: `[0x0, 0x01, 0x818, 0x8180, 0x82010, 0x820100]`, where `first_vals[i]` represents the smallest number value of a path with length `i + 1`.
2. let `offsets` be a length-5 constant array where:
	* `offsets[0] = 1`, accounting for the fact that the 0th entry is for the empty partial path (i.e. the path to the root node)
	* `offsets[1] = offsets[0] + 8` since there are 8 paths of length 1 and they're contiguous
	* `offests[2] = offsets[1] + 130` since there are 130 paths of length 2 and they're contiguous
	* `offsets[3] = offsets[2] + 9` since there are 9 paths of length 3 and they're contiguous
	* `offsets[4] = offsets[3] + 144 + 1` since there are 144 paths of length 4 but they skip `0x8200`
	* `offsets[5] = offsets[4] + 240` since there are 240 paths of length 5 and they're contiguous
3. then the index is..
	* `0` if the path is the empty string'
	* `recomp(path) - first-vals[path.len() - 1] + offsets[path.len() - 1]` otherwise
		* where `recomp` returns the numerical value of the path when interpreted as a big-endian sequence of *nibbles* (not bytes, as we can have odd number of nibbles) 


This works because we can have the following numbers of partial paths of each length, due to trie structure and RLP:
* `1` path of length `0`, corresponding to the root node
* `8` paths of length `1`, since all of the indexes are byte strings (not lists), which means the greatest first nibble we'll ever see from RLP is `0x8`
* `130` paths of length `2`, because...
	1. the bytes `0x01..=0x7F` are their own repr, and there are 127 of those
	2. the index `0` maps to the empty string in ethereum's variable-length big-endian repr and RLP encoding of the empty string `0x80`, which brings us to 128.
	3. We get another `2` possible length-2 paths because a 55-byte index is larger than any realistic trie to be constructed, so the index's byte repr is guaranteed to be <55 bytes. Therefore the remaining cases are `0x81` and `0x82`, as `4095` requires two bytes to express. This brings us to 130.
* `9` paths of length `3` because all paths of length `3` start with either `0x81` or `0x82`, and...
	1. The full paths starting from `0x81` range from `0x8180` to `0x81FF`, so the three-nibble prefixes are `0x818` to `0x81F`, a range consisting of 8 paths
	2. There is only one length-three path starting with `0x82`- `0x820`, as `4095`, the greatest index we can have, has RLP encoding `0x820FFF`.
* `144` paths of length `4`, because...
	1. the indices `128..=255` map to length-4 full paths, and there are 128 of those (`0x8180..=0x81FF`)
	2. the indices `256..=4095` map to paths `0x820100..=0x820FFF`, for which there are 16 possible length-4 prefixes (`0x8201..=0x820F`)
* `240` paths of length `5`, because these are the 5-nibble prefixes of paths `0x820100..=0x820FFF`, namely `0x82010..=0x820FF`, of which there are 240.
* `3840` paths of length `6`, because these correspond to the leaves at indexes `256..=4095`.
