### Starky2lib

This module contains finished prototype STARKs for the following:
* `depth_5_merkle_tree`: a STARK that constructs a depth-5-merkle tree generically from any STARK that implements a suitable hash with a 8x32 bit digest
* `ecgfp5`: A STARK that implments variable-time curve arithmetic for [EcGFp5](https://github.com/pornin/ecgfp5), Goldilocks' native elliptic curve defined over its degree-5 extension field
* `sha2_compression`: A STARK that implements the sha2 compression function used in sha256.
* `keccak_f`: A STARK that implements the keccak permutation with the parameters Ethereum uses. This is a fork of the keccak-f STARK in the `evm` crate
* `keccak256_sponge`: A STARK that implements the sponge for `keccak256`, the hash function Ethereum uses.
* `ro_memory`: A STARK that checks the semantics of read-only memory accesses.
* `rw_memory`: A STARK that checks the semantics of read-write memory accesses.
* `stack`: A STARK that checks the semantics of stack memory accesses.
* `slice_check`: A STARK that checks that two equal-length slices in different memories have identical contents.
* `rlp`: a STARK that takes a memory containing recursive structured lists and checks a memory of claimed Ethereum RLP encodings for those lists.

The following are still as-of-yet unfinished
* `keccak256_memory`: same as `keccak256_sponge`, but it reads from an `ro_memory` STARK via CTLs. See its readme for more information.
* `ecgfp5_to_cruve`: variable-time `map_to_curve` for elements of `GF(p^5)`, a degree-5 extension field of Goldilocks
* `idx_keyed_trie`: a STARK that reads from and uses multiple memories to, given a list of values, compute the root of an Ethereum modified merkle patricia tree where the corresponding key to the `i`th value is the index `i`.
