## Keccak256 Sponge STARK

This module contains a STARK that emulates a `keccak256` sponge by feeding it input block-by-block via a CTL. this is done by including an index in the CTL columns. It internally uses the `keccak_f` STARK and the `xor` stark and requires one to set up those CTLs as well.

### CTL Interface

The STARK itself has only one channel. There are seven CTLs being performed, and some of them are multi-channel:
1. `xor_ctl_cols_a` - a 34-channel CTL for a 32-bit XOR's LHS input, used to XOR the current block into the state. See the `xor` STARK for more information.
2. `xor_ctl_cols_b` - a 34-channel CTL for a 32-bit XOR's RHS input, used to XOR the current block into the state. See the `xor` STARK for more information.
3. `xor_ctl_cols_output` - a 34-channel CTL for a 32-bit XOR's output, used to XOR the current block into the state. See the `xor` STARK for more information.
4. `keccak_ctl_col_input` - a CTL for the input to `keccak_f`, the state after the current block has been XOR'd in. Contains 50 colums for the state in 32-bit chunks.
5. `keccak_ctl_col_output` - a CTL for the output from `keccak_f`, the permuted state. Contains 50 columns for the state in 32-bit chunks.
6. `input_ctl_col` - 34 CTLs for the current input block. Contains "encoded" input, where the index of the block and hash instance are encoded in the high bits of the field element. See the note below for more information about this
7. `output_ctl_col` - 34 CTLs for the hash output. Contains 34 colums, since the sponge rate is 34 32-bit chunks. The "looking" STARK can only apply the lookup on the first 8 columns if they only care about the first 256-bits of output (i.e. if they were doing `keccak256` hashes).

#### Input encoding

The input encoding for every 32-bit chunk of an input block is as follows:
* bits 0..32: the 32-bit chunk of the current block
* bits 32..48: 16-bit current hash index, which identifies the instance of the sponge this input is for.
* bits 48..63: 15-bit current block index, which identifies the order in which this block should appear in the sponge's input.

This necesarily means that one cann't perform more that 2^16 hashes in one instance of this STARK, nor can any hash accept more than 2^15 blocks as input.

> That said, this STARK was written before using an older implementation of CTLs that only allowed looking up one column at a time, requiring us to embed this exta information to prevent the prover from re-ordering the input blocks. Now that the CTLs are have been generalized via `CtlColSet`s, this encoding is wholly unnecessary. Instead we can just do a single CTL containing 36 columns - 34 for the 32-bit chunks, one for the hash index, and another for the block index.
