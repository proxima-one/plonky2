## EcGFp5 STARK

This module contains a STARK that performs arithmetic for [EcGFp5](https://github.com/pornin/ecgfp5), a native curve for Goldilocks. It performs point additions, point double-adds, and 32-bit Scalar multiplications.

Each point is two elements of a degree-5 extension field of Goldilocks, so each point is 10 columns.

The STARK assigns a two-bit opcode to the things it does:
* 00: add,
* 01: double and add
* 10: 32-bit scalar mul
* 00: illegal
 
### CTL Interface

The STARK is generic over the number of channels. For each channel, it exposes the following CTLs:
1. `ctl_cols_add`: the operation idx (identifying the operation performed), the opcode (checked), the LHS input point, the RHS input point, and the output point.
2. `ctl_cols_double_add`: the operation idx (identifying the poeration perfomed), the opcode (checked), the LHS input point, the RHS input point, and the output point.
3. `ctl_cols_scalar_mul_input`: the operation idx (identifying the operation performed), the opcode (checked), the input point, and the scalar.
4. `ctl_cols_scalar_mul_output`: the operation idx (identifying the operation performed), the opcode (checked), and the output point.
