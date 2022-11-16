## XOR STARK

This is a very narrow STARK that performs XORs via bit decompositions, one each row. It is generic over the number of bits (maximum of 63 due to goldilocks) and the number of channels.

### CTL Interface

`xor` exposes three `CtlColSet`s for CTLs on each channel:
* `a`: a single column representing the LHS argument to the XOR
* `b`: a single column representing the RHS argument to the XOR
* `c`: a single column reperseenting the XOR'd output

These can be retrieved by instantiating an `XorLayout<F, N, NUM_CHANNELS>` for the desired number of bits `N` and the number of channels `NUM_CHANNELS`, and calling the `ctl_cols_a`, `ctl_cols_b`, and `ctl_cols_c` methods on it.
