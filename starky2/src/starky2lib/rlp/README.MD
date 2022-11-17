## RLP STARK

This module contains a STARK that checks correctness of Ethereum RLP encodings of nested lists of data via three memories. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for more information about how it does this.

### CTL Interface

This STARK only has one channel. It exposes the following `CtlColSet`s with the following methods:
1. `input_memory_ctls()`: a 5-channel lookup to a read-only memory containing the input data structure. Each channel's colset has two columns: `addr` and `value`
2. `call_stack_ctls()`: a 3-channel lookup to a stack memory used as the state machine's call stack. Each channel's colset has three columns: `is_pop`, `value`, `timestamp`.
3. `output_stack_ctls()`: a 5-channel lookup to a read-only memory (not a stack - it's called a "stack" here because implementation-wise we write to it in a stack-like manner). Each channel's colset has two columns: `addr` and `value`.

