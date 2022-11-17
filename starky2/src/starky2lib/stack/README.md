## Stack STARK

This module contains a STARK that checks the semantics of a trace of stack operations, which are expressed as a 3-tuple of field elements `(is_pop, value, timestamp)`. It is generic over the number of channels used.

### CTL Interface

For each channel, the STARK exposes one `CtlColSet` for the accesses on that channel, which contains three columns - `is_pop`, `value`, `timestamp`. It can be retrieved by calling the `ctl_cols` method in `layout.rs`.
