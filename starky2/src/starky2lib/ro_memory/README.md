## Read-Only Memory STARK

This module contains a STARK that checks the semantics of an access trace of a read-only memory using Cairo's memory arguent

### CTL Interface

For each channel, the STARK exposes one `CtlColSet` for the accesses on that channel, which contains two colums - `addr`, `value`. It can be retrieved via the `ctl_cols` function in `layout.rs`.
