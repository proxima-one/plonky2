pub(crate) const KECCAK_WIDTH_BYTES: usize = 200;
pub(crate) const KECCAK_WIDTH_U32S: usize = KECCAK_WIDTH_BYTES / 4;
pub(crate) const KECCAK_RATE_BYTES: usize = 136;
pub(crate) const KECCAK_RATE_U32S: usize = KECCAK_RATE_BYTES / 4;
pub(crate) const KECCAK_CAPACITY_BYTES: usize = 64;
pub(crate) const KECCAK_CAPACITY_U32S: usize = KECCAK_CAPACITY_BYTES / 4;

/// 00: stark padding 
/// 01: absorb
/// 10: squeeze
pub(crate) const MODE_BIT_0: usize = 0;
pub(crate) const MODE_BIT_1: usize = MODE_BIT_0 + 1;

pub(crate) const INPUT_FILTER: usize = MODE_BIT_1 + 1;
pub(crate) const OUTPUT_FILTER: usize = INPUT_FILTER + 1;
pub(crate) const INVOKE_PERMUTATION_FILTER: usize = OUTPUT_FILTER + 1;
pub(crate) const BLOCK_IDX: usize = INVOKE_PERMUTATION_FILTER + 1;
pub(crate) const HASH_IDX: usize = BLOCK_IDX + 1;
pub(crate) const LEN: usize = HASH_IDX + 1;
