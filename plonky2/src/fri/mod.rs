use crate::fri::reduction_strategies::FriReductionStrategy;

pub mod commitment;
pub mod proof;
pub mod prover;
pub mod recursive_verifier;
pub mod reduction_strategies;
pub mod verifier;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FriConfig {
    pub proof_of_work_bits: u32,

    pub reduction_strategy: FriReductionStrategy,

    /// Number of query rounds to perform.
    pub num_query_rounds: usize,
}

/// Parameters which are generated during preprocessing, in contrast to `FriConfig` which is
/// user-specified.
#[derive(Debug)]
pub(crate) struct FriParams {
    /// The arity of each FRI reduction step, expressed as the log2 of the actual arity.
    /// For example, `[3, 2, 1]` would describe a FRI reduction tree with 8-to-1 reduction, then
    /// a 4-to-1 reduction, then a 2-to-1 reduction. After these reductions, the reduced polynomial
    /// is sent directly.
    pub reduction_arity_bits: Vec<usize>,
}

impl FriParams {
    pub(crate) fn total_arities(&self) -> usize {
        self.reduction_arity_bits.iter().sum()
    }

    pub(crate) fn max_arity_bits(&self) -> Option<usize> {
        self.reduction_arity_bits.iter().copied().max()
    }
}