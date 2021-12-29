use plonky2::fri::{FriConfig, FriParams};

pub struct StarkConfig {
    pub security_bits: usize,

    /// The number of challenge points to generate, for IOPs that have soundness errors of (roughly)
    /// `degree / |F|`.
    pub num_challenges: usize,

    pub fri_config: FriConfig,
}

impl StarkConfig {
    pub(crate) fn fri_params(&self, degree_bits: usize) -> FriParams {
        let fri_config = &self.fri_config;
        let reduction_arity_bits = fri_config.reduction_strategy.reduction_arity_bits(
            degree_bits,
            fri_config.rate_bits,
            fri_config.num_query_rounds,
        );
        FriParams {
            config: fri_config.clone(),
            hiding: false,
            degree_bits,
            reduction_arity_bits,
        }
    }
}
