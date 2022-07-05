# Streaming Verifier

This is a verifier that works directly on buffers. It is used by the `solana-verifier` to split the verifier across several transactions without having to make copies or pay for deserialization every time.

### Buffer Layout

The verifier expects two buffers:
1. `proof_buf`: Buffer containing the proof data - read-only, except for the first step
2. `circuit_buf`: Buffer containing the circuit data - read-only

The layout below is a re-ordering of the `Proof` and `CircuitData` structs such that the verifier gets exactly the data it needs, when it needs it, by performing a linear scan. Each element appears one-after-the-other, with no separators, packed directly into the buffer.

#### `proof_buf` layout
`len`
`wires_cap_offset`
`plonk_zs_pp_cap_offset`
`quotient_polys_cap_offset`
`constants_offset`
`plonk_sigmas_offset`
`wires_offset`
`plonk_zs_offset`
`pps_offset`
`quotient_polys_offset`
`plonk_zs_next_offset`
`challenge_betas_offset`
`challenge_gammas_offset`
`challenge_alphas_offset`
`challenge_zeta_offset`
`fri_alpha_offset`
`fri_pow_offset`
`fri_betas_offset`
`fri_query_indices_offset`
`proof.public_inputs_hash`
`proof.wires_cap`
`proof.plonk_zs_partial_products_cap`
`proof.quotient_polys_cap`
`proof.openings.constants`
`proof.openings.plonk_sigmas`
`proof.openings.wires`
`proof.openings.plonk_zs`
`proof.openings.partial_products`
`proof.openings.quotient_polys`
`proof.openings.plonk_zs_next`
`proof.challenges.plonk_betas`
`proof.challenges.plonk_gammas`
`proof.challenges.plonk_alphas`
`proof.challenges.plonk_zeta`
`proof.challenges.fri_challenges.fri_alpha`
`proof.challenges.fri_challenges.fri_pow_response`
`proof.challenges.fri_challenges.fri_betas`
`proof.challenges.fri_challenges.fri_query_indices`

The challenges are zeroed initially and written by the first step of the verifier.

#### `circuit_buf`
`len`
`circuit_digest_offset`
`num_challenges_offset`
`num_gate_constraints_offset`
`gates_offset`
`selector_indicies_offset`
`selector_groups_offset`
`degree_bits_offset`
`num_routed_wires_offset`
`k_is_offset`
`num_partial_products_offset`
`quotient_degree_factor_offset`
`sigmas_cap_offset`
`fri_instance_oracles_offset`
`fri_instance_batches_offset`
`common_data.circuit_digest`
`common_data.config.num_challenges`
`common_data.num_gate_constraints`
`common_data.gates`
`common_data.selectors_info.selector_indices`
`common_data.selectors_info.groups`
`common_data.degree_bits`
`common_data.config.num_routed_wires`
`common_data.k_is`
`common_data.num_partial_products`
`common_data.quotient_degree_factor`
`verifier_data.constants_sigmas_cap`
`fri_instance_info.oracles`
`fri_isntance_info.batches`


The fri_instance_info fields are zeroed initially and written by an initialization method
