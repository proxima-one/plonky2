use std::collections::HashSet;

use plonky2_field::extension::Extendable;
use plonky2_field::polynomial::PolynomialCoeffs;

use crate::fri::proof::{CompressedFriProof, FriChallenges, FriProof, FriProofTarget};
use crate::fri::verifier::{compute_evaluation, fri_combine_initial, PrecomputedReducedOpenings};
use crate::gadgets::polynomial::PolynomialCoeffsExtTarget;
use crate::hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField};
use crate::hash::merkle_tree::MerkleCap;
use crate::iop::challenger::{Challenger, RecursiveChallenger};
use crate::iop::target::Target;
use crate::plonk::circuit_builder::CircuitBuilder;
use crate::plonk::circuit_data::CommonCircuitData;
use crate::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use crate::plonk::proof::{
    CompressedProof, CompressedProofWithPublicInputs, FriInferredElements, OpeningSet,
    OpeningSetTarget, Proof, ProofChallenges, ProofChallengesTarget, ProofTarget,
    ProofWithPublicInputs, ProofWithPublicInputsTarget,
};
use crate::util::reverse_bits;

pub(crate) fn get_challenges<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    public_inputs_hash: <<C as GenericConfig<D>>::InnerHasher as Hasher<F>>::Hash,
    wires_cap: &MerkleCap<F, C::Hasher>,
    plonk_zs_partial_products_cap: &MerkleCap<F, C::Hasher>,
    quotient_polys_cap: &MerkleCap<F, C::Hasher>,
    openings: &OpeningSet<F, D>,
    commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
    final_poly: &PolynomialCoeffs<F::Extension>,
    pow_witness: F,
    circuit_digest: <<C as GenericConfig<D>>::Hasher as Hasher<F>>::Hash,
    degree_bits: usize,
    num_challenges: usize,
    fri_num_query_rounds: usize,
    fri_rate_bits: usize,
) -> anyhow::Result<ProofChallenges<F, D>> {
    let mut challenger = Challenger::<F, C::Hasher>::new();

    // Observe the instance.
    challenger.observe_hash::<C::Hasher>(circuit_digest);
    challenger.observe_hash::<C::InnerHasher>(public_inputs_hash);

    challenger.observe_cap(wires_cap);

    let plonk_betas = challenger.get_n_challenges(num_challenges);

    let plonk_gammas = challenger.get_n_challenges(num_challenges);

    challenger.observe_cap(plonk_zs_partial_products_cap);

    let plonk_alphas = challenger.get_n_challenges(num_challenges);

    #[cfg(target_os = "solana")]
    solana_program::msg!("yo");

    #[cfg(target_os = "solana")]
    solana_program::log::sol_log_compute_units();

    challenger.observe_cap(quotient_polys_cap);
    let plonk_zeta = challenger.get_extension_challenge::<D>();

    challenger.observe_openings_iter(&mut openings.iter_fri_openings());

    #[cfg(target_os = "solana")]
    solana_program::msg!("yo");

    Ok(ProofChallenges {
        plonk_betas,
        plonk_gammas,
        plonk_alphas,
        plonk_zeta,
        fri_challenges: challenger.buffer_verifier_fri_challenges::<C, D>(
            commit_phase_merkle_caps,
            final_poly,
            pow_witness,
            degree_bits,
            fri_num_query_rounds,
            fri_rate_bits,
        ),
    })
}

impl<F: RichField, H: Hasher<F>> Challenger<F, H> {
    pub fn buffer_verifier_fri_challenges<C: GenericConfig<D, F = F>, const D: usize>(
        &mut self,
        commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
        final_poly: &PolynomialCoeffs<F::Extension>,
        pow_witness: F,
        degree_bits: usize,
        num_query_rounds: usize,
        rate_bits: usize,
    ) -> FriChallenges<F, D>
    where
        F: RichField + Extendable<D>,
    {
        let num_fri_queries = num_query_rounds;
        let lde_size = 1 << (degree_bits + rate_bits);
        // Scaling factor to combine polynomials.
        let fri_alpha = self.get_extension_challenge::<D>();

        // Recover the random betas used in the FRI reductions.
        let fri_betas = commit_phase_merkle_caps
            .iter()
            .map(|cap| {
                self.observe_cap(cap);
                self.get_extension_challenge::<D>()
            })
            .collect();

        self.observe_extension_elements(&final_poly.coeffs);

        let fri_pow_response = C::InnerHasher::hash_no_pad(
            &self
                .get_hash()
                .elements
                .iter()
                .copied()
                .chain(Some(pow_witness))
                .collect::<Vec<_>>(),
        )
        .elements[0];

        let fri_query_indices = (0..num_fri_queries)
            .map(|_| self.get_challenge().to_canonical_u64() as usize % lde_size)
            .collect();

        FriChallenges {
            fri_alpha,
            fri_betas,
            fri_pow_response,
            fri_query_indices,
        }
    }
}
