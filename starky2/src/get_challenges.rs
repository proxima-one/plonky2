use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::fri::proof::{FriProof, FriProofTarget};
use plonky2::gadgets::polynomial::PolynomialCoeffsExtTarget;
use plonky2::hash::hash_types::{MerkleCapTarget, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::{Challenger, RecursiveChallenger};
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};

use crate::config::StarkConfig;
use crate::cross_table_lookup::CtlDescriptor;
use crate::permutation::{
    get_n_permutation_challenge_sets, get_n_permutation_challenge_sets_target,
};
use crate::proof::*;
use crate::stark::Stark;

// makes a challenger and overves the trace caps
pub fn start_all_proof_challenger<'a, F, C, I, const D: usize>(
    trace_caps: I,
) -> Challenger<F, C::Hasher>
where
    I: Iterator<Item = &'a MerkleCap<F, C::Hasher>>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: 'a,
{
    let mut challenger = Challenger::<F, C::Hasher>::new();

    for cap in trace_caps {
        challenger.observe_cap(cap);
    }

    return challenger;
}

// assumes `start_all_proof_challenges` was used to get the challenger
pub fn get_ctl_challenges<F, C, const D: usize>(
    challenger: &mut Challenger<F, C::Hasher>,
    ctl_descriptor: &CtlDescriptor,
    num_challenges: usize,
) -> Vec<Vec<F>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    ctl_descriptor
        .instances
        .iter()
        .map(|_| challenger.get_n_challenges(num_challenges))
        .collect()
}

// IMPORTANT: assumes `challenger` has already observed the trace caps and the ctl challenges have already been extracted
fn get_single_table_challenges<F, C, S, const D: usize>(
    stark: &S,
    challenger: &mut Challenger<F, C::Hasher>,
    permutation_zs_cap: Option<&MerkleCap<F, C::Hasher>>,
    ctl_zs_cap: Option<&MerkleCap<F, C::Hasher>>,
    quotient_polys_cap: &MerkleCap<F, C::Hasher>,
    openings: &StarkOpeningSet<F, D>,
    commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
    final_poly: &PolynomialCoeffs<F::Extension>,
    pow_witness: F,
    config: &StarkConfig,
    degree_bits: usize,
) -> StarkProofChallenges<F, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let num_challenges = config.num_challenges;
    let permutation_challenge_sets = permutation_zs_cap.map(|permutation_zs_cap| {
        let tmp = get_n_permutation_challenge_sets(
            challenger,
            num_challenges,
            stark.permutation_batch_size(),
        );
        challenger.observe_cap(permutation_zs_cap);
        tmp
    });

    if let Some(cap) = ctl_zs_cap {
        challenger.observe_cap(cap);
    }

    let stark_alphas = challenger.get_n_challenges(num_challenges);

    challenger.observe_cap(quotient_polys_cap);

    let stark_zeta = challenger.get_extension_challenge::<D>();

    challenger.observe_openings(&openings.to_fri_openings());

    let fri_challenges = challenger.fri_challenges::<C, D>(
        commit_phase_merkle_caps,
        final_poly,
        pow_witness,
        degree_bits,
        &config.fri_config,
    );

    StarkProofChallenges {
        permutation_challenge_sets,
        stark_alphas,
        stark_zeta,
        fri_challenges
    }
}

fn get_stark_challenges<F, C, S, const D: usize>(
    stark: &S,
    trace_cap: &MerkleCap<F, C::Hasher>,
    permutation_zs_cap: Option<&MerkleCap<F, C::Hasher>>,
    quotient_polys_cap: &MerkleCap<F, C::Hasher>,
    openings: &StarkOpeningSet<F, D>,
    commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
    final_poly: &PolynomialCoeffs<F::Extension>,
    pow_witness: F,
    config: &StarkConfig,
    degree_bits: usize,
) -> StarkProofChallenges<F, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let num_challenges = config.num_challenges;

    let mut challenger = Challenger::<F, C::Hasher>::new();

    challenger.observe_cap(trace_cap);

    let permutation_challenge_sets = permutation_zs_cap.map(|permutation_zs_cap| {
        let tmp = get_n_permutation_challenge_sets(
            &mut challenger,
            num_challenges,
            stark.permutation_batch_size(),
        );
        challenger.observe_cap(permutation_zs_cap);
        tmp
    });

    let stark_alphas = challenger.get_n_challenges(num_challenges);

    challenger.observe_cap(quotient_polys_cap);
    let stark_zeta = challenger.get_extension_challenge::<D>();

    challenger.observe_openings(&openings.to_fri_openings());

    StarkProofChallenges {
        permutation_challenge_sets,
        stark_alphas,
        stark_zeta,
        fri_challenges: challenger.fri_challenges::<C, D>(
            commit_phase_merkle_caps,
            final_poly,
            pow_witness,
            degree_bits,
            &config.fri_config,
        ),
    }
}

impl<F, C, const D: usize> StarkProofWithPublicInputs<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // TODO: Should be used later in compression?
    #![allow(dead_code)]
    pub(crate) fn fri_query_indices_no_ctl<S: Stark<F, D>>(
        &self,
        stark: &S,
        config: &StarkConfig,
        degree_bits: usize,
    ) -> Vec<usize> {
        self.get_stark_challenges_no_ctl(stark, config, degree_bits)
            .fri_challenges
            .fri_query_indices
    }

    /// Computes Fiat-Shamir challenges for this specific proof within an `AllProof`
    pub(crate) fn get_stark_challenges_with_ctl<S: Stark<F, D>>(
        &self,
        stark: &S,
        config: &StarkConfig,
        challenger: &mut Challenger<F, C::Hasher>,
        degree_bits: usize,
    ) -> StarkProofChallenges<F, D> {
        let StarkProof {
            trace_cap: _,
            permutation_zs_cap,
            ctl_zs_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProof {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
        } = &self.proof;

        get_single_table_challenges::<F, C, S, D>(
            stark,
            challenger,
            permutation_zs_cap.as_ref(),
            ctl_zs_cap.as_ref(),
            quotient_polys_cap,
            openings,
            commit_phase_merkle_caps,
            final_poly,
            *pow_witness,
            config,
            degree_bits,
        )
    }

    /// Computes all Fiat-Shamir challenges used in the STARK proof.
    pub(crate) fn get_stark_challenges_no_ctl<S: Stark<F, D>>(
        &self,
        stark: &S,
        config: &StarkConfig,
        degree_bits: usize,
    ) -> StarkProofChallenges<F, D> {
        let StarkProof {
            trace_cap,
            permutation_zs_cap,
            ctl_zs_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProof {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
        } = &self.proof;

        assert!(
            ctl_zs_cap.is_none(),
            "CTLs not supported in `get_stark_challenges`"
        );

        get_stark_challenges::<F, C, S, D>(
            stark,
            trace_cap,
            permutation_zs_cap.as_ref(),
            quotient_polys_cap,
            openings,
            commit_phase_merkle_caps,
            final_poly,
            *pow_witness,
            config,
            degree_bits,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn get_challenges_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    trace_cap: &MerkleCapTarget,
    permutation_zs_cap: Option<&MerkleCapTarget>,
    quotient_polys_cap: &MerkleCapTarget,
    openings: &StarkOpeningSetTarget<D>,
    commit_phase_merkle_caps: &[MerkleCapTarget],
    final_poly: &PolynomialCoeffsExtTarget<D>,
    pow_witness: Target,
    config: &StarkConfig,
) -> StarkProofChallengesTarget<D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let num_challenges = config.num_challenges;

    let mut challenger = RecursiveChallenger::<F, C::Hasher, D>::new(builder);

    challenger.observe_cap(trace_cap);

    let permutation_challenge_sets = permutation_zs_cap.map(|permutation_zs_cap| {
        let tmp = get_n_permutation_challenge_sets_target(
            builder,
            &mut challenger,
            num_challenges,
            stark.permutation_batch_size(),
        );
        challenger.observe_cap(permutation_zs_cap);
        tmp
    });

    let stark_alphas = challenger.get_n_challenges(builder, num_challenges);

    challenger.observe_cap(quotient_polys_cap);
    let stark_zeta = challenger.get_extension_challenge(builder);

    let zero = builder.zero();
    challenger.observe_openings(&openings.to_fri_openings(zero));

    StarkProofChallengesTarget {
        permutation_challenge_sets,
        stark_alphas,
        stark_zeta,
        fri_challenges: challenger.fri_challenges::<C>(
            builder,
            commit_phase_merkle_caps,
            final_poly,
            pow_witness,
            &config.fri_config,
        ),
    }
}

impl<const D: usize> StarkProofWithPublicInputsTarget<D> {
    pub(crate) fn get_challenges<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        S: Stark<F, D>,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        stark: &S,
        config: &StarkConfig,
    ) -> StarkProofChallengesTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let StarkProofTarget {
            trace_cap,
            permutation_zs_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProofTarget {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
        } = &self.proof;

        get_challenges_target::<F, C, S, D>(
            builder,
            stark,
            trace_cap,
            permutation_zs_cap.as_ref(),
            quotient_polys_cap,
            openings,
            commit_phase_merkle_caps,
            final_poly,
            *pow_witness,
            config,
        )
    }
}

// TODO: Deal with the compressed stuff.
// impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
//     CompressedProofWithPublicInputs<F, C, D>
// {
//     /// Computes all Fiat-Shamir challenges used in the Plonk proof.
//     pub(crate) fn get_challenges(
//         &self,
//         common_data: &CommonCircuitData<F, C, D>,
//     ) -> anyhow::Result<ProofChallenges<F, D>> {
//         let CompressedProof {
//             wires_cap,
//             plonk_zs_partial_products_cap,
//             quotient_polys_cap,
//             openings,
//             opening_proof:
//                 CompressedFriProof {
//                     commit_phase_merkle_caps,
//                     final_poly,
//                     pow_witness,
//                     ..
//                 },
//         } = &self.proof;
//
//         get_challenges(
//             self.get_public_inputs_hash(),
//             wires_cap,
//             plonk_zs_partial_products_cap,
//             quotient_polys_cap,
//             openings,
//             commit_phase_merkle_caps,
//             final_poly,
//             *pow_witness,
//             common_data,
//         )
//     }
//
//     /// Computes all coset elements that can be inferred in the FRI reduction steps.
//     pub(crate) fn get_inferred_elements(
//         &self,
//         challenges: &ProofChallenges<F, D>,
//         common_data: &CommonCircuitData<F, C, D>,
//     ) -> FriInferredElements<F, D> {
//         let ProofChallenges {
//             plonk_zeta,
//             fri_alpha,
//             fri_betas,
//             fri_query_indices,
//             ..
//         } = challenges;
//         let mut fri_inferred_elements = Vec::new();
//         // Holds the indices that have already been seen at each reduction depth.
//         let mut seen_indices_by_depth =
//             vec![HashSet::new(); common_data.fri_params.reduction_arity_bits.len()];
//         let precomputed_reduced_evals = PrecomputedReducedOpenings::from_os_and_alpha(
//             &self.proof.openings.to_fri_openings(),
//             *fri_alpha,
//         );
//         let log_n = common_data.degree_bits + common_data.config.fri_config.rate_bits;
//         // Simulate the proof verification and collect the inferred elements.
//         // The content of the loop is basically the same as the `fri_verifier_query_round` function.
//         for &(mut x_index) in fri_query_indices {
//             let mut subgroup_x = F::MULTIPLICATIVE_GROUP_GENERATOR
//                 * F::primitive_root_of_unity(log_n).exp_u64(reverse_bits(x_index, log_n) as u64);
//             let mut old_eval = fri_combine_initial::<F, C, D>(
//                 &common_data.get_fri_instance(*plonk_zeta),
//                 &self
//                     .proof
//                     .opening_proof
//                     .query_round_proofs
//                     .initial_trees_proofs[&x_index],
//                 *fri_alpha,
//                 subgroup_x,
//                 &precomputed_reduced_evals,
//                 &common_data.fri_params,
//             );
//             for (i, &arity_bits) in common_data
//                 .fri_params
//                 .reduction_arity_bits
//                 .iter()
//                 .enumerate()
//             {
//                 let coset_index = x_index >> arity_bits;
//                 if !seen_indices_by_depth[i].insert(coset_index) {
//                     // If this index has already been seen, we can skip the rest of the reductions.
//                     break;
//                 }
//                 fri_inferred_elements.push(old_eval);
//                 let arity = 1 << arity_bits;
//                 let mut evals = self.proof.opening_proof.query_round_proofs.steps[i][&coset_index]
//                     .evals
//                     .clone();
//                 let x_index_within_coset = x_index & (arity - 1);
//                 evals.insert(x_index_within_coset, old_eval);
//                 old_eval = compute_evaluation(
//                     subgroup_x,
//                     x_index_within_coset,
//                     arity_bits,
//                     &evals,
//                     fri_betas[i],
//                 );
//                 subgroup_x = subgroup_x.exp_power_of_2(arity_bits);
//                 x_index = coset_index;
//             }
//         }
//         FriInferredElements(fri_inferred_elements)
//     }
// }
