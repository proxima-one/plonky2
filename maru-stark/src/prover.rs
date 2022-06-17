use std::iter::once;

use anyhow::{ensure, Result};
use itertools::Itertools;
use plonky2::field::extension_field::Extendable;
use plonky2::field::field_types::Field;
use plonky2::field::packable::Packable;
use plonky2::field::packed_field::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_util::{log2_ceil, log2_strict};
use rayon::prelude::*;

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::permutation::PermutationCheckVars;
use crate::permutation::{
    compute_permutation_z_polys, get_n_permutation_challenge_sets, PermutationChallengeSet,
};
use crate::proof::{StarkOpeningSet, StarkProof, StarkProofWithPublicInputs};
use crate::public_memory::{
    compute_public_memory_z_polys, get_n_public_memory_challenges, MemoryAccessVars,
    PublicMemoryChallenge, PublicMemoryVars,
};
use crate::stark::Stark;
use crate::vanishing_poly::eval_vanishing_poly;
use crate::vars::StarkEvaluationVars;

pub fn prove<F, C, S, const D: usize>(
    stark: S,
    config: &StarkConfig,
    trace_poly_values: Vec<PolynomialValues<F>>,
    mut public_inputs: [F; S::PUBLIC_INPUTS],
    public_memory_accesses: Option<&[(F, F)]>,
    timing: &mut TimingTree,
) -> Result<StarkProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
    [(); <<F as Packable>::Packing>::WIDTH]:,
    [(); C::Hasher::HASH_SIZE]:,
{
    assert!(
        stark.uses_public_memory() == public_memory_accesses.is_some(),
        "`public_memory_accesses` should be `Some` iff `stark` uses public memory"
    );
    
    let degree = trace_poly_values[0].len();
    let degree_bits = log2_strict(degree);
    let fri_params = config.fri_params(degree_bits);
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;
    assert!(
        fri_params.total_arities() <= degree_bits + rate_bits - cap_height,
        "FRI total reduction arity is too large.",
    );

    let trace_commitment = timed!(
        timing,
        "compute trace commitment",
        PolynomialBatch::<F, C, D>::from_values(
            // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
            // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
            trace_poly_values.clone(),
            rate_bits,
            false,
            cap_height,
            timing,
            None,
        )
    );

    let trace_cap = trace_commitment.merkle_tree.cap.clone();
    let mut challenger = Challenger::new();
    challenger.observe_cap(&trace_cap);

    // Permutation arguments.
    let permutation_zs_commitment_challenges = stark.uses_permutation_args().then(|| {
        let permutation_challenge_sets = get_n_permutation_challenge_sets(
            &mut challenger,
            config.num_challenges,
            stark.permutation_batch_size(),
        );
        let permutation_z_polys = compute_permutation_z_polys::<F, C, S, D>(
            &stark,
            config,
            &trace_poly_values,
            &permutation_challenge_sets,
        );

        let permutation_zs_commitment = timed!(
            timing,
            "compute permutation Z commitments",
            PolynomialBatch::<F, C, D>::from_values(
                permutation_z_polys,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None,
            )
        );
        (permutation_zs_commitment, permutation_challenge_sets)
    });
    let permutation_zs_commitment = permutation_zs_commitment_challenges
        .as_ref()
        .map(|(comm, _)| comm);
    let permutation_zs_cap = permutation_zs_commitment
        .as_ref()
        .map(|commit| commit.merkle_tree.cap.clone());
    if let Some(cap) = &permutation_zs_cap {
        challenger.observe_cap(cap);
    }

    // public memory argument;
    let public_memory_zs_commitment_challenges = stark.uses_public_memory().then(|| {
        let public_memory_challenges =
            get_n_public_memory_challenges(&mut challenger, config.num_challenges);

        let public_memory_cols = S::public_memory_cols().unwrap();
        let width = S::public_memory_width();
        let memory_access_vars = MemoryAccessVars {
            addr_columns: &trace_poly_values[public_memory_cols[0]..public_memory_cols[0] + width],
            value_columns: &trace_poly_values[public_memory_cols[1]..public_memory_cols[1] + width],
            addr_sorted_columns: &trace_poly_values
                [public_memory_cols[2]..public_memory_cols[2] + width],
            value_sorted_columns: &trace_poly_values
                [public_memory_cols[3]..public_memory_cols[3] + width],
        };

        let public_memory_z_polys = compute_public_memory_z_polys::<F, C, S, D>(
            &stark,
            config,
            &memory_access_vars,
            &public_memory_challenges,
        );
        
        // set PIs to public memory product for each challenge
        let public_memory_accesses = public_memory_accesses.unwrap();
        let public_memory_pis = stark.public_memory_pis().unwrap();
        assert!(public_memory_challenges.len() == public_memory_pis.len() - 3);
        public_memory_pis[..public_memory_pis.len() - 3]
            .iter()
            .zip(public_memory_challenges.iter())
            .for_each(|(&i, &challenge)| {
                let PublicMemoryChallenge { alpha, z } = challenge;
                let num = public_memory_accesses
                    .iter()
                    .fold(F::ONE, |p, &(a, v)| p * (z - (a + alpha * v)));
                let denom = z.exp_u64(public_memory_accesses.len() as u64);
                public_inputs[i] = num * denom.inverse()
            });

        let public_memory_zs_commitment = timed!(
            timing,
            "compute public memory Z commitments",
            PolynomialBatch::<F, C, D>::from_values(
                public_memory_z_polys,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None
            )
        );
        (public_memory_zs_commitment, public_memory_challenges)
    });
    let public_memory_zs_commitment = public_memory_zs_commitment_challenges
        .as_ref()
        .map(|(commitment, _)| commitment);
    let public_memory_zs_cap = public_memory_zs_commitment
        .as_ref()
        .map(|commitment| commitment.merkle_tree.cap.clone());
    if let Some(cap) = &public_memory_zs_cap {
        challenger.observe_cap(cap);
    }

    let alphas = challenger.get_n_challenges(config.num_challenges);
    let quotient_polys = compute_quotient_polys::<F, <F as Packable>::Packing, C, S, D>(
        &stark,
        &trace_commitment,
        &permutation_zs_commitment_challenges,
        &public_memory_zs_commitment_challenges,
        public_inputs,
        alphas,
        degree_bits,
        config,
    );
    let all_quotient_chunks = quotient_polys
        .into_par_iter()
        .flat_map(|mut quotient_poly| {
            quotient_poly
                .trim_to_len(degree * stark.quotient_degree_factor())
                .expect("Quotient has failed, the vanishing polynomial is not divisible by Z_H");
            // Split quotient into degree-n chunks.
            quotient_poly.chunks(degree)
        })
        .collect();
    let quotient_commitment = timed!(
        timing,
        "compute quotient commitment",
        PolynomialBatch::from_coeffs(
            all_quotient_chunks,
            rate_bits,
            false,
            config.fri_config.cap_height,
            timing,
            None,
        )
    );
    let quotient_polys_cap = quotient_commitment.merkle_tree.cap.clone();
    challenger.observe_cap(&quotient_polys_cap);

    let zeta = challenger.get_extension_challenge::<D>();
    // To avoid leaking witness data, we want to ensure that our opening locations, `zeta` and
    // `g * zeta`, are not in our subgroup `H`. It suffices to check `zeta` only, since
    // `(g * zeta)^n = zeta^n`, where `n` is the order of `g`.
    let g = F::primitive_root_of_unity(degree_bits);
    ensure!(
        zeta.exp_power_of_2(degree_bits) != F::Extension::ONE,
        "Opening point is in the subgroup."
    );
    let openings = StarkOpeningSet::new(
        zeta,
        g,
        &trace_commitment,
        permutation_zs_commitment,
        public_memory_zs_commitment,
        &quotient_commitment,
    );
    challenger.observe_openings(&openings.to_fri_openings());

    let initial_merkle_trees = once(&trace_commitment)
        .chain(permutation_zs_commitment)
        .chain(public_memory_zs_commitment)
        .chain(once(&quotient_commitment))
        .collect_vec();

    let opening_proof = timed!(
        timing,
        "compute openings proof",
        PolynomialBatch::prove_openings(
            &stark.fri_instance(zeta, g, config),
            &initial_merkle_trees,
            &mut challenger,
            &fri_params,
            timing,
        )
    );
    let proof = StarkProof {
        trace_cap,
        permutation_zs_cap,
        public_memory_zs_cap,
        quotient_polys_cap,
        openings,
        opening_proof,
    };

    Ok(StarkProofWithPublicInputs {
        proof,
        public_inputs: public_inputs.to_vec(),
    })
}

/// Computes the quotient polynomials `(sum alpha^i C_i(x)) / Z_H(x)` for `alpha` in `alphas`,
/// where the `C_i`s are the Stark constraints.
fn compute_quotient_polys<'a, F, P, C, S, const D: usize>(
    stark: &S,
    trace_commitment: &'a PolynomialBatch<F, C, D>,
    permutation_zs_commitment_challenges: &'a Option<(
        PolynomialBatch<F, C, D>,
        Vec<PermutationChallengeSet<F>>,
    )>,
    public_memory_zs_commitment_challenges: &'a Option<(
        PolynomialBatch<F, C, D>,
        Vec<PublicMemoryChallenge<F>>,
    )>,
    public_inputs: [F; S::PUBLIC_INPUTS],
    alphas: Vec<F>,
    degree_bits: usize,
    config: &StarkConfig,
) -> Vec<PolynomialCoeffs<F>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar = F>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
    [(); P::WIDTH]:,
{
    let degree = 1 << degree_bits;
    let rate_bits = config.fri_config.rate_bits;

    let quotient_degree_bits = log2_ceil(stark.quotient_degree_factor());
    assert!(
        quotient_degree_bits <= rate_bits,
        "Having constraints of degree higher than the rate is not supported yet."
    );
    let step = 1 << (rate_bits - quotient_degree_bits);
    // When opening the `Z`s polys at the "next" point, need to look at the point `next_step` steps away.
    let next_step = 1 << quotient_degree_bits;

    // Evaluation of the first Lagrange polynomial on the LDE domain.
    let lagrange_first = PolynomialValues::selector(degree, 0).lde_onto_coset(quotient_degree_bits);
    // Evaluation of the last Lagrange polynomial on the LDE domain.
    let lagrange_last =
        PolynomialValues::selector(degree, degree - 1).lde_onto_coset(quotient_degree_bits);

    let z_h_on_coset = ZeroPolyOnCoset::<F>::new(degree_bits, quotient_degree_bits);

    // Retrieve the LDE values at index `i`.
    let get_trace_values_packed = |i_start| -> [P; S::COLUMNS] {
        trace_commitment
            .get_lde_values_packed(i_start, step)
            .try_into()
            .unwrap()
    };

    // Last element of the subgroup.
    let last = F::primitive_root_of_unity(degree_bits).inverse();
    let size = degree << quotient_degree_bits;
    let coset = F::cyclic_subgroup_coset_known_order(
        F::primitive_root_of_unity(degree_bits + quotient_degree_bits),
        F::coset_shift(),
        size,
    );

    // We will step by `P::WIDTH`, and in each iteration, evaluate the quotient polynomial at
    // a batch of `P::WIDTH` points.
    let quotient_values = (0..size)
        .into_par_iter()
        .step_by(P::WIDTH)
        .map(|i_start| {
            let i_next_start = (i_start + next_step) % size;
            let i_range = i_start..i_start + P::WIDTH;

            let x = *P::from_slice(&coset[i_range.clone()]);
            let z_last = x - last;
            let lagrange_basis_first = *P::from_slice(&lagrange_first.values[i_range.clone()]);
            let lagrange_basis_last = *P::from_slice(&lagrange_last.values[i_range]);

            let mut consumer = ConstraintConsumer::new(
                alphas.clone(),
                z_last,
                lagrange_basis_first,
                lagrange_basis_last,
            );
            let vars = StarkEvaluationVars {
                local_values: &get_trace_values_packed(i_start),
                next_values: &get_trace_values_packed(i_next_start),
                public_inputs: &public_inputs,
            };
            let permutation_check_data = permutation_zs_commitment_challenges.as_ref().map(
                |(permutation_zs_commitment, permutation_challenge_sets)| PermutationCheckVars {
                    local_zs: permutation_zs_commitment.get_lde_values_packed(i_start, step),
                    next_zs: permutation_zs_commitment.get_lde_values_packed(i_next_start, step),
                    permutation_challenge_sets: permutation_challenge_sets.to_vec(),
                },
            );
            let public_memory_check_data: Option<PublicMemoryVars<F, F, P, 1>> =
                public_memory_zs_commitment_challenges.as_ref().map(
                    |(zs_commitment, challenges)| {
                        let public_memory_pis = stark.public_memory_pis().unwrap();
                        let public_memory_cols = S::public_memory_cols().unwrap();
                        let addr_cols_start = public_memory_cols[0];
                        let mem_cols_start = public_memory_cols[1];
                        let addr_sorted_cols_start = public_memory_cols[2];
                        let mem_sorted_cols_start = public_memory_cols[3];
                        PublicMemoryVars {
                            local_cumulative_products: zs_commitment
                                .get_lde_values_packed(i_start, step),
                            next_cumulative_products: zs_commitment
                                .get_lde_values_packed(i_next_start, step),
                            public_memory_challenges: challenges.to_vec(),
                            public_memory_pis,
                            addr_cols_start,
                            mem_cols_start,
                            addr_sorted_cols_start,
                            mem_sorted_cols_start,
                        }
                    },
                );
            eval_vanishing_poly::<F, F, P, C, S, D, 1>(
                stark,
                config,
                vars,
                permutation_check_data,
                public_memory_check_data,
                &mut consumer,
            );
            let mut constraints_evals = consumer.accumulators();
            // We divide the constraints evaluations by `Z_H(x)`.
            let denominator_inv = z_h_on_coset.eval_inverse_packed(i_start);
            for eval in &mut constraints_evals {
                *eval *= denominator_inv;
            }
            constraints_evals
        })
        .collect::<Vec<_>>();

    transpose(&quotient_values)
        .into_par_iter()
        .map(PolynomialValues::new)
        .map(|values| values.coset_ifft(F::coset_shift()))
        .collect()
}
