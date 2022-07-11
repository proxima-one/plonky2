use anyhow::{ensure, Result};
use plonky2_field::extension::{flatten, Extendable, FieldExtension};
use plonky2_field::interpolation::{barycentric_weights, interpolate};
use plonky2_field::polynomial::PolynomialCoeffs;
use plonky2_field::types::Field;
use plonky2_util::{log2_strict, reverse_index_bits_in_place};

use crate::fri::proof::{FriChallenges, FriInitialTreeProof, FriProof, FriQueryRound};
use crate::fri::structure::{FriBatchInfo, FriInstanceInfo, FriOpenings, FriPolynomialInfo};
use crate::fri::{FriConfig, FriParams};
use crate::hash::hash_types::RichField;
use crate::hash::merkle_proofs::verify_merkle_proof_to_cap;
use crate::hash::merkle_tree::MerkleCap;
use crate::plonk::config::{GenericConfig, Hasher};
use crate::plonk::plonk_common::{PlonkOracle, FRI_ORACLES};
use crate::util::reducing::ReducingFactor;
use crate::util::reverse_bits;

/// Computes P'(x^arity) from {P(x*g^i)}_(i=0..arity), where g is a `arity`-th root of unity
/// and P' is the FRI reduced polynomial.
pub(crate) fn compute_evaluation<F: Field + Extendable<D>, const D: usize>(
    x: F,
    x_index_within_coset: usize,
    arity_bits: usize,
    evals: &[F::Extension],
    beta: F::Extension,
) -> F::Extension {
    let arity = 1 << arity_bits;
    debug_assert_eq!(evals.len(), arity);

    let g = F::primitive_root_of_unity(arity_bits);

    // The evaluation vector needs to be reordered first.
    let mut evals = evals.to_vec();
    reverse_index_bits_in_place(&mut evals);
    let rev_x_index_within_coset = reverse_bits(x_index_within_coset, arity_bits);
    let coset_start = x * g.exp_u64((arity - rev_x_index_within_coset) as u64);
    // The answer is gotten by interpolating {(x*g^i, P(x*g^i))} and evaluating at beta.
    let points = g
        .powers()
        .map(|y| (coset_start * y).into())
        .zip(evals)
        .collect::<Vec<_>>();
    let barycentric_weights = barycentric_weights(&points);
    interpolate(&points, beta, &barycentric_weights)
}

pub(crate) fn fri_verify_proof_of_work<F: RichField + Extendable<D>, const D: usize>(
    fri_pow_response: F,
    fri_pow_bits: u32,
) -> Result<()> {
    ensure!(
        fri_pow_response.to_canonical_u64().leading_zeros()
            >= fri_pow_bits + (64 - F::order().bits()) as u32,
        "Invalid proof of work witness."
    );

    Ok(())
}

pub(crate) fn precompute_reduced_evals<F: RichField + Extendable<D>, const D: usize>(
    openings: &FriOpenings<F, D>,
    alpha: F::Extension,
) -> PrecomputedReducedOpenings<F, D> {
    PrecomputedReducedOpenings::from_os_and_alpha(openings, alpha)
}

fn fri_verify_initial_proof<F: RichField, H: Hasher<F>>(
    x_index: usize,
    proof: &FriInitialTreeProof<F, H>,
    initial_merkle_caps: &[MerkleCap<F, H>],
) -> Result<()>
where
    [(); H::HASH_SIZE]:,
{
    for ((evals, merkle_proof), cap) in proof.evals_proofs.iter().zip(initial_merkle_caps) {
        println!("verifying initial merkle proof");
        verify_merkle_proof_to_cap::<F, H>(evals.clone(), x_index, cap, merkle_proof)?;
    }

    Ok(())
}

pub(crate) fn fri_combine_initial<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    instance: &FriInstanceInfo<F, D>,
    proof: &FriInitialTreeProof<F, C::Hasher>,
    alpha: F::Extension,
    subgroup_x: F,
    precomputed_reduced_evals: &PrecomputedReducedOpenings<F, D>,
    hiding: bool,
) -> F::Extension {
    assert!(D > 1, "Not implemented for D=1.");
    let subgroup_x = F::Extension::from_basefield(subgroup_x);
    let mut alpha = ReducingFactor::new(alpha);
    let mut sum = F::Extension::ZERO;

    for (batch, reduced_openings) in instance
        .batches
        .iter()
        .zip(&precomputed_reduced_evals.reduced_openings_at_point)
    {
        let FriBatchInfo { point, polynomials } = batch;
        let evals = polynomials
            .iter()
            .map(|p| {
                let poly_blinding = instance.oracles[p.oracle_index].blinding;
                let salted = hiding && poly_blinding;
                proof.unsalted_eval(p.oracle_index, p.polynomial_index, salted)
            })
            .map(F::Extension::from_basefield);
        let reduced_evals = alpha.reduce(evals);
        let numerator = reduced_evals - *reduced_openings;
        let denominator = subgroup_x - *point;
        sum = alpha.shift(sum);
        sum += numerator / denominator;
    }

    // Multiply the final polynomial by `X`, so that `final_poly` has the maximum degree for
    // which the LDT will pass. See github.com/mir-protocol/plonky2/pull/436 for details.
    sum * subgroup_x
}

pub(crate) fn fri_verifier_query_round<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    instance: &FriInstanceInfo<F, D>,
    precomputed_reduced_evals: &PrecomputedReducedOpenings<F, D>,
    initial_merkle_caps: &[MerkleCap<F, C::Hasher>],
    commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
    final_poly: &PolynomialCoeffs<F::Extension>,
    round_proof: &FriQueryRound<F, C::Hasher, D>,
    fri_alpha: F::Extension,
    fri_betas: &[F::Extension],
    reduction_arity_bits: &[usize],
    mut x_index: usize,
    n: usize,
    hiding: bool,
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    fri_verify_initial_proof::<F, C::Hasher>(
        x_index,
        &round_proof.initial_trees_proof,
        initial_merkle_caps,
    )?;
    // `subgroup_x` is `subgroup[x_index]`, i.e., the actual field element in the domain.
    let log_n = log2_strict(n);
    let mut subgroup_x = F::MULTIPLICATIVE_GROUP_GENERATOR
        * F::primitive_root_of_unity(log_n).exp_u64(reverse_bits(x_index, log_n) as u64);

    // old_eval is the last derived evaluation; it will be checked for consistency with its
    // committed "parent" value in the next iteration.
    let mut old_eval = fri_combine_initial::<F, C, D>(
        instance,
        &round_proof.initial_trees_proof,
        fri_alpha,
        subgroup_x,
        precomputed_reduced_evals,
        hiding,
    );

    for (i, &arity_bits) in reduction_arity_bits.iter().enumerate() {
        let arity = 1 << arity_bits;
        let evals = &round_proof.steps[i].evals;

        // Split x_index into the index of the coset x is in, and the index of x within that coset.
        let coset_index = x_index >> arity_bits;
        let x_index_within_coset = x_index & (arity - 1);

        // Check consistency with our old evaluation from the previous round.
        ensure!(evals[x_index_within_coset] == old_eval);

        // Infer P(y) from {P(x)}_{x^arity=y}.
        old_eval = compute_evaluation(
            subgroup_x,
            x_index_within_coset,
            arity_bits,
            evals,
            fri_betas[i],
        );

        verify_merkle_proof_to_cap::<F, C::Hasher>(
            flatten(evals),
            coset_index,
            &commit_phase_merkle_caps[i],
            &round_proof.steps[i].merkle_proof,
        )?;

        // Update the point x to x^arity.
        subgroup_x = subgroup_x.exp_power_of_2(arity_bits);

        x_index = coset_index;
    }

    // Final check of FRI. After all the reductions, we check that the final polynomial is equal
    // to the one sent by the prover.
    ensure!(
        final_poly.eval(subgroup_x.into()) == old_eval,
        "Final polynomial evaluation is invalid."
    );

    Ok(())
}

/// For each opening point, holds the reduced (by `alpha`) evaluations of each polynomial that's
/// opened at that point.
#[derive(Clone, Debug)]
pub(crate) struct PrecomputedReducedOpenings<F: RichField + Extendable<D>, const D: usize> {
    pub reduced_openings_at_point: Vec<F::Extension>,
}

impl<F: RichField + Extendable<D>, const D: usize> PrecomputedReducedOpenings<F, D> {
    pub(crate) fn from_os_and_alpha(openings: &FriOpenings<F, D>, alpha: F::Extension) -> Self {
        let reduced_openings_at_point = openings
            .batches
            .iter()
            .map(|batch| ReducingFactor::new(alpha).reduce(batch.values.iter()))
            .collect();
        Self {
            reduced_openings_at_point,
        }
    }
}

pub fn get_fri_instance<F: RichField + Extendable<D>, const D: usize>(
    num_constants: usize,
    num_wires: usize,
    num_routed_wires: usize,
    num_challenges: usize,
    num_partial_products: usize,
    quotient_degree_factor: usize,
    degree_bits: usize,
    plonk_zeta: F::Extension,
) -> FriInstanceInfo<F, D> {
    let num_preprocessed_polys = num_constants + num_routed_wires;
    let fri_preprocessed_polys = FriPolynomialInfo::from_range(
        PlonkOracle::CONSTANTS_SIGMAS.index,
        0..num_preprocessed_polys,
    );

    let fri_wire_polys = FriPolynomialInfo::from_range(PlonkOracle::WIRES.index, 0..num_wires);

    let num_zs_partial_products_polys = num_challenges * (1 + num_partial_products);
    let fri_zs_partial_products_polys = FriPolynomialInfo::from_range(
        PlonkOracle::ZS_PARTIAL_PRODUCTS.index,
        0..num_zs_partial_products_polys,
    );

    let num_quotient_polys = num_challenges * quotient_degree_factor;
    let fri_quotient_polys =
        FriPolynomialInfo::from_range(PlonkOracle::QUOTIENT.index, 0..num_quotient_polys);

    let all_fri_polynomials = [
        fri_preprocessed_polys,
        fri_wire_polys,
        fri_zs_partial_products_polys,
        fri_quotient_polys,
    ]
    .concat();

    let zeta_batch = FriBatchInfo {
        point: plonk_zeta,
        polynomials: all_fri_polynomials,
    };

    let g = F::Extension::primitive_root_of_unity(degree_bits);
    let zeta_next = g * plonk_zeta;
    let fri_zs_polys =
        FriPolynomialInfo::from_range(PlonkOracle::ZS_PARTIAL_PRODUCTS.index, 0..num_challenges);
    let zeta_next_batch = FriBatchInfo {
        point: zeta_next,
        polynomials: fri_zs_polys,
    };

    let batches = vec![zeta_batch, zeta_next_batch];

    FriInstanceInfo {
        oracles: FRI_ORACLES.to_vec(),
        batches,
    }
}

pub fn get_final_poly_len(fri_reduction_arity_bits: &[usize], fri_degree_bits: usize) -> usize {
    1 << (fri_degree_bits - fri_reduction_arity_bits.iter().sum::<usize>())
}
