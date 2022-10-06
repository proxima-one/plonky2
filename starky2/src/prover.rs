use anyhow::{ensure, Result};
use itertools::Itertools;
use maybe_rayon::*;
use plonky2::field::extension::Extendable;
use plonky2::field::packable::Packable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::Field;
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_util::{log2_ceil, log2_strict};

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::cross_table_lookup::{CtlCheckVars, CtlColumn, CtlTableData, TableID};
use crate::permutation::compute_permutation_z_polys;
use crate::permutation::get_n_permutation_challenge_sets;
use crate::permutation::{PermutationChallengeSet, PermutationCheckVars};
use crate::proof::{StarkOpeningSet, StarkProof, StarkProofWithPublicInputs};
use crate::stark::Stark;
use crate::vanishing_poly::eval_vanishing_poly;
use crate::vars::StarkEvaluationVars;

/// Make a new challenger, compute all STARK trace commitments and observe them in the challenger
pub fn start_all_proof<F, C, const D: usize>(
    config: &StarkConfig,
    trace_poly_values: &[Vec<PolynomialValues<F>>],
    timing: &mut TimingTree,
) -> Result<(Vec<PolynomialBatch<F, C, D>>, Challenger<F, C::Hasher>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let trace_commitments = compute_trace_commitments(config, trace_poly_values, timing)?;
    let mut challenger = Challenger::<F, C::Hasher>::new();
    for cap in trace_commitments.iter().map(|c| &c.merkle_tree.cap) {
        challenger.observe_cap(cap);
    }

    Ok((trace_commitments, challenger))
}

// Compute all STARK trace commitments.
fn compute_trace_commitments<F, C, const D: usize>(
    config: &StarkConfig,
    trace_poly_values: &[Vec<PolynomialValues<F>>],
    timing: &mut TimingTree,
) -> Result<Vec<PolynomialBatch<F, C, D>>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    Ok(timed!(
        timing,
        "compute trace commitments",
        trace_poly_values
            .par_iter()
            .cloned()
            .map(|trace| {
                let mut timing = TimingTree::default();
                PolynomialBatch::<F, C, D>::from_values(
                    // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
                    // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
                    trace,
                    rate_bits,
                    false,
                    cap_height,
                    &mut timing,
                    None,
                )
            })
            .collect::<Vec<_>>()
    ))
}

/// Compute proof for a STARK with no CTLs
pub fn prove_no_ctl<F, C, S, const D: usize>(
    stark: &S,
    config: &StarkConfig,
    trace_poly_values: &[PolynomialValues<F>],
    public_inputs: [F; S::PUBLIC_INPUTS],
    timing: &mut TimingTree,
) -> Result<StarkProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    let trace_commitment = timed!(
        timing,
        "compute trace commitment",
        PolynomialBatch::<F, C, D>::from_values(
            // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
            // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
            trace_poly_values.to_vec(),
            rate_bits,
            false,
            cap_height,
            timing,
            None,
        )
    );

    let mut challenger = Challenger::<F, C::Hasher>::new();
    challenger.observe_cap(&trace_commitment.merkle_tree.cap);

    prove_single_table(
        stark,
        config,
        trace_poly_values,
        &trace_commitment,
        None,
        public_inputs,
        &mut challenger,
        timing,
    )
}

/// Compute proof for a single STARK table.
/// NOTE: this this function assumes the trace cap has been already observed by the challenger
pub fn prove_single_table<F, C, S, const D: usize>(
    stark: &S,
    config: &StarkConfig,
    trace_poly_values: &[PolynomialValues<F>],
    trace_commitment: &PolynomialBatch<F, C, D>,
    ctl_data: Option<&CtlTableData<F>>,
    public_inputs: [F; S::PUBLIC_INPUTS],
    challenger: &mut Challenger<F, C::Hasher>,
    timing: &mut TimingTree,
) -> Result<StarkProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    let degree = trace_poly_values[0].len();
    let degree_bits = log2_strict(degree);
    let fri_params = config.fri_params(degree_bits);
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;
    assert!(
        fri_params.total_arities() <= degree_bits + rate_bits - cap_height,
        "FRI total reduction arity is too large.",
    );

    // Permutation arguments.
    let permutation_zs_commitment_challenges = stark.uses_permutation_args().then(|| {
        let permutation_challenge_sets = get_n_permutation_challenge_sets(
            challenger,
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
            PolynomialBatch::from_values(
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

    let ctl_zs_commitment_challenges_cols = ctl_data.map(|ctl_data| {
        let commitment = timed!(
            timing,
            "compute CTL Z commitments",
            PolynomialBatch::<F, C, D>::from_values(
                ctl_data.table_zs.clone(),
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None
            )
        );
        let challenges = ctl_data.challenges.clone();
        (
            commitment,
            challenges,
            (
                ctl_data.cols.clone(),
                ctl_data.foreign_col_tids.clone(),
                ctl_data.foreign_col_indices.clone(),
            ),
        )
    });

    let ctl_zs_commitment = ctl_zs_commitment_challenges_cols
        .as_ref()
        .map(|(comm, _, _)| comm);
    let ctl_zs_cap = ctl_zs_commitment
        .as_ref()
        .map(|c| c.merkle_tree.cap.clone());
    if let Some(cap) = &ctl_zs_cap {
        challenger.observe_cap(cap);
    }

    let alphas = challenger.get_n_challenges(config.num_challenges);
    let quotient_polys = compute_quotient_polys::<F, <F as Packable>::Packing, C, S, D>(
        stark,
        trace_commitment,
        &permutation_zs_commitment_challenges,
        &ctl_zs_commitment_challenges_cols,
        public_inputs,
        alphas.clone(),
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
        trace_commitment,
        permutation_zs_commitment,
        ctl_zs_commitment,
        &quotient_commitment,
        degree_bits,
    );

    challenger.observe_openings(&openings.to_fri_openings());

    let initial_merkle_trees = std::iter::once(trace_commitment)
        .chain(permutation_zs_commitment)
        .chain(ctl_zs_commitment)
        .chain(std::iter::once(&quotient_commitment))
        .collect_vec();

    let opening_proof = timed!(
        timing,
        "compute openings proof",
        PolynomialBatch::prove_openings(
            &stark.fri_instance(
                zeta,
                g,
                degree_bits,
                ctl_data.map(|data| data.table_zs.len()).unwrap_or(0),
                config
            ),
            &initial_merkle_trees,
            challenger,
            &fri_params,
            timing,
        )
    );

    let proof = StarkProof {
        trace_cap: trace_commitment.merkle_tree.cap.clone(),
        permutation_zs_cap,
        ctl_zs_cap,
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
/// Computes the quotient polynomials `(sum alpha^i C_i(x)) / Z_H(x)` for `alpha` in `alphas`,
/// where the `C_i`s are the Stark constraints.
fn compute_quotient_polys<'a, F, P, C, S, const D: usize>(
    stark: &S,
    trace_commitment: &'a PolynomialBatch<F, C, D>,
    permutation_zs_commitment_challenges: &'a Option<(
        PolynomialBatch<F, C, D>,
        Vec<PermutationChallengeSet<F>>,
    )>,
    ctl_zs_commitment_challenges_cols: &'a Option<(
        PolynomialBatch<F, C, D>,
        Vec<F>,
        (Vec<CtlColumn>, Vec<TableID>, Vec<usize>),
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

    // First element of the subgroup.
    let first = F::primitive_root_of_unity(degree_bits);
    // Last element of the subgroup.
    let last = first.inverse();
    let size = degree << quotient_degree_bits;
    let coset = F::cyclic_subgroup_coset_known_order(
        F::primitive_root_of_unity(degree_bits + quotient_degree_bits),
        F::coset_shift(),
        size,
    );

    let ctl_zs_first_last = ctl_zs_commitment_challenges_cols.as_ref().map(|(c, _, _)| {
        let mut ctl_zs_first = Vec::with_capacity(c.polynomials.len());
        let mut ctl_zs_last = Vec::with_capacity(c.polynomials.len());
        c.polynomials
            .par_iter()
            .map(|p| {
                (
                    p.eval(F::ONE),
                    p.eval(F::primitive_root_of_unity(degree_bits).inverse()),
                )
            })
            .unzip_into_vecs(&mut ctl_zs_first, &mut ctl_zs_last);

        (ctl_zs_first, ctl_zs_last)
    });

    // We will step by `P::WIDTH`, and in each iteration, evaluate the quotient polynomial at
    // a batch of `P::WIDTH` points.
    let quotient_values = (0..size)
        .into_par_iter()
        .step_by(P::WIDTH)
        .flat_map_iter(|i_start| {
            let i_next_start = (i_start + next_step) % size;
            let i_range = i_start..i_start + P::WIDTH;

            let x = *P::from_slice(&coset[i_range.clone()]);
            let z_first = x - first;
            let z_last = x - last;
            let lagrange_basis_first = *P::from_slice(&lagrange_first.values[i_range.clone()]);
            let lagrange_basis_last = *P::from_slice(&lagrange_last.values[i_range]);

            let mut consumer = ConstraintConsumer::new(
                alphas.clone(),
                z_last,
                z_first,
                lagrange_basis_first,
                lagrange_basis_last,
            );
            let vars = StarkEvaluationVars {
                local_values: &get_trace_values_packed(i_start),
                next_values: &get_trace_values_packed(i_next_start),
                public_inputs: &public_inputs,
            };
            let permutation_check_vars = permutation_zs_commitment_challenges.as_ref().map(
                |(permutation_zs_commitment, permutation_challenge_sets)| PermutationCheckVars {
                    local_zs: permutation_zs_commitment.get_lde_values_packed(i_start, step),
                    next_zs: permutation_zs_commitment.get_lde_values_packed(i_next_start, step),
                    permutation_challenge_sets: permutation_challenge_sets.to_vec(),
                },
            );

            let ctl_vars =
                ctl_zs_commitment_challenges_cols
                    .as_ref()
                    .map(|(commitment, challenges, cols)| {
                        let local_zs = commitment.get_lde_values_packed(i_start, step);
                        let next_zs = commitment.get_lde_values_packed(i_next_start, step);
                        let challenges = challenges.clone();
                        let (cols, foreign_col_tids, foreign_col_indices) = cols.clone();
                        let (first_zs, last_zs) = ctl_zs_first_last.clone().unwrap();

                        CtlCheckVars {
                            local_zs,
                            next_zs,
                            first_zs,
                            last_zs,
                            challenges,
                            cols,
                            foreign_col_tids,
                            foreign_col_indices,
                        }
                    });

            eval_vanishing_poly::<F, F, P, C, S, D, 1>(
                stark,
                config,
                vars,
                permutation_check_vars,
                ctl_vars.as_ref(),
                &mut consumer,
            );

            let mut constraints_evals = consumer.accumulators();
            // We divide the constraints evaluations by `Z_H(x)`.
            let denominator_inv: P = z_h_on_coset.eval_inverse_packed(i_start);

            for eval in &mut constraints_evals {
                *eval *= denominator_inv;
            }

            let num_challenges = alphas.len();

            (0..P::WIDTH).into_iter().map(move |i| {
                (0..num_challenges)
                    .map(|j| constraints_evals[j].as_slice()[i])
                    .collect()
            })
        })
        .collect::<Vec<_>>();

    transpose(&quotient_values)
        .into_par_iter()
        .map(PolynomialValues::new)
        .map(|values| values.coset_ifft(F::coset_shift()))
        .collect()
}
