use itertools::{Itertools, Chunks, TupleWindows};
use std::iter;
use plonky2_field::batch_util::batch_add_inplace;
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::Field;
use plonky2_field::zero_poly_coset::ZeroPolyOnCoset;

use crate::gates::gate::GateBox;
use crate::gates::selectors::SelectorsInfo;
use crate::hash::hash_types::RichField;
use crate::iop::ext_target::ExtensionTarget;
use crate::iop::target::Target;
use crate::plonk::circuit_builder::CircuitBuilder;
use crate::plonk::circuit_data::CommonCircuitData;
use crate::plonk::config::GenericConfig;
use crate::plonk::plonk_common;
use crate::plonk::plonk_common::eval_l_1_circuit;
use crate::plonk::vars::{EvaluationTargets, EvaluationVars, EvaluationVarsBaseBatch};
use crate::util::partial_products::check_partial_products_iter;
use crate::util::reducing::ReducingFactorTarget;
use crate::util::strided_view::PackedStridedView;


/// Evaluate the vanishing polynomial at `x`. In this context, the vanishing polynomial is a random
/// linear combination of gate constraints, plus some other terms relating to the permutation
/// argument. All such terms should vanish on `H`.
pub(crate) fn eval_vanishing_poly<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    x: F::Extension,
    vars: EvaluationVars<F, D>,
    local_zs: &[F::Extension],
    next_zs: &[F::Extension],
    partial_products: &[F::Extension],
    s_sigmas: &[F::Extension],
    betas: &[F],
    gammas: &[F],
    alphas: &[F],
    gates: &[GateBox<F, D>],
    selectors_info: &SelectorsInfo,
    k_is: &[F],
    degree_bits: usize,
    quotient_degree_factor: usize,
    num_partial_products: usize,
    num_gate_constraints: usize,
    num_challenges: usize,
    num_routed_wires: usize,
) -> Vec<F::Extension> {
    let max_degree = quotient_degree_factor;
    let num_prods = num_partial_products;

    let constraint_terms =
        evaluate_gate_constraints::<F, C, D>(vars, num_gate_constraints, gates, selectors_info);

    #[cfg(target_os = "solana")]
    solana_program::msg!("3");

    // The L_1(x) (Z(x) - 1) vanishing terms.
    let mut vanishing_z_1_terms = Vec::new();
    // The terms checking the partial products.
    let mut vanishing_partial_products_terms = Vec::new();

    let degree = 1 << degree_bits;
    let l1_x = plonk_common::eval_l_1(degree, x);

    for i in 0..num_challenges {
        let z_x = local_zs[i];
        let z_gx = next_zs[i];
        vanishing_z_1_terms.push(l1_x * (z_x - F::Extension::ONE));

        let numerator_values = (0..num_routed_wires)
            .map(|j| {
                let wire_value = vars.local_wires[j];
                let k_i = k_is[j];
                let s_id = x.scalar_mul(k_i);
                wire_value + s_id.scalar_mul(betas[i]) + gammas[i].into()
            });
        let denominator_values = (0..num_routed_wires)
            .map(|j| {
                let wire_value = vars.local_wires[j];
                let s_sigma = s_sigmas[j];
                wire_value + s_sigma.scalar_mul(betas[i]) + gammas[i].into()
            });

        // The partial products considered for this iteration of `i`.
        let current_partial_products = &partial_products[i * num_prods..(i + 1) * num_prods];
        // Check the quotient partial products.

        let product_accs = iter::once(&z_x)
            .chain(current_partial_products.iter())
            .chain(iter::once(&z_gx));
       
        let chunk_size = max_degree;
        let numerators_chunks = numerator_values.chunks(chunk_size);
        let denominators_chunks = denominator_values.chunks(chunk_size);

        let partial_product_checks = check_partial_products_iter(
            numerators_chunks.into_iter(),
            denominators_chunks.into_iter(),
            product_accs.tuple_windows(),
        );

        vanishing_partial_products_terms.extend(partial_product_checks);
    }

    #[cfg(target_os = "solana")]
    solana_program::msg!("4");

    let vanishing_terms = [
        vanishing_z_1_terms,
        vanishing_partial_products_terms,
        constraint_terms,
    ]
    .concat();

    let alphas = &alphas.iter().map(|&a| a.into()).collect::<Vec<_>>();
    plonk_common::reduce_with_powers_multi(&vanishing_terms, alphas)
}

/// Evaluates all gate constraints.
///
/// `num_gate_constraints` is the largest number of constraints imposed by any gate. It is not
/// strictly necessary, but it helps performance by ensuring that we allocate a vector with exactly
/// the capacity that we need.
pub fn evaluate_gate_constraints<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    vars: EvaluationVars<F, D>,
    num_gate_constraints: usize,
    gates: &[GateBox<F, D>],
    selectors_info: &SelectorsInfo,
) -> Vec<F::Extension> {
    let mut constraints = vec![F::Extension::ZERO; num_gate_constraints];

    #[cfg(target_os = "solana")]
    solana_program::msg!("num_gates: {}, num_gate_constraints: {}", gates.len(), num_gate_constraints);

    for (i, gate) in gates.iter().enumerate() {
        #[cfg(target_os = "solana")]
        solana_program::msg!("evaluating gate: {}", gate.0.id());

        let selector_index = selectors_info.selector_indices[i];
        let gate_constraints = gate.0.eval_filtered(
            vars,
            i,
            selector_index,
            selectors_info.groups[selector_index].clone(),
            selectors_info.num_selectors(),
        );
        for (i, c) in gate_constraints.into_iter().enumerate() {
            debug_assert!(
                i < num_gate_constraints,
                "num_constraints() gave too low of a number"
            );
            constraints[i] += c;
        }
        #[cfg(target_os = "solana")]
        solana_program::msg!("done!");
    }
    constraints
}
