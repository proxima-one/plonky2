//! Cairo's public memory argument in Maru
use anyhow::ensure;
use itertools::Itertools;
use plonky2::field::batch_util::batch_multiply_inplace;
use plonky2::field::extension_field::{Extendable, FieldExtension};
use plonky2::field::field_types::Field;
use plonky2::field::packed_field::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::{Challenger, RecursiveChallenger};
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::util::reducing::{ReducingFactor, ReducingFactorTarget};
use rayon::prelude::*;

use crate::config::StarkConfig;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::proof::StarkProofWithPublicInputs;
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

#[derive(Copy, Clone)]
pub(crate) struct PublicMemoryChallenge<F: Field + Copy> {
    pub(crate) z: F,
    pub(crate) alpha: F,
}

fn get_public_memory_challenge<F: RichField, H: Hasher<F>>(
    challenger: &mut Challenger<F, H>,
) -> PublicMemoryChallenge<F> {
    let z = challenger.get_challenge();
    let alpha = challenger.get_challenge();
    PublicMemoryChallenge { z, alpha }
}

pub(crate) fn get_n_public_memory_challenges<F: RichField, H: Hasher<F>>(
    challenger: &mut Challenger<F, H>,
    num_challenges: usize,
) -> Vec<PublicMemoryChallenge<F>> {
    (0..num_challenges)
        .map(|_| get_public_memory_challenge(challenger))
        .collect()
}

pub(crate) struct MemoryAccessVars<'a, F: Field> {
    pub(crate) addr_columns: &'a [PolynomialValues<F>],
    pub(crate) addr_sorted_columns: &'a [PolynomialValues<F>],
    pub(crate) value_columns: &'a [PolynomialValues<F>],
    pub(crate) value_sorted_columns: &'a [PolynomialValues<F>],
}

impl<'a, F: Field> MemoryAccessVars<'a, F> {
    fn len(&self) -> usize {
        self.addr_columns[0].len()
    }

    fn width(&self) -> usize {
        self.addr_columns.len()
    }
}

/// Compute all Z polynomials (for public memory arguments).
pub(crate) fn compute_public_memory_z_polys<F, C, S, const D: usize>(
    stark: &S,
    config: &StarkConfig,
    memory_access_vars: &MemoryAccessVars<F>,
    public_memory_challenges: &Vec<PublicMemoryChallenge<F>>,
) -> Vec<PolynomialValues<F>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    public_memory_challenges
        .into_par_iter()
        .map(|challenge| compute_public_memory_z_poly_group(&challenge, memory_access_vars))
        .flatten_iter()
        .collect()
}

fn compute_public_memory_z_poly_group<F: Field>(
    challenge: &PublicMemoryChallenge<F>,
    memory_access_vars: &MemoryAccessVars<F>,
) -> Vec<PolynomialValues<F>> {
    let &PublicMemoryChallenge { z, alpha } = challenge;
    let mut res = vec![
        PolynomialValues::new(vec![F::ZERO; memory_access_vars.len()]);
        memory_access_vars.width()
    ];

    // public memory argument
    res[0].values[0] = prod_term(memory_access_vars, 0, 0, challenge);
    for j in 1..memory_access_vars.width() {
        res[j].values[0] = prod_term(memory_access_vars, 0, j, challenge) * res[j - 1].values[0];
    }
    for i in 1..memory_access_vars.len() {
        res[0].values[i] = prod_term(memory_access_vars, i, 0, challenge)
            * res[memory_access_vars.width() - 1].values[i - 1];
        for j in 1..memory_access_vars.width() {
            res[j].values[i] =
                prod_term(memory_access_vars, i, j, challenge) * res[j - 1].values[i - 1];
        }
    }

    res
}

fn prod_term<F: Field>(
    memory_access_vars: &MemoryAccessVars<F>,
    i: usize,
    j: usize,
    challenge: &PublicMemoryChallenge<F>,
) -> F {
    let &MemoryAccessVars::<F> {
        addr_columns,
        value_columns,
        addr_sorted_columns,
        value_sorted_columns,
    } = memory_access_vars;
    prod_term_inner(
        addr_columns[i].values[j],
        value_columns[i].values[j],
        addr_sorted_columns[i].values[j],
        value_sorted_columns[i].values[j],
        challenge,
    )
}

fn prod_term_inner<F: Field>(
    a: F,
    v: F,
    a_sorted: F,
    v_sorted: F,
    challenge: &PublicMemoryChallenge<F>,
) -> F {
    let &PublicMemoryChallenge { z, alpha } = challenge;
    let num = z - (a + alpha * v);
    let denom = z - (a_sorted + alpha * v_sorted);
    num * denom.inverse()
}

macro_rules! prod_term_constraint {
    (
        $a:expr,
        $v:expr,
        $a_sorted:expr,
        $v_sorted:expr,
        $prev_product:expr,
        $new_product:expr,
        $z:expr,
        $alpha:expr
    ) => {{
        let __num = -($a + $v * $alpha) + $z;
        let __denom = -($a_sorted + $v_sorted * $alpha) + $z;
        __denom * $new_product - __num * $prev_product
    }};
}

// variables for evaluating 1 row of Cairo's public memory constraints staggered over `W` accesses per row.
pub struct PublicMemoryVars<F, FE, P, const D2: usize>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    pub(crate) public_memory_pis: Vec<usize>,
    pub(crate) addr_cols_start: usize,
    pub(crate) mem_cols_start: usize,
    pub(crate) addr_sorted_cols_start: usize,
    pub(crate) mem_sorted_cols_start: usize,
    pub(crate) local_cumulative_products: Vec<Vec<P>>,
    pub(crate) next_cumulative_products: Vec<Vec<P>>,
    pub(crate) public_memory_challenges: Vec<PublicMemoryChallenge<F>>,
}

impl<F, FE, P, const D2: usize> PublicMemoryVars<F, FE, P, D2>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    pub(crate) fn width(&self) -> usize {
        self.local_cumulative_products.len()
    }
}

pub(crate) fn eval_public_memory<F, FE, P, C, S, const D: usize, const D2: usize>(
    stark: &S,
    config: &StarkConfig,
    vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
    public_memory_vars: &PublicMemoryVars<F, FE, P, D2>,
    challenges: &Vec<PublicMemoryChallenge<F>>,
    constrainer: &mut ConstraintConsumer<P>,
) where
    F: RichField + Extendable<D>,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    let PublicMemoryVars {
        public_memory_pis,
        addr_cols_start,
        mem_cols_start,
        addr_sorted_cols_start,
        mem_sorted_cols_start,
        local_cumulative_products,
        next_cumulative_products,
        public_memory_challenges,
    } = public_memory_vars;

    let StarkEvaluationVars {
        public_inputs,
        local_values,
        next_values,
    } = vars;

    let curr_row = local_values;
    let next_row = next_values;

    // make sure sorted addresses are sequential
    for i in 1..public_memory_vars.width() {
        constrainer.constraint(
            (curr_row[addr_sorted_cols_start + i] - curr_row[addr_sorted_cols_start + i - 1])
                * (curr_row[addr_sorted_cols_start + i]
                    - curr_row[addr_sorted_cols_start + i - 1]
                    - FE::ONE),
        );
    }
    constrainer.constraint_transition(
        (next_row[*addr_sorted_cols_start]
            - curr_row[addr_sorted_cols_start + public_memory_vars.width() - 1])
            * (next_row[*addr_sorted_cols_start]
                - curr_row[addr_sorted_cols_start + public_memory_vars.width() - 1]
                - FE::ONE),
    );

    // make sure sorted accesses are single-valued
    for i in 1..public_memory_vars.width() {
        constrainer.constraint(
            (curr_row[mem_sorted_cols_start + i] - curr_row[mem_sorted_cols_start + i - 1])
                * (curr_row[addr_sorted_cols_start + i]
                    - curr_row[addr_sorted_cols_start + i - 1]
                    - FE::ONE),
        );
    }
    constrainer.constraint_transition(
        (next_row[*mem_sorted_cols_start]
            - curr_row[mem_sorted_cols_start + public_memory_vars.width() - 1])
            * (curr_row[*addr_sorted_cols_start]
                - curr_row[addr_sorted_cols_start + public_memory_vars.width() - 1]
                - FE::ONE),
    );

    // once for each challenge
    for (i, challenge) in public_memory_challenges.iter().enumerate() {
        
        let z = FE::from_basefield(challenge.z);
        let alpha = FE::from_basefield(challenge.alpha);
        let a = curr_row[*addr_cols_start];
        let v = curr_row[*mem_cols_start];
        let a_sorted = curr_row[*addr_sorted_cols_start];
        let v_sorted = curr_row[*mem_sorted_cols_start];
        let num = -(a + v * alpha) + z;
        let denom = -(a_sorted + v_sorted * alpha) + z;

        // permutation / public memory argument
        constrainer.constraint_first_row(local_cumulative_products[i][0] * denom - num);
        for j in 1..public_memory_vars.width() {
            constrainer.constraint(prod_term_constraint!(
                curr_row[addr_cols_start + j],
                curr_row[mem_cols_start + j],
                curr_row[addr_sorted_cols_start + j],
                curr_row[mem_sorted_cols_start + j],
                local_cumulative_products[i][j - 1],
                local_cumulative_products[i][j],
                FE::from_basefield(challenge.z),
                FE::from_basefield(challenge.alpha)
            ));
        }
        constrainer.constraint_transition(prod_term_constraint!(
            next_row[*addr_cols_start],
            next_row[*mem_cols_start],
            next_row[*addr_sorted_cols_start],
            next_row[*mem_sorted_cols_start],
            local_cumulative_products[i][public_memory_vars.width() - 1],
            next_cumulative_products[i][0],
            z,
            alpha
        ));
    }

    // check final comulative product against one given as public input for each challenge
    for i in 0..public_memory_vars.width() {
        let pi = vars.public_inputs[public_memory_pis[i]];
        constrainer.constraint_last_row(
            local_cumulative_products[i][public_memory_vars.width() - 1] * pi - FE::ONE,
        );
    }

    // range checks - since we've verified that...
    // 1) the sorted addresses are a permutation of the non-sorted addresses
    // 2) the sorted addresses are sequential
    // we only need to check the first and last addresses correspond to the min and max address respectively.
    let rc_min_idx = public_memory_pis[public_memory_pis.len() - 3];
    let rc_max_idx = public_memory_pis[public_memory_pis.len() - 2];
    let rc_min = vars.public_inputs[rc_min_idx];
    let rc_max = vars.public_inputs[rc_max_idx];
    constrainer.constraint_first_row(curr_row[*addr_sorted_cols_start] - rc_min);
    constrainer.constraint_last_row(curr_row[addr_sorted_cols_start + public_memory_vars.width() - 1] - rc_max);
}

pub(crate) fn check_public_memory_pis<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize, S: Stark<F, D>>(
    stark: &S,
    config: &StarkConfig,
    proof_with_pis: &StarkProofWithPublicInputs<F, C, D>,
    public_memory_accesses: &[(F, F)],
    public_memory_challenges: &[PublicMemoryChallenge<F>],
) -> anyhow::Result<()> {
    let trace_length = 1u64 << proof_with_pis.proof.recover_degree_bits(config);
    let pis = stark.public_memory_pis().unwrap();
    let num_non_padding_insns = proof_with_pis.public_inputs[pis[pis.len() - 1]];
    let num_dummy_insns = F::from_canonical_u64(trace_length) - num_non_padding_insns;

    for (i, &PublicMemoryChallenge { z, alpha }) in public_memory_challenges.iter().enumerate() {
        let denom = z.exp_u64(public_memory_accesses.len() as u64 + num_dummy_insns.to_canonical_u64());
        let num = public_memory_accesses.iter().fold(F::ONE, |p, &(a, v)| p * (z - (a + alpha * v)));
        ensure!(
            num * denom.inverse() == proof_with_pis.public_inputs[pis[i]],
            "public memory PIs given in proof doesn't match public memory trace"
        );
    }
    Ok(())
}
