use std::iter;

use anyhow::{anyhow, ensure, Result};
use itertools::Itertools;
use maybe_rayon::*;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::proof::{StarkProof, StarkProofWithPublicInputs};
use crate::stark::Stark;
use crate::vars::StarkEvaluationVars;

/// represets a set of cross-table lookups to be performed between an arbitrary number of starks on arbitrary sets of colums
#[derive(Debug, Clone)]
pub struct CtlDescriptor {
    /// instances of CTLs, where a colset in one table "looks up" a column in another table
    /// represented as pairs of columns where the LHS is a set of columns in some table "looking" up the RHS, another set of columns in some table
    pub instances: Vec<(CtlColSet, CtlColSet)>,
    /// the number of tables involved
    pub num_tables: usize,
}

impl CtlDescriptor {
    pub fn from_instances(instances: Vec<(CtlColSet, CtlColSet)>, num_tables: usize) -> Self {
        Self {
            instances,
            num_tables,
        }
    }
}

/// Describes a set of columns that is involved in a cross-table lookup
/// These columns are "linked" together via a linear-combination. This
/// means the lookup effectively amounts to looking up a "tuple"
/// of columns up to the *same* permutations. In other words,
/// if a set of colums (a, b, c) in trace 0 is "looking up"
/// a set of columns in (x, y, z) in trace 1, then the lookup will
/// enforce that, for every row i in trace 0, there exists a row j in trace 1
/// such that (a[i], b[i], c[i]) = (x[j], y[j], z[j]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CtlColSet {
    /// table ID for the table that this column set belongs to
    pub(crate) tid: TableID,
    /// set of column indices for this side of the CTL
    pub(crate) colset: Vec<usize>,
    /// column index for the corresponding filter, if any
    pub(crate) filter_col: Option<usize>,
}

impl CtlColSet {
    pub fn new(tid: TableID, colset: Vec<usize>, filter_col: Option<usize>) -> CtlColSet {
        CtlColSet {
            tid,
            colset,
            filter_col,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TableID(pub usize);

impl From<usize> for TableID {
    fn from(id: usize) -> Self {
        TableID(id)
    }
}

impl Into<usize> for TableID {
    fn into(self) -> usize {
        self.0
    }
}

// challenges used to reduce a set of columns to a single polynomial
// against which the CTL is performed
#[derive(Debug, Copy, Clone)]
pub struct CtlLinearCombChallenge<F: Field> {
    pub(crate) alpha: F,
    pub(crate) gamma: F,
}

pub(crate) fn get_ctl_linear_comb_challenge<F: RichField, H: Hasher<F>>(
    challenger: &mut Challenger<F, H>,
) -> CtlLinearCombChallenge<F> {
    CtlLinearCombChallenge {
        alpha: challenger.get_challenge(),
        gamma: challenger.get_challenge(),
    }
}

// challenges used to compute the lookup's Z polys against the reduced colset poly
#[derive(Debug, Copy, Clone)]
pub struct CtlChallenge<F: Field> {
    pub(crate) gamma: F,
}

pub(crate) fn get_ctl_challenge<F: RichField, H: Hasher<F>>(
    challenger: &mut Challenger<F, H>,
) -> CtlChallenge<F> {
    CtlChallenge {
        gamma: challenger.get_challenge(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CtlColsetData<F: Field> {
    // the set of columns
    pub(crate) colset: CtlColSet,
    // the Z poly for the CTL
    // there are `num_challenges` of them
    pub(crate) z_polys: Vec<PolynomialValues<F>>,
    // the challenges used to reduce the colset into a single polynomial
    // there are `num_challenges` of them
    pub(crate) linear_comb_challenges: Vec<CtlLinearCombChallenge<F>>,
    // the challenges used to compute the Z polys against the reduced polys
    // there are `num_challenges` of them
    pub(crate) ctl_challenges: Vec<CtlChallenge<F>>,
}

#[derive(Debug, Clone)]
pub struct CtlData<F: Field> {
    pub by_table: Vec<CtlTableData<F>>,
}

#[derive(Debug, Clone)]
pub struct CtlTableData<F: Field> {
    pub(crate) looking: Vec<CtlColsetData<F>>,
    pub(crate) looked: Vec<CtlColsetData<F>>,
}

impl<F: Field> CtlTableData<F> {
    pub(crate) fn zs(&self) -> Vec<PolynomialValues<F>> {
        let mut zs = Vec::new();
        for colset in self.looking.iter().chain(self.looked.iter()) {
            zs.extend(colset.z_polys.iter().cloned());
        }

        zs
    }

    pub(crate) fn num_zs(&self) -> usize {
        self.looking
            .iter()
            .chain(self.looked.iter())
            .map(|colset| colset.z_polys.len())
            .sum()
    }

    pub(crate) fn challenges(&self) -> (Vec<CtlLinearCombChallenge<F>>, Vec<CtlChallenge<F>>) {
        let mut linear_comb_challenges = Vec::new();
        let mut ctl_challenges = Vec::new();
        for colset in self.looking.iter().chain(self.looked.iter()) {
            linear_comb_challenges.extend(colset.linear_comb_challenges.iter().cloned());
            ctl_challenges.extend(colset.ctl_challenges.iter().cloned());
        }

        (linear_comb_challenges, ctl_challenges)
    }

    pub(crate) fn cols(&self) -> Vec<CtlColSet> {
        let mut cols = Vec::new();
        for colset in self.looking.iter().chain(self.looked.iter()) {
            cols.push(colset.colset.clone());
        }

        cols
    }
}

// compute the preprocessed polynomials necessary for the lookup argument given CTL traces and table descriptors
pub fn get_ctl_data<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &StarkConfig,
    trace_poly_valueses: &[Vec<PolynomialValues<F>>],
    ctl_descriptor: &CtlDescriptor,
    challenger: &mut Challenger<F, C::Hasher>,
) -> CtlData<F> {
    let num_challenges = config.num_challenges;

    let mut by_table = vec![
        CtlTableData {
            looking: Vec::new(),
            looked: Vec::new()
        };
        ctl_descriptor.num_tables
    ];

    for (looking_colset, looked_colset) in ctl_descriptor.instances.iter() {
        let CtlColSet {
            tid: looking_tid,
            colset: looking_cols,
            filter_col: looking_filter_col,
        } = looking_colset.clone();

        let CtlColSet {
            tid: looked_tid,
            colset: looked_cols,
            filter_col: looked_filter_col,
        } = looked_colset.clone();

        let linear_comb_challenges = (0..num_challenges)
            .map(|_| get_ctl_linear_comb_challenge(challenger))
            .collect_vec();

        let ctl_challenges = (0..num_challenges)
            .map(|_| get_ctl_challenge(challenger))
            .collect_vec();

        let looking_filter_poly =
            looking_filter_col.map(|col| &trace_poly_valueses[looking_tid.0][col]);
        let looking_colset_polys = looking_cols
            .iter()
            .map(|&col| &trace_poly_valueses[looking_tid.0][col])
            .collect_vec();
        let looking_z_polys = linear_comb_challenges
            .iter()
            .zip(ctl_challenges.iter())
            .map(|(linear_comb_challenge, challenge)| {
                compute_z_poly(
                    &looking_colset_polys,
                    looking_filter_poly,
                    linear_comb_challenge,
                    challenge,
                )
            })
            .collect_vec();

        let looked_filter_poly =
            looked_filter_col.map(|col| &trace_poly_valueses[looked_tid.0][col]);
        let looked_colset_polys = looked_cols
            .iter()
            .map(|&col| &trace_poly_valueses[looked_tid.0][col])
            .collect_vec();
        let looked_z_polys = linear_comb_challenges
            .iter()
            .zip(ctl_challenges.iter())
            .map(|(linear_comb_challenge, challenge)| {
                compute_z_poly(
                    &looked_colset_polys,
                    looked_filter_poly,
                    linear_comb_challenge,
                    challenge,
                )
            })
            .collect_vec();

        let looking_data = CtlColsetData {
            colset: looking_colset.clone(),
            z_polys: looking_z_polys,
            linear_comb_challenges: linear_comb_challenges.clone(),
            ctl_challenges: ctl_challenges.clone(),
        };

        let looked_data = CtlColsetData {
            colset: looked_colset.clone(),
            z_polys: looked_z_polys,
            linear_comb_challenges,
            ctl_challenges,
        };

        by_table[looking_tid.0].looking.push(looking_data);
        by_table[looked_tid.0].looked.push(looked_data);
    }

    CtlData { by_table }
}

fn compute_z_poly<F: Field>(
    colset_polys: &[&PolynomialValues<F>],
    selector_poly: Option<&PolynomialValues<F>>,
    linear_comb_challenge: &CtlLinearCombChallenge<F>,
    challenge: &CtlChallenge<F>,
) -> PolynomialValues<F> {
    let &CtlLinearCombChallenge { gamma, alpha } = linear_comb_challenge;
    let eval_reduced = |row: usize| {
        let mut eval = F::ZERO;
        for &poly in colset_polys {
            eval = eval * alpha + poly.values[row];
        }
        eval + gamma
    };

    let &CtlChallenge { gamma } = challenge;
    if let Some(selector_poly) = selector_poly {
        let mut evals = Vec::new();
        let mut eval = F::ONE;
        for i in (0..selector_poly.len()).filter(|&i| selector_poly.values[i] != F::ZERO) {
            debug_assert!(selector_poly.values[i] == F::ONE, "non-binary filter");

            evals.resize(i, eval);

            eval *= eval_reduced(i) + gamma;
            evals.push(eval);
        }
        evals.resize(selector_poly.len(), eval);
        PolynomialValues::new(evals)
    } else {
        let evals = (0..colset_polys[0].len())
            .map(eval_reduced)
            .scan(F::ONE, |eval, reduced_eval| {
                *eval *= reduced_eval + gamma;
                Some(*eval)
            })
            .collect_vec();
        PolynomialValues::new(evals)
    }
}

#[derive(Debug, Clone)]
pub struct CtlCheckVars<F, FE, P, const D2: usize>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    pub(crate) local_zs: Vec<P>,
    pub(crate) next_zs: Vec<P>,
    pub(crate) first_zs: Vec<F>,
    pub(crate) last_zs: Vec<F>,
    pub(crate) linear_comb_challenges: Vec<CtlLinearCombChallenge<F>>,
    pub(crate) challenges: Vec<CtlChallenge<F>>,
    pub(crate) cols: Vec<CtlColSet>,
}

impl<F, const D: usize> CtlCheckVars<F, F::Extension, F::Extension, D>
where
    F: RichField + Extendable<D>,
{
    pub fn from_proofs<C: GenericConfig<D, F = F>>(
        proofs: &[StarkProofWithPublicInputs<F, C, D>],
        ctl_descriptor: &CtlDescriptor,
        linear_comb_challenges_by_table: &[Vec<CtlLinearCombChallenge<F>>],
        ctl_challenges_by_table: &[Vec<CtlChallenge<F>>],
    ) -> Vec<Self> {
        let num_tables = ctl_descriptor.num_tables;
        debug_assert_eq!(num_tables, proofs.len());

        let first_last_zs = proofs.iter().map(|p| {
            (
                p.proof
                    .openings
                    .ctl_zs_first
                    .as_ref()
                    .expect("no ctl first opening!")
                    .clone(),
                p.proof
                    .openings
                    .ctl_zs_last
                    .as_ref()
                    .expect("no ctl last opening!")
                    .clone(),
            )
        });
        let ctl_zs = proofs
            .iter()
            .map(|p| {
                let openings = &p.proof.openings;
                let ctl_zs = openings.ctl_zs.as_ref().expect("no ctl openings!").iter();
                let ctl_zs_next = openings
                    .ctl_zs_next
                    .as_ref()
                    .expect("no ctl openings!")
                    .iter();
                ctl_zs.zip(ctl_zs_next)
            })
            .collect_vec();

        // (looking, looked) by table
        let mut instances_by_table = vec![(Vec::new(), Vec::new()); num_tables];
        for (looking, looked) in ctl_descriptor.instances.iter() {
            instances_by_table[looking.tid.0].0.push(looking);
            instances_by_table[looked.tid.0].1.push(looked);
        }

        let instances_by_table = instances_by_table
            .into_iter()
            .map(|(looking, looked)| looking.into_iter().chain(looked.into_iter()));

        instances_by_table
            .zip(first_last_zs.zip(ctl_zs))
            .zip(linear_comb_challenges_by_table.into_iter().zip(ctl_challenges_by_table.into_iter()))
            .map(
                |((instances, ((first_zs, last_zs), ctl_zs)), (linear_comb_challenges, ctl_challenges))| {
                    let cols = instances.cloned().collect_vec();
                    let (local_zs, next_zs) = ctl_zs.unzip();

                    let challenges = ctl_challenges.clone();
                    let linear_comb_challenges = linear_comb_challenges.clone();

                    CtlCheckVars {
                        local_zs,
                        next_zs,
                        first_zs,
                        last_zs,
                        linear_comb_challenges,
                        challenges,
                        cols,
                    }
                },
            )
            .collect_vec()
    }
}

pub(crate) fn eval_cross_table_lookup_checks<F, FE, P, C, S, const D: usize, const D2: usize>(
    vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
    ctl_vars: &CtlCheckVars<F, FE, P, D2>,
    consumer: &mut ConstraintConsumer<P>,
    num_challenges: usize,
) where
    F: RichField + Extendable<D>,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    debug_assert_eq!(ctl_vars.challenges.len(), num_challenges * ctl_vars.cols.len());

    let eval_reduced = |evals: &[P], alpha: F, gamma: F| {
        let mut sum = P::ZEROS;
        for &eval in evals {
            sum = sum * FE::from_basefield(alpha) + eval
        }
        sum + FE::from_basefield(gamma)
    };

    for instance in 0..ctl_vars.cols.len() {
        let colset = &ctl_vars.cols[instance];
        let filter_col = colset.filter_col;
        let local_ctl_col_values = colset
            .colset
            .iter()
            .map(|&col| vars.local_values[col])
            .collect_vec();
        let next_ctl_col_values = colset
            .colset
            .iter()
            .map(|&col| vars.next_values[col])
            .collect_vec();

        let sel = filter_col.map_or(P::ONES, |col| vars.local_values[col]);
        // check filter is binary
        consumer.constraint(sel * (P::ONES - sel));

        let next_sel = filter_col.map_or(P::ONES, |col| vars.next_values[col]);

        for i in 0..num_challenges {
            let linear_comb_challenge =
                &ctl_vars.linear_comb_challenges[instance * num_challenges + i];
            let challenge = &ctl_vars.challenges[instance * num_challenges + i];
            let local_z = ctl_vars.local_zs[instance * num_challenges + i];
            let next_z = ctl_vars.next_zs[instance * num_challenges + i];
            let first_z = ctl_vars.first_zs[instance * num_challenges + i];
            let last_z = ctl_vars.last_zs[instance * num_challenges + i];

            // check first and last zs
            consumer.constraint_first_row(local_z - FE::from_basefield(first_z));
            consumer.constraint_last_row(local_z - FE::from_basefield(last_z));

            // check grand product
            let reduced_eval = eval_reduced(
                &next_ctl_col_values,
                linear_comb_challenge.alpha,
                linear_comb_challenge.gamma,
            );
            let eval = reduced_eval + FE::from_basefield(challenge.gamma) - P::ONES;
            consumer.constraint_transition(next_z - (local_z * (next_sel * eval + P::ONES)));
            consumer.constraint_last_row(next_z - FE::from_basefield(first_z));

            // check grand product start
            let reduced_eval = eval_reduced(
                &local_ctl_col_values,
                linear_comb_challenge.alpha,
                linear_comb_challenge.gamma,
            );
            let eval = reduced_eval + FE::from_basefield(challenge.gamma) - P::ONES;
            consumer.constraint_first_row((sel * eval + P::ONES) - FE::from_basefield(first_z));
            
        }
    }
}

pub fn verify_cross_table_lookups<
    'a,
    I: Iterator<Item = &'a StarkProof<F, C, D>>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'a,
    const D: usize,
>(
    proofs: I,
    descriptor: &CtlDescriptor,
    num_challenges: usize
) -> Result<()> {
    let ctl_zs_openings = proofs
        .flat_map(|p| p.openings.ctl_zs_last.iter())
        .collect_vec();

    let mut looking_zs = Vec::new();
    let mut looked_zs = Vec::new();
    let mut indices = vec![0; descriptor.num_tables];
    for (looking, _) in descriptor.instances.iter() {
        let tid = looking.tid;
        let idx = indices[tid.0];
        let zs = &ctl_zs_openings[tid.0][idx..idx + num_challenges];
        indices[tid.0] += num_challenges;
        looking_zs.extend(zs.iter().map(move |z| (z, tid)));
    }

    for (_, looked) in descriptor.instances.iter() {
        let tid = looked.tid;
        let idx = indices[tid.0];
        let zs = &ctl_zs_openings[tid.0][idx..idx + num_challenges];
        indices[tid.0] += num_challenges;
        looked_zs.extend(zs.iter().map(move |z| (z, tid)));
    }

    for ((looking_z, looking_tid), (looked_z, looked_tid)) in looking_zs.into_iter().zip(looked_zs.into_iter()) {
        if looking_z != looked_z {
            let msg = format!(
                "cross table lookup verification failed. looking TableID: {}, looked TableID: {}, looking_z: {:?}, looked_z: {:?}",
                looking_tid.0, looked_tid.0, looking_z, looked_z
            );
            return Err(anyhow!(msg));
        }
    }

    Ok(())
}
