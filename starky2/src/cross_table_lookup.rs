use anyhow::{ensure, Result};
use itertools::Itertools;
use maybe_rayon::*;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::proof::{StarkProof, StarkProofWithPublicInputs};
use crate::stark::Stark;
use crate::vars::StarkEvaluationVars;

// represents the imports and exports for a stark table relying on a cross-table lookup
#[derive(Debug, Clone)]
pub struct CtlDescriptor {
    /// instances of CTLs, where a column in one table "looks up" a column in another table
    /// represented as pairs of columns where the LHS is a column in this table and the RHS is a column in another tabe
    pub(crate) instances: Vec<(CtlColumn, CtlColumn)>,
}

impl CtlDescriptor {
    pub fn from_instances(instances: Vec<(CtlColumn, CtlColumn)>) -> Self {
        Self { instances }
    }
}

/// Describes a column that is involved in a cross-table lookup
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CtlColumn {
    /// table ID for the table that this column belongs to
    pub tid: TableID,
    /// column index for the column
    pub col: usize,
    /// column index for the corresponding filter, if any
    filter_col: Option<usize>,
}

impl CtlColumn {
    pub fn new(tid: TableID, col: usize, filter_col: Option<usize>) -> CtlColumn {
        CtlColumn {
            tid,
            col,
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

#[derive(Debug, Clone)]
pub struct CtlData<F: Field> {
    pub by_table: Vec<CtlTableData<F>>,
}

#[derive(Debug, Clone)]
pub struct CtlTableData<F: Field> {
    pub(crate) cols: Vec<CtlColumn>,
    pub(crate) foreign_col_tids: Vec<TableID>,
    pub(crate) foreign_col_indices: Vec<usize>,
    pub(crate) table_zs: Vec<PolynomialValues<F>>,
    // challenges used for the CTLs in this table
    pub(crate) challenges: Vec<F>,
}

// compute the preprocessed polynomials necessary for the lookup argument given CTL traces and table descriptors
pub fn get_ctl_data<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &StarkConfig,
    trace_poly_valueses: &[Vec<PolynomialValues<F>>],
    ctl_descriptor: &CtlDescriptor,
    challenger: &mut Challenger<F, C::Hasher>,
) -> CtlData<F> {
    let num_tables = trace_poly_valueses.len();
    let instances = ctl_descriptor
        .instances
        .iter()
        .map(|_| challenger.get_n_challenges(config.num_challenges))
        .zip(ctl_descriptor.instances.iter().cloned())
        .collect_vec();

    let compute_z_poly = |gamma: F,
                          table_idx: usize,
                          col: usize,
                          filter_col: Option<usize>|
     -> PolynomialValues<F> {
        match filter_col {
            None => {
                let col_values = &trace_poly_valueses[table_idx][col].values;
                let values = col_values
                    .iter()
                    .scan(F::ONE, |prev, &eval| {
                        let next = *prev * (eval + gamma);
                        *prev = next;
                        Some(next)
                    })
                    .collect();

                PolynomialValues::new(values)
            }
            Some(filter_col) => {
                let col_values = &trace_poly_valueses[table_idx][col].values;
                let filter_col_values = &trace_poly_valueses[table_idx][filter_col].values;
                let values = col_values
                    .iter()
                    .zip(filter_col_values.iter())
                    .scan(F::ONE, |prev, (&eval, &filter_eval)| {
                        if filter_eval == F::ONE {
                            let next = *prev * (eval + gamma);
                            *prev = next;
                            Some(next)
                        } else if filter_eval == F::ZERO {
                            Some(*prev)
                        } else {
                            panic!("non-binary filter!")
                        }
                    })
                    .collect();

                PolynomialValues::new(values)
            }
        }
    };

    let instances = instances
        .into_par_iter()
        .flat_map_iter(|(challenges, (looking_col, looked_col))| {
            let looking = challenges.clone().into_iter().map(move |gamma| {
                let z = compute_z_poly(
                    gamma,
                    looking_col.tid.0,
                    looking_col.col,
                    looking_col.filter_col,
                );
                (looking_col.tid, looking_col, z)
            });

            let looked = challenges.clone().into_iter().map(move |gamma| {
                let z = compute_z_poly(
                    gamma,
                    looked_col.tid.0,
                    looked_col.col,
                    looked_col.filter_col,
                );
                (looked_col.tid, looked_col, z)
            });

            looking.zip(looked).zip(challenges.into_iter())
        })
        .collect::<Vec<_>>();

    let mut by_table = vec![
        CtlTableData {
            cols: Vec::new(),
            table_zs: Vec::new(),
            challenges: Vec::new(),
            foreign_col_tids: Vec::new(),
            foreign_col_indices: Vec::new(),
        };
        num_tables
    ];
    for (((looking_tid, looking_col, looking_z), (looked_tid, looked_col, looked_z)), gamma) in
        instances
    {
        let looking_idx = by_table[looking_tid.0].cols.len();
        let looked_idx = by_table[looked_tid.0].cols.len();

        let table = &mut by_table[looking_tid.0];
        table.cols.push(looking_col);
        table.foreign_col_tids.push(looked_tid);
        table.foreign_col_indices.push(looked_idx);
        table.table_zs.push(looking_z);
        table.challenges.push(gamma);

        let table = &mut by_table[looked_tid.0];
        table.cols.push(looked_col);
        table.foreign_col_tids.push(looking_tid);
        table.foreign_col_indices.push(looking_idx);
        table.table_zs.push(looked_z);
        table.challenges.push(gamma);
    }

    CtlData { by_table }
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
    pub(crate) challenges: Vec<F>,
    pub(crate) cols: Vec<CtlColumn>,
    pub(crate) foreign_col_tids: Vec<TableID>,
    pub(crate) foreign_col_indices: Vec<usize>,
}

impl<F, const D: usize> CtlCheckVars<F, F::Extension, F::Extension, D>
where
    F: RichField + Extendable<D>,
{
    pub fn from_proofs<C: GenericConfig<D, F = F>>(
        proofs: &[StarkProofWithPublicInputs<F, C, D>],
        ctl_descriptor: &CtlDescriptor,
        ctl_challenges: &[Vec<F>],
    ) -> Vec<Self> {
        let num_tables = proofs.len();
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
        let mut ctl_zs = proofs
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

        let mut res = first_last_zs
            .map(|(first_zs, last_zs)| CtlCheckVars {
                local_zs: Vec::new(),
                next_zs: Vec::new(),
                first_zs,
                last_zs,
                challenges: Vec::new(),
                cols: Vec::new(),
                foreign_col_tids: Vec::new(),
                foreign_col_indices: Vec::new(),
            })
            .collect_vec();
        debug_assert!(res.len() == num_tables);

        for (&(looking, looked), challenges) in
            ctl_descriptor.instances.iter().zip(ctl_challenges.iter())
        {
            for &gamma in challenges {
                let (&looking_z, &looking_z_next) = ctl_zs[looking.tid.0].next().unwrap();
                let (&looked_z, &looked_z_next) = ctl_zs[looked.tid.0].next().unwrap();
                let looking_last_idx = res[looking.tid.0].cols.len();
                let looked_last_idx = res[looked.tid.0].cols.len();

                let mut vars = &mut res[looking.tid.0];
                vars.local_zs.push(looking_z);
                vars.next_zs.push(looking_z_next);
                vars.challenges.push(gamma);
                vars.cols.push(looking);
                vars.foreign_col_tids.push(looked.tid);
                vars.foreign_col_indices.push(looked_last_idx);

                vars = &mut res[looked.tid.0];
                vars.local_zs.push(looked_z);
                vars.next_zs.push(looked_z_next);
                vars.challenges.push(gamma);
                vars.cols.push(looked);
                vars.foreign_col_tids.push(looking.tid);
                vars.foreign_col_indices.push(looking_last_idx);
            }
        }
        
        res
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
    debug_assert!(ctl_vars.challenges.len() % num_challenges == 0);

    let challenges = ctl_vars.challenges.iter();
    let zs = ctl_vars.local_zs.iter().zip(ctl_vars.next_zs.iter());
    let first_last_zs = ctl_vars.first_zs.iter().zip(ctl_vars.last_zs.iter());
    let cols = ctl_vars.cols.iter();

    for (&gamma, ((&col, (&first_z, &last_z)), (&local_z, &next_z))) in
        challenges.zip((cols.zip(first_last_zs)).zip(zs))
    {
        let sel = col
            .filter_col
            .map_or(P::ONES, |filter_col| vars.next_values[filter_col]);

        let eval = vars.next_values[col.col] + FE::from_basefield(gamma) - P::ONES;

        // check first and last z evals
        // degree 1
        consumer.constraint_first_row(local_z - FE::from_basefield(first_z));
        consumer.constraint_last_row(local_z - FE::from_basefield(last_z));

        // check grand product
        // degree 3
        consumer.constraint_transition(next_z - (local_z * (sel * eval + P::ONES)));
        consumer.constraint_last_row(next_z - FE::from_basefield(first_z));

        // check against other table happens separately in `verify_cross_table_lookups` below
    }
}

pub fn verify_cross_table_lookups<
    'a,
    I: Iterator<Item = &'a StarkProof<F, C, D>>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'a,
    const D: usize,
>(
    vars: &[CtlCheckVars<F, F::Extension, F::Extension, D>],
    proofs: I,
) -> Result<()> {
    let ctl_zs_openings = proofs
        .flat_map(|p| p.openings.ctl_zs_last.iter())
        .collect_vec();

    let z_pairs = vars.iter().enumerate().flat_map(|(tid, vars)| {
        (0..vars.cols.len())
            .zip(
                vars.foreign_col_tids
                    .iter()
                    .zip(vars.foreign_col_indices.iter()),
            )
            .map(move |stuff| (tid, stuff))
            .map(|(tid, (idx, (&foreign_tid, &foreign_idx)))| {
                let local_z = ctl_zs_openings[tid][idx];
                let foreign_z = ctl_zs_openings[foreign_tid.0][foreign_idx];

                (local_z, foreign_z)
            })
    });

    for (local_z, foreign_z) in z_pairs {
        ensure!(
            local_z == foreign_z,
            "cross table lookup verification failed."
        );
    }

    Ok(())
}
