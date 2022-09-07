use plonky2::hash::hash_types::RichField;
use plonky2::field::packed::PackedField;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;
use maybe_rayon::*;
use itertools::{izip, Itertools};
use std::collections::{HashMap, BTreeMap};

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::util::is_power_of_two;
use crate::vars::StarkEvaluationVars;
use crate::stark::Stark;

// represents the imports and exports for a stark table relying on a cross-table lookup
#[derive(Debug, Clone)]
pub struct CtlDescriptor {
	/// instances of CTLs, where a column in one table "looks up" a column in another table
	/// represented as pairs of columns where the LHS is a column in this table and the RHS is a column in another tabe
	pub(crate) instances: Vec<(CtlColumn, CtlColumn)>,
}

impl CtlDescriptor {
	pub fn from_instances(instances: Vec<(CtlColumn, CtlColumn)>) -> Self {
		CtlDescriptor { instances }
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
	filter_col: Option<usize>
}

impl CtlColumn {
    pub fn new(tid: TableID, col: usize, filter_col: Option<usize>) -> CtlColumn {
		CtlColumn {
			tid,
			col,
			filter_col
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
	pub by_table: Vec<CtlTableData<F>>
}

#[derive(Debug, Clone)]
pub struct CtlTableData<F: Field> {
	pub(crate) cols: Vec<CtlColumn>,
	pub(crate) table_zs: Vec<PolynomialValues<F>>,
	// challenges used for the CTLs in this table
	pub(crate) challenges: Vec<F>
}

// compute the preprocessed polynomials necessary for the lookup argument given CTL traces and table descriptors
pub fn get_ctl_data<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(config: &StarkConfig, trace_poly_valueses: &[Vec<PolynomialValues<F>>], ctl_descriptor: &CtlDescriptor, challenger: &mut Challenger<F, C::Hasher>) -> CtlData<F> {
	let num_tables = trace_poly_valueses.len();
	let instances = ctl_descriptor.instances.iter().map(|_| challenger.get_n_challenges(config.num_challenges)).zip(ctl_descriptor.instances.iter().cloned()).collect_vec();

	let compute_z_poly = |gamma: F, table_idx: usize, col: usize, filter_col: Option<usize>| -> PolynomialValues<F> {
		match filter_col {
			None => {
				let col_values = &trace_poly_valueses[table_idx][col].values;
				let values = std::iter::once(F::ONE).chain(
					col_values.iter().scan(F::ONE, |prev, &eval| {
						let next = *prev * (eval + gamma);
						*prev = next;
						Some(next)
					})
				).collect();

				PolynomialValues::new(values)
			},
			Some(filter_col) => {
				let mut values = vec![F::ONE];
				let col_values = &trace_poly_valueses[table_idx][col].values;
				let filter_col_values = &trace_poly_valueses[table_idx][filter_col].values;

				for (&eval, &filter) in col_values.iter().zip(filter_col_values.iter()) {
					let prev = values.last().unwrap();
					if filter == F::ONE {
						values.push(*prev * (eval + gamma));
					} else if filter == F::ZERO {
						values.push(*prev);
					} else {
						panic!("non-binary filter col!")
					}
				}

				PolynomialValues::new(values)
			}
		}
	};

	let instances = instances.into_par_iter().flat_map_iter(|(challenges, (looking_col, looked_col))| {
		let looking = challenges.clone().into_iter().map(move |gamma| {
			let z = compute_z_poly(gamma, looking_col.tid.0, looking_col.col, looking_col.filter_col);
			(looking_col.tid, looking_col, z)
		});
		
		let looked = challenges.clone().into_iter().map(move |gamma| {
			let z = compute_z_poly(gamma, looked_col.tid.0, looked_col.col, looked_col.filter_col);
			(looked_col.tid, looked_col, z)
		});
		
		looking.zip(looked).zip(challenges.into_iter())
	}).collect::<Vec<_>>();

	let mut by_table = vec![CtlTableData { cols: Vec::new(), table_zs: Vec::new(), challenges: Vec::new() }; num_tables];
	for (((looking_tid, looking_col, looking_z), (looked_tid, looked_col, looked_z)), gamma) in instances {
		let table = &mut by_table[looking_tid.0];
		table.cols.push(looking_col);
		table.table_zs.push(looking_z);
		table.challenges.push(gamma);

		let table = &mut by_table[looked_tid.0];
		table.cols.push(looked_col);
		table.table_zs.push(looked_z);
		table.challenges.push(gamma);
	}
	
	CtlData {
		by_table,
	}
}

pub(crate) struct CtlCheckVars<'a, F, FE, P, const D2: usize>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    pub(crate) local_zs: Vec<P>,
    pub(crate) next_zs: Vec<P>,
    pub(crate) challenges: &'a [F],
	pub(crate) cols: &'a [CtlColumn],
}

pub(crate) fn eval_cross_table_lookup_checks<F, FE, P, C, S, const D: usize, const D2: usize>(
    vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
    ctl_vars: CtlCheckVars<F, FE, P, D2>,
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
	let zs_chunks = ctl_vars.local_zs.chunks_exact(num_challenges);
	let zs_chunks_next = ctl_vars.next_zs.chunks_exact(num_challenges);
	let challenge_cols = ctl_vars.challenges.iter().zip(ctl_vars.cols);
	for ((zs, zs_next), (&gamma, col)) in zs_chunks.zip(zs_chunks_next).zip(challenge_cols) {
		let sel = col.filter_col.map_or(P::ONES, |sel_col| vars.local_values[sel_col]);
		let eval = vars.local_values[col.col] + FE::from_basefield(gamma) - FE::ONES;

		for (&local_z, &next_z) in zs.iter().zip(zs_next) {

			// degree 1
			consumer.constraint_first_row(local_z - P::ONES);

			// degree 3
			consumer.constraint_transition(next_z - (
				local_z * (sel * eval + P::ONES)
			));

			// ? pretty sure the other checks only happen in the verifier, as we need to get the last z and check against the other table
		}
	}
}

