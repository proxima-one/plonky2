use plonky2::hash::hash_types::RichField;
use plonky2::field::packed::PackedField;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;
use std::collections::{HashMap, BTreeMap};

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::util::is_power_of_two;
use crate::vars::StarkEvaluationVars;
use crate::stark::Stark;

// represents the imports and exports for a stark table relying on a cross-table lookup
#[derive(Debug, Clone)]
pub struct CtlTableDescriptor {
	pub(crate) tid: TableID,
	pub(crate) looked_cols: Vec<Col>,
	pub(crate) looking_cols: Vec<Col>,
	pub(crate) looked_tids: Vec<TableID>,
}


pub struct CtlExport {
	col: usize,
	filter_col: Option<usize>
}

impl CtlExport {
	pub fn new(col: usize, filter_col: Option<usize>) -> CtlExport {
		CtlExport {
			col,
			filter_col
		}	
	}
}

pub struct CtlImport {
	col: usize,
	filter_col: Option<usize>
}

impl CtlImport {
	pub fn new(col: usize, filter_col: Option<usize>) -> CtlImport {
		CtlImport {
			col,
			filter_col
		}	
	}	
}

/// Describes a column that is involved in a cross-table lookup
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Col {
	col: usize,
	filter_col: Option<usize>
}

impl Col {
    fn new(col: usize, filter_col: Option<usize>) -> Col {
		Col {
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

/// Represents a set traces from different STARKs which ferform cross-table lookups against each other.
/// the ith element of `table_descriptors` represents the ith element of `trarce_poly_values`.
pub struct CtlTraces<'a, F: RichField + Extendable<D>, const D: usize> {
	trace_poly_valueses: &'a [Vec<PolynomialValues<F>>],
	ctl_descriptors: Vec<CtlTableDescriptor>,
}

// the preprocessed polynomials necessary for a single CTL argument
#[derive(Debug, Clone)]
pub(crate) struct CtlInstanceData<F: Field> {
	looking_col: Col,
	looked_col: Col,
	looking_tid: TableID,
	looked_tid: TableID,
	// `num_challenges` z polys for the column in the looked (source) trace
	looked_zs: Vec<PolynomialValues<F>>,
	// `num_challenges` z polys for the column in the looking (destination) trace 
	looking_zs: Vec<PolynomialValues<F>>,
	// challenges used for the CTLs
	challenges: Vec<F>
}

#[derive(Debug, Clone)]
pub(crate) struct CtlData<F: Field> {
	instances: Vec<CtlInstanceData<F>>
}

#[derive(Debug, Clone)]
pub(crate) struct CtlTableData<F: Field> {
	pub(crate) cols: Vec<Col>,
	pub(crate) table_zs: Vec<PolynomialValues<F>>,
	// challenges used for the CTLs in this table
	pub(crate) challenges: Vec<F>
}

pub(crate) fn ctl_data_by_table<F: Field>(ctl_data: CtlData<F>, num_tables: usize) -> Vec<CtlTableData<F>> {
	let mut res = vec![
		CtlTableData::<F> {
			cols: vec![],
			table_zs: vec![],
			challenges: vec![]
		};
		num_tables
	];
	
	for instance in ctl_data.instances {
		let td = &mut res[instance.looking_tid.0];
		td.table_zs.extend(instance.looking_zs);
		td.challenges.extend(instance.challenges.clone());
		td.cols.push(instance.looking_col);

		let td = &mut res[instance.looked_tid.0];
		td.table_zs.extend(instance.looked_zs);
		td.challenges.extend(instance.challenges);
		td.cols.push(instance.looked_col);
	}

	res
}

// compute the preprocessed polynomials necessary for the lookup argument given CTL traces and table descriptors
fn get_ctl_data<'a, F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(config: &StarkConfig, ctl_traces: CtlTraces<F, D>, challenger: &mut Challenger<F, C::Hasher>) -> CtlData<F> {
	let CtlTraces { trace_poly_valueses, ctl_descriptors } = ctl_traces;
	let mut instances = Vec::new();
	for descriptor in ctl_descriptors.iter(){
		let looking_tid = descriptor.tid;
		for (&looking_col, (&looked_col, &looked_tid)) in descriptor.looking_cols.iter().zip(descriptor.looked_cols.iter().zip(descriptor.looked_tids.iter())) {
			let challenges = challenger.get_n_challenges(config.num_challenges);
			let looked_zs = challenges.iter().map(|&gamma| {
				match looked_col.filter_col {
					None => {
						let col_values = &trace_poly_valueses[looked_tid.0][looked_col.col].values;
						std::iter::once(F::ONE).chain(
							col_values.iter().scan(F::ONE, |prev, &eval| {
								let next = *prev * (eval + gamma);
								*prev = next;
								Some(next)
							})
						).collect()
					}
					Some(filter_col) => {
						let mut values = vec![F::ONE];
						let col_values = &trace_poly_valueses[looked_tid.0][looked_col.col].values;
						let filter_col_values = &trace_poly_valueses[looked_tid.0][filter_col].values;

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

						values
					}
				}
			}).map(PolynomialValues::new).collect();

			let looking_zs = challenges.iter().map(|&gamma| {
				match looking_col.filter_col {
					None => {
						let col_values = &trace_poly_valueses[looking_tid.0][looking_col.col].values;
						std::iter::once(F::ONE).chain(
							col_values.iter().scan(F::ONE, |prev, &eval| {
								let next = *prev * (eval + gamma);
								*prev = next;
								Some(next)
							})
						).collect()
					}
					Some(filter_col) => {
						let mut values = vec![F::ONE];
						let col_values = &trace_poly_valueses[looking_tid.0][looking_col.col].values;
						let filter_col_values = &trace_poly_valueses[looking_tid.0][filter_col].values;

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

						values
					}
				}
			}).map(PolynomialValues::new).collect();

			instances.push(CtlInstanceData {
				looked_col,
				looking_col,
				looked_tid,
				looking_tid,
				looked_zs,
				looking_zs,
				challenges,
			})
		}
	}

	CtlData {
		instances,
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
	pub(crate) cols: &'a [Col],
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

