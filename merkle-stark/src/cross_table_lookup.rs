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
pub struct CtlTableDescriptor {
	looked_cols: Vec<LookedCol>,
	looking_cols: Vec<LookingCol>,
	looked_tids: Vec<TableID>,
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

struct CtlTableExport {
	tid: TableID,
	
}

/// Describes a column that is to be constrained as an "import" from the given export via a cross-table lookup
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct LookedCol {
	src: LookingCol,
	col: usize,
	filter_col: Option<usize>
}

impl LookedCol {
    fn new(src: LookingCol, col: usize, filter_col: Option<usize>) -> LookedCol {
        LookedCol {
			src,
			col,
			filter_col
		}
	}
}

/// Describes a column that is to be "exported" from this table via a cross-table lookup
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct LookingCol {
	col: usize,
	filter_col: Option<usize>
}

impl LookingCol {
    fn new(col: usize, filter_col: Option<usize>) -> LookingCol {
		LookingCol {
			col,
			filter_col
		}
    }
}


#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TableID(usize);

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
pub(crate) struct CtlInstanceData<F: Field> {
	// `num_challenges` z polys for the column in the looked (source) trace
	looked_zs: Vec<PolynomialValues<F>>,
	// `num_challenges` z polys for the column in the looking (destination) trace 
	looking_zs: Vec<PolynomialValues<F>>,
	// challenges used for the CTLs
	challenges: Vec<F>
}

pub(crate) struct CtlData<F: Field> {
	instances: Vec<CtlInstanceData<F>>
}

pub(crate) struct CtlTableData<F: Field> {
	pub(crate) table_zs: Vec<PolynomialValues<F>>,
	// challenges used for the CTLs
	challenges: Vec<F>
}

// compute the preprocessed polynomials necessary for the lookup argument given CTL traces and table descriptors
fn get_ctl_data<'a, F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(config: &StarkConfig, ctl_traces: CtlTraces<F, D>, challenger: &mut Challenger<F, C::Hasher>) -> CtlData<F> {
	let CtlTraces { trace_poly_valueses, ctl_descriptors } = ctl_traces;
	let mut instances = Vec::new();
	for (looking_tid, descriptor) in ctl_descriptors.iter().enumerate() {
		for (looking_col, (looked_col, looked_tid)) in descriptor.looking_cols.iter().zip(descriptor.looked_cols.iter().zip(descriptor.looked_tids.iter())) {
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
						let col_values = &trace_poly_valueses[looking_tid][looking_col.col].values;
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
						let col_values = &trace_poly_valueses[looking_tid][looking_col.col].values;
						let filter_col_values = &trace_poly_valueses[looking_tid][filter_col].values;

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

pub(crate) struct CtlCheckVars<F, FE, P, const D2: usize>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    pub(crate) local_z: P,
    pub(crate) next_z: P,
    pub(crate) challenges: Vec<F>,
	pub(crate) col: usize,
	pub(crate) sel_col: Option<usize>
}

pub(crate) fn eval_cross_table_lookup_checks<F, FE, P, C, S, const D: usize, const D2: usize>(
    vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
    ctl_vars: &[CtlCheckVars<F, FE, P, D2>],
    consumer: &mut ConstraintConsumer<P>,
) where
    F: RichField + Extendable<D>,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
	for lookup_vars in ctl_vars {
		for gamma in lookup_vars.challenges {
			let sel = lookup_vars.sel_col.map_or(P::ONES, |sel_col| vars.local_values[sel_col]);
			let eval = vars.local_values[lookup_vars.col] + FE::from_basefield(gamma) - FE::ONES;

			// degree 1
			consumer.constraint_first_row(lookup_vars.local_z - P::ONES);

			// degree 3
			consumer.constraint_transition(lookup_vars.next_z - (
				lookup_vars.local_z * (sel * eval + P::ONES)
			));

			// ? pretty sure the other checks only happen in the verifier, as we need to get the last z and check against the other table
		}
	}	
}

