use plonky2::hash::hash_types::RichField;
use plonky2::field::packed::PackedField;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use std::collections::HashMap;

use crate::util::is_power_of_two;
use crate::vars::StarkEvaluationVars;
use crate::stark::Stark;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Import(usize);

impl Import {
    fn new(column: usize) -> Import {
        Import(column)
	}
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Export(usize);

impl Export {
    fn new(column: usize) -> Export {
        Export(column)
    }
}


#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

/// a STARK that performs a domain-free cross-table lookup argument
pub trait CtlStark<F: RichField + Extendable<D>, const D: usize>: Stark<F, D> {
    /// columns of this stark's trace that are to be "imported" from an external trace
	/// given an ID for the table. The caller must ensure this ID is the same across traces
    fn import_cols() -> Vec<usize> {
        vec![]
    }

    /// columns of this stark's trace that are to be "exported" to an external trace
    fn col_exports(table_id: TableID) -> Vec<Export> {
        vec![]
    }

    /// for each import/export, indicate whether or not the current row should be included in the import/export.
    fn eval_selectors<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
    )
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ImportOrExport {
	Import(Import),
	Export(Export),
}

impl From<Import> for ImportOrExport {
	fn from(import: Import) -> Self {
		ImportOrExport::Import(import)
	}
}

impl From<Export> for ImportOrExport {
	fn from(export: Export) -> Self {
		ImportOrExport::Export(export)
	}
}

pub struct CtlConsumer<F: RichField + Extendable<D>, const D: usize> {
	// false if import, true if export
	sels: HashMap<ImportOrExport, Vec<(usize, F)>>,
	trace_len: usize,
	idx: usize
}

impl<F: RichField + Extendable<D>, const D: usize> CtlConsumer<F, D> {
	pub(crate) fn new(imports: &[Import], exports: &[Export], trace_len: usize) -> CtlConsumer<F, D> {
		let mut sels = HashMap::with_capacity(imports.len() + exports.len());

		for &import in imports {
			sels.insert(import.into(), Vec::new());
		}
		for &export in exports {
			sels.insert(export.into(), Vec::new());
		}

		let idx = 0;

		CtlConsumer { sels, trace_len, idx }
	}

	pub(crate) fn advance(&mut self) {
		self.idx += 1;
	}

	pub fn import_at_col(&mut self, col: usize, val: F) {
		let idx = self.idx;
		let sels = self.sels.get_mut(&ImportOrExport::Import(Import::new(col))).expect("not an import column for this CTL!");
		sels.push((idx, val));
	}

	pub fn export_at_col(&mut self, col: usize, val: F) {
		let idx = self.idx;
		let sels = self.sels.get_mut(&ImportOrExport::Export(Export::new(col))).expect("not an export column for this CTL!");
		sels.push((idx, val));
	}

	fn compute_polys(self, challenges: Vec<F>) -> CtlPolynomials<F, D> {
		let mut import_sels = Vec::new();
		let mut export_sels = Vec::new(); 
		let mut import_zs = Vec::new();
		let mut export_zs = Vec::new();
		let mut import_cols = Vec::new();
		let mut export_cols = Vec::new();

		for (marker, active_rows) in self.sels.into_iter() {
			match marker {
				ImportOrExport::Import(col) => {
					let mut sel = PolynomialValues::new(vec![F::ZERO; self.trace_len]);
					let mut zs = vec![PolynomialValues::new(vec![F::ONE; self.trace_len]); challenges.len()];
					let mut curr_evals = vec![F::ONE; challenges.len()];
					let mut z_idx = 0;
					
					for (row, val) in active_rows {
						sel.values[row] = F::ONE;

						while z_idx < row {
							for (i, z) in zs.iter_mut().enumerate() {
								z.values[z_idx] = curr_evals[i];
								z_idx += 1;
							}
						}


						for (i, z) in zs.iter_mut().enumerate() {
							curr_evals[i] *= val + challenges[i];
							z.values[row] += curr_evals[i];
						}
					}

					import_sels.push(sel);
					import_zs.push(zs);
					import_cols.push(col.0);
				},
				ImportOrExport::Export(col) => {
					let mut sel = PolynomialValues::new(vec![F::ZERO; self.trace_len]);
					let mut zs = vec![PolynomialValues::new(vec![F::ONE; self.trace_len]); challenges.len()];
					let mut curr_evals = vec![F::ONE; challenges.len()];
					let mut z_idx = 0;

					for (row, val) in active_rows {
						sel.values[row] = F::ONE;

						while z_idx < row {
							for (i, z) in zs.iter_mut().enumerate() {
								z.values[z_idx] = curr_evals[i];
								z_idx += 1;
							}
						}


						for (i, z) in zs.iter_mut().enumerate() {
							curr_evals[i] *= val + challenges[i];
							z.values[row] += curr_evals[i];
						}
					}

					export_sels.push(sel);
					export_zs.push(zs);
					export_cols.push(col.0);
				}
			}
		}

		CtlPolynomials {
			import_sels,
			export_sels,
			import_zs,
			export_zs,
			import_cols,
			export_cols
		}
	}
}

pub(crate) struct CtlPolynomials<F: RichField + Extendable<D>, const D: usize> {
	import_cols: Vec<usize>,
	export_cols: Vec<usize>,
	import_zs: Vec<Vec<PolynomialValues<F>>>,
	export_zs: Vec<Vec<PolynomialValues<F>>>,
	import_sels: Vec<PolynomialValues<F>>,
	export_sels: Vec<PolynomialValues<F>>,
}
