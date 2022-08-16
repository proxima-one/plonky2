use plonky2::hash::hash_types::RichField;
use plonky2::field::packed::PackedField;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use std::collections::{HashMap, BTreeMap};

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

pub struct CtlConsumer<F: RichField + Extendable<D>, const D: usize> {
	import_sels: BTreeMap<usize, Vec<(usize, F)>>,
	export_sels: BTreeMap<usize, Vec<(usize, F)>>,
	trace_len: usize,
	idx: usize
}

impl<F: RichField + Extendable<D>, const D: usize> CtlConsumer<F, D> {
	pub(crate) fn new(imports: &[Import], exports: &[Export], trace_len: usize) -> CtlConsumer<F, D> {
		let mut import_sels = BTreeMap::with_capacity(imports.len());
		let mut export_sels = BTreeMap::with_capacity(exports.len());

		for &import in imports {
			import_sels.insert(import.0, Vec::new());
		}
		for &export in exports {
			export_sels.insert(export.0, Vec::new());
		}

		let idx = 0;

		CtlConsumer { import_sels, export_sels, trace_len, idx }
	}

	pub(crate) fn advance(&mut self) {
		self.idx += 1;
	}

	pub fn import_at_col(&mut self, col: usize, val: F) {
		let idx = self.idx;
		let sels = self.import_sels.get_mut(&col).expect("not an import column for this CTL!");
		sels.push((idx, val));
	}

	pub fn export_at_col(&mut self, col: usize, val: F) {
		let idx = self.idx;
		let sels = self.export_sels.get_mut(&col).expect("not an export column for this CTL!");
		sels.push((idx, val));
	}
	

	fn eval_selector_polys(&self) -> CtlSelectorPolynomials<F, D> {
		let mut import_sels = Vec::new();
		let mut export_sels = Vec::new(); 
		let mut import_cols = Vec::new();
		let mut export_cols = Vec::new();

		for (col, active_rows) in self.import_sels.iter() {
			let mut sel = PolynomialValues::new(vec![F::ZERO; self.trace_len]);
			
			for &(row, val) in active_rows {
				sel.values[row] = F::ONE;
			}

			import_sels.push(sel);
			import_cols.push(*col);
		}

		for (col, active_rows) in self.export_sels.iter() {
			let mut sel = PolynomialValues::new(vec![F::ZERO; self.trace_len]);
			
			for &(row, val) in active_rows {
				sel.values[row] = F::ONE;
			}

			export_sels.push(sel);
			export_cols.push(*col);
		}

		CtlSelectorPolynomials {
			import_sels,
			export_sels,
			import_cols,
			export_cols
		}
	}

	fn eval_z_polys(&self, challenges: &[F]) -> CtlZPolynomials<F, D> {
		let mut import_zs = Vec::with_capacity(self.import_sels.len());
		let mut export_zs = Vec::with_capacity(self.export_sels.len());

		for (col, active_rows) in self.import_sels.iter() {
			let mut zs = vec![PolynomialValues::new(vec![F::ONE; active_rows.len() + 1]); challenges.len()];

			for ((i, z), &gamma) in zs.iter_mut().enumerate().zip(challenges) {
				let mut curr_eval = F::ONE;
				let mut prev_row = 0;
				for &(row, val) in active_rows {
					for _ in prev_row..row {
						z.values.push(curr_eval);
					}
					prev_row = row;
					curr_eval *= val + gamma;
				}
			}
			
			for &(row, val) in active_rows {
				for i in prev_row..row {
				}
				z.values[row] = val;
			}

			import_zs.push(z);
		}

		CtlZPolynomials { import_sels, export_sels }
	}
}

pub(crate) struct CtlSelectorPolynomials<F: RichField + Extendable<D>, const D: usize> {
	import_cols: Vec<usize>,
	export_cols: Vec<usize>,
	import_sels: Vec<PolynomialValues<F>>,
	export_sels: Vec<PolynomialValues<F>>,
}

pub(crate) struct CtlZPolynomials<F: RichField + Extendable<D>, const D: usize> {
	import_zs: Vec<Vec<PolynomialValues<F>>>,
	export_zs: Vec<Vec<PolynomialValues<F>>>,
}
