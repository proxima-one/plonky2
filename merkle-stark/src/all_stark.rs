use std::sync::Arc;
use anyhow::Result;

use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::timing::TimingTree;
use plonky2::field::polynomial::PolynomialValues;
use crate::cross_table_lookup::{CtlTableDescriptor, TableID, CtlData};

use crate::config::StarkConfig;
use crate::proof::StarkProofWithPublicInputs;
use crate::stark::Stark;

/// This trait is implemented by multi-trace STARKs that use cross-table lookups
/// This trait is used to configure which columns are to look up which other columns.
/// This trait should only be implemented via the `all_stark` macro in the `all_stark` crate
pub trait CtlStark {
	fn new(config: StarkConfig) -> Self;

	/// returns the number of tables in this multi-trace STARK
	fn num_tables(&self) -> usize;

	/// returns a `CtlTableDescriptor` for each table in the STARK, specifying which columns are to be looked up from where
	/// See `CtlTableDescriptor` for more information
	fn get_table_descriptors(&self) -> Vec<CtlTableDescriptor>;
}

pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>{
	proofs: Vec<StarkProofWithPublicInputs<F, C, D>>,
	table_descriptors: Vec<CtlTableDescriptor>,
}

/// This trait is implemented by multi-trace STARKs that use cross-table lookups
/// This trait should only be implemented via the `all_stark` macro in the `all_stark` crate
pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>: CtlStark {
	// a type containing all of the `Stark` implementors for this multi-table STARK.
	type Starks;
	fn prove(&self, starks: &Self::Starks, config: &StarkConfig, trace_poly_valueses: &[Vec<PolynomialValues<F>>], public_inputs: &[Vec<F>], timing: &mut TimingTree) -> Result<AllProof<F, C, D>>;
	fn verify(&self, starks: &Self::Starks, inputs: &[F], proof: &AllProof<F, C, D>) -> Result<()>;	
}
