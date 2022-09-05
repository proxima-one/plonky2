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
/// This trait is used to configure which columns are to look up which other columns by the user.
pub trait CtlStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
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
/// This trait should only be implemented via the `impl_all_stark` macro.
pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>: CtlStark<F, C, D> {
	fn prove(&self, config: &StarkConfig, public_inputs: &[Vec<F>], timing: &mut TimingTree) -> Result<AllProof<F, C, D>>;
	fn verify(&self, inputs: &[F], proof: &AllProof<F, C, D>) -> Result<()>;	
}


/// This macro implements the `AllStark` trait for a given marker struct and a list of types that implement `Stark`
/// intended usage:
/// ```
///     use crate::{MyStark0, MyStark1, MyStark2};
/// 
///     struct MyAllStark;
///     impl_all_stark!(MyAllStark, MyStark0, MyStark1, MyStark1);
// TODO: turn this into a proc macro so the user can wire the tables together in a declarative way
#[macro_export]
macro_rules! impl_all_stark {
	() => { }
}
