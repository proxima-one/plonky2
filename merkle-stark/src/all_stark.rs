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

pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	type AllProof;

	fn new(config: StarkConfig) -> Self;
	fn num_tables(&self) -> usize;
	fn verify(&self, proof: &Self::AllProof) -> Result<()>;
	fn prove(&self, trace_poly_valueses: &[Vec<PolynomialValues<F>>], public_inputses: &[Vec<F>], ctl_descriptors: &[CtlTableDescriptor], timing: &mut TimingTree) -> Result<Self::AllProof>;
}
