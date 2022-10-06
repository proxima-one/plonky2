use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::timing::TimingTree;

use crate::config::StarkConfig;
use crate::cross_table_lookup::CtlDescriptor;
use crate::proof::StarkProofWithPublicInputs;

/// This trait is implemented by multi-trace STARKs that use cross-table lookups
/// This trait is used to configure which columns are to look up which other columns.
/// It is highly reccomended to implement this trait via the `derive(AllStark)` macro in the `all_stark_derive` crate
pub trait CtlStark<F: Field> {
    /// Data needed to generate all of the traces
    type GenData;

    /// returns the number of tables in this multi-trace STARK
    fn num_tables(&self) -> usize;

    /// returns a `CtlDescriptor`, which contains pairs `CtlColumn`s that represent each CTL to perform.
    /// IMPORTANT: This method establishes the ordering for extracing challenge points, so the ordering of the instances returned must be deterministic.
    /// see `CtlDescriptor` for more information
    fn get_ctl_descriptor(&self) -> CtlDescriptor;

    /// generate all of the traces
    /// returns (public_inputses, traces_poly_valueses)
    fn generate(
        &self,
        gen_data: Self::GenData,
    ) -> Result<(Vec<Vec<F>>, Vec<Vec<PolynomialValues<F>>>)>;
}

/// an aggregate multi-table STARK proof.
pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proofs: Vec<StarkProofWithPublicInputs<F, C, D>>,
}

/// This trait is implemented by multi-trace STARKs that use cross-table lookups
/// TODO: `derive(AllStark)` macro in a new `all_stark_derive` crate that can be used to auto-implement this.
pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>:
    CtlStark<F>
{
    // a type containing all of the `Stark` implementors for this multi-table STARK.
    type Starks;

    /// return instances of all of the `Stark` implementors
    fn get_starks(&self, config: &StarkConfig) -> Self::Starks;

    fn prove(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        trace_poly_valueses: &[Vec<PolynomialValues<F>>],
        public_inputses: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>;
    fn verify(
        &self,
        starks: &Self::Starks,
        config: &StarkConfig,
        proof: &AllProof<F, C, D>,
    ) -> Result<()>;
}
