use anyhow::ensure;
use anyhow::Result;
use itertools::izip;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::Hasher;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::config::StarkConfig;
use crate::cross_table_lookup::get_ctl_data;
use crate::cross_table_lookup::verify_cross_table_lookups;
use crate::cross_table_lookup::CtlCheckVars;
use crate::cross_table_lookup::CtlDescriptor;
use crate::get_challenges::get_ctl_challenges_by_table;
use crate::get_challenges::start_all_proof_challenger;
use crate::proof::StarkProofWithPublicInputs;
use crate::prover::prove_single_table;
use crate::prover::start_all_proof;
use crate::stark::Stark;
use crate::verifier::verify_stark_proof_with_ctl;

/// an aggregate multi-table STARK proof.
pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proofs: Vec<StarkProofWithPublicInputs<F, C, D>>,
}

/// A set of associated starks sticthed together via cross-table-lookups
pub trait AllStark<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// returns the number of starks / traces / tables in this composite multi-stark "AllStark" construction
    fn num_starks() -> usize;

    /// returns a `CtlDescriptor`, which contains pairs `CtlColumn`s that represent each CTL to perform.
    /// IMPORTANT: This method establishes the ordering for extracing challenge points, so the ordering of the instances returned must be deterministic.
    /// see `CtlDescriptor` for more information
    fn get_ctl_descriptor(&self) -> CtlDescriptor;

    fn prove(
        &self,
        config: &StarkConfig,
        traces_evals: &[Vec<PolynomialValues<F>>],
        public_inputs: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:;

    fn verify(&self, config: &StarkConfig, all_proof: &AllProof<F, C, D>) -> Result<()>
    where
        [(); C::Hasher::HASH_SIZE]:;
}
