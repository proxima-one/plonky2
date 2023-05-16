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
        starks: &[&impl Stark<F, D>],
        config: &StarkConfig,
        traces_evals: &[Vec<PolynomialValues<F>>],
        public_inputses: &[Vec<F>],
        timing: &mut TimingTree,
    ) -> Result<AllProof<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        ensure!(
            starks.len() == Self::num_starks(),
            "number of starks given must be equal to AllStark::num_starks()"
        );
        ensure!(
            starks.len() == traces_evals.len(),
            "number of traces must be equal to the number of starks"
        );

        for (stark, pis) in starks.iter().zip(public_inputses.iter()) {
            ensure!(
                stark.num_public_inputs() == pis.len(),
                "each stark must have the correct number of corresponding public inputs"
            );
        }

        for (stark, trace_evals) in starks.iter().zip(traces_evals.iter()) {
            ensure!(
                stark.num_columns() == trace_evals.len(),
                "each stark must have the correct number of columns"
            );
        }

        let (trace_commitments, mut challenger) =
            start_all_proof::<F, C, D>(config, traces_evals, timing)?;

        let ctl_descriptor = self.get_ctl_descriptor();
        assert_eq!(ctl_descriptor.num_tables, starks.len());

        let ctl_data = timed!(
            timing,
            "get ctl data",
            get_ctl_data::<F, C, D>(config, traces_evals, &ctl_descriptor, &mut challenger,)
        );

        let mut proofs = Vec::with_capacity(starks.len());
        for (&stark, trace_commitment, trace_evals, ctl_data, public_inputs) in izip!(
            starks,
            &trace_commitments,
            traces_evals,
            &ctl_data.by_table,
            public_inputses
        ) {
            let proof = prove_single_table(
                stark,
                config,
                trace_evals,
                trace_commitment,
                Some(ctl_data),
                public_inputs,
                &mut challenger,
                timing,
            )?;
            proofs.push(proof);
        }

        Ok(AllProof { proofs })
    }

    fn verify(
        &self,
        starks: &[&impl Stark<F, D>],
        config: &StarkConfig,
        all_proof: &AllProof<F, C, D>,
    ) -> Result<()>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        ensure!(
            starks.len() == Self::num_starks(),
            "number of starks given must be equal to AllStark::num_starks()"
        );
        ensure!(
            starks.len() == all_proof.proofs.len(),
            "number of starks given must be equal to number of proofs"
        );

        let mut challenger = start_all_proof_challenger::<F, C, _, D>(
            all_proof.proofs.iter().map(|proof| &proof.proof.trace_cap),
        );
        let num_challenges = config.num_challenges;

        let ctl_descriptor = self.get_ctl_descriptor();
        let (linear_comb_challenges, ctl_challenges) = get_ctl_challenges_by_table::<F, C, D>(
            &mut challenger,
            &ctl_descriptor,
            num_challenges,
        );

        let ctl_vars = CtlCheckVars::from_proofs(
            &all_proof.proofs,
            &ctl_descriptor,
            &linear_comb_challenges,
            &ctl_challenges,
        );

        for (&stark, proof, ctl_vars) in izip!(starks, &all_proof.proofs, &ctl_vars) {
            verify_stark_proof_with_ctl(stark, proof, ctl_vars, &mut challenger, config)?;
        }

        verify_cross_table_lookups(
            all_proof.proofs.iter().map(|p| &p.proof),
            &ctl_descriptor,
            num_challenges,
        )?;

        Ok(())
    }
}
