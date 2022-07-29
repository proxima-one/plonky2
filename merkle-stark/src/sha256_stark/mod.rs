use std::marker::PhantomData;

use plonky2::{field::{extension::{Extendable, FieldExtension}, packed::PackedField}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};

use crate::{stark::Stark, vars::{StarkEvaluationVars, StarkEvaluationTargets}, constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer}};

pub mod constants;
pub mod layout;
pub mod constraints;
pub mod generation;

use constraints::{eval_phase_0_and_1, eval_phase_2, eval_phase_3, eval_msg_schedule, eval_round_fn, eval_phase_transitions, eval_shift_wis, eval_bits_are_bits};
use layout::NUM_COLS;

#[derive(Copy, Clone)]
pub struct Sha2CompressionStark<F: RichField + Extendable<D>, const D: usize> {
	_phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Sha2CompressionStark<F, D> {
    pub fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for Sha2CompressionStark<F, D> {
    const COLUMNS: usize = NUM_COLS;
    const PUBLIC_INPUTS: usize = 0;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
		let curr_row = vars.local_values;
		let next_row = vars.next_values;

        eval_phase_0_and_1(curr_row, next_row, yield_constr);
		// eval_phase_2(curr_row, next_row, yield_constr);
		// eval_phase_3(curr_row, next_row, yield_constr);

		eval_phase_transitions(curr_row, next_row, yield_constr);

		eval_msg_schedule(curr_row, next_row, yield_constr);
		eval_round_fn(curr_row, next_row, yield_constr);

		eval_shift_wis(curr_row, next_row, yield_constr);
		eval_bits_are_bits(curr_row, next_row, yield_constr);
    }

	fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
		todo!()
	}

	fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_stark::generation::Sha2TraceGenerator;
    use crate::config::StarkConfig;
    use crate::proof::StarkProofWithPublicInputs;
    use crate::prover::prove;
    use crate::verifier::verify_stark_proof;

    use plonky2::util::timing::TimingTree;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use anyhow::Result;


    #[test]
    fn test_stark() ->  Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let mut left_input = [0u32; 8];
        let mut right_input = [0u32; 8];
        for i in 0..8 {
            left_input[i] = i as u32;
            right_input[i] = i as u32 + 8;
        }


        let mut generator = Sha2TraceGenerator::<F>::new(128);
        generator.gen_hash(left_input, right_input);

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let proof = prove::<F, C, S, D>(
            stark,
            &config,
            trace,
            [],
            &mut timing
        )?;

        verify_stark_proof(stark, proof, &config)?;

        Ok(())
    }
}