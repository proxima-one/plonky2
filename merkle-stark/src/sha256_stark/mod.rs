use std::marker::PhantomData;

use plonky2::field::{polynomial::PolynomialValues, types::Field};
use plonky2::{
    field::{
        extension::{Extendable, FieldExtension},
        packed::PackedField,
    },
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_util::log2_ceil;

use crate::{
    constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer},
    stark::Stark,
    vars::{StarkEvaluationTargets, StarkEvaluationVars},
};

pub mod constants;
pub mod constraints;
pub mod generation;
pub mod layout;

use constraints::{
    eval_bits_are_bits, eval_check_his, eval_msg_schedule, eval_phase_0_and_1, eval_phase_2,
    eval_phase_3, eval_phase_transitions, eval_round_fn, eval_shift_wis,
};
use generation::{to_u32_array_be, Sha2TraceGenerator};
use layout::{NUM_COLS, NUM_STEPS_PER_HASH};

#[derive(Copy, Clone)]
pub struct Sha2CompressionStark<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Sha2CompressionStark<F, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
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
        eval_phase_2(curr_row, next_row, yield_constr);
        eval_phase_3(curr_row, next_row, yield_constr);

        eval_phase_transitions(curr_row, next_row, yield_constr);

        eval_msg_schedule(curr_row, next_row, yield_constr);
        eval_round_fn(curr_row, next_row, yield_constr);

        eval_check_his(curr_row, next_row, yield_constr);
        eval_shift_wis(curr_row, next_row, yield_constr);
        eval_bits_are_bits(curr_row, yield_constr);
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

pub struct Sha2StarkCompressor {
    inputs: Vec<([u32; 8], [u32; 8])>,
}

impl Sha2StarkCompressor {
    pub fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    pub fn add_instance(&mut self, left_input: [u8; 32], right_input: [u8; 32]) {
        let left = to_u32_array_be(left_input);
        let right = to_u32_array_be(right_input);

        self.inputs.push((left, right));
    }

    /// returns the generated trace against which a proof may be generated
    pub fn generate<F: Field>(self) -> Vec<PolynomialValues<F>> {
        let max_rows = 1 << log2_ceil(self.inputs.len() * NUM_STEPS_PER_HASH);
        let mut generator = Sha2TraceGenerator::<F>::new(max_rows);
        for (left, right) in self.inputs.into_iter() {
            generator.gen_hash(left, right);
        }

        generator.into_polynomial_values()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove;
    use crate::sha256_stark::generation::Sha2TraceGenerator;
    use crate::stark_testing::test_stark_low_degree;
    use crate::verifier::verify_stark_proof;

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let stark = S::new();
        test_stark_low_degree(stark)
    }

    // #[test]
    // fn test_stark_circuit() -> Result<()> {
    //     const D: usize = 2;
    //     type C = PoseidonGoldilocksConfig;
    //     type F = <C as GenericConfig<D>>::F;
    //     type S = Sha2CompressionStark<F, D>;

    //     let stark = S::new();

    //     test_stark_circuit_constraints::<F, C, S, D>(stark)
    // }

    #[test]
    fn test_single() -> Result<()> {
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
        let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing)?;

        verify_stark_proof(stark, proof, &config)?;

        Ok(())
    }

    #[test]
    fn test_multiple() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = Sha2CompressionStark<F, D>;

        let mut left_input = [0; 32];
        let mut right_input = [0; 32];
        for i in 0..32 {
            left_input[i] = i as u8;
            right_input[i] = i as u8 + 32;
        }

        let mut compressor = Sha2StarkCompressor::new();
        compressor.add_instance(left_input, right_input);

        let mut left_input = [0; 32];
        let mut right_input = [0; 32];
        for i in 0..32 {
            left_input[i] = i as u8 + 64;
            right_input[i] = i as u8 + 96;
        }

        compressor.add_instance(left_input, right_input);
        let trace = compressor.generate();

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let mut timing = TimingTree::default();
        let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut timing)?;

        verify_stark_proof(stark, proof, &config)?;

        Ok(())
    }
}
