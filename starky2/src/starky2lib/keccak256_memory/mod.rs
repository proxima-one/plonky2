#![allow(dead_code)]

/// STARK that does keccak256 by looking up keccak-f and reading input from a read-only memory

pub mod generation;
pub mod layout;

use std::marker::PhantomData;

use layout::*;
use plonky2::field::{
    extension::{Extendable, FieldExtension},
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;

use crate::permutation::PermutationPair;
use crate::{
    constraint_consumer::ConstraintConsumer, stark::Stark,
    vars::StarkEvaluationVars,
};

pub struct Keccak256SpongeStark<F: RichField + Extendable<D>, const D: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Keccak256SpongeStark<F, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Default for Keccak256SpongeStark<F, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for Keccak256SpongeStark<F, D> {
    const COLUMNS: usize = KECCAK_256_STACK_NUM_COLS;
    const PUBLIC_INPUTS: usize = KECCAK_256_STACK_NUM_PIS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        _vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        _yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        todo!()
    }

    fn eval_ext_circuit(
        &self,
        _builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        _vars: crate::vars::StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        _yield_constr: &mut crate::constraint_consumer::RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn permutation_pairs(&self) -> Vec<PermutationPair> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;

    use super::generation::{Keccak256InputStack, Keccak256StackGenerator};
    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::stark_testing::test_stark_low_degree;
    use crate::verifier::verify_stark_proof_no_ctl;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type S = Keccak256SpongeStark<F, D>;

    // #[test]
    // fn test_stark_degree() -> Result<()> {
    //     let stark = Keccak256SpongeStark::<F, D>::new();
    //     test_stark_low_degree(stark)
    // }

    // #[test]
    // fn test_basic() -> Result<()> {
    //     todo!()
    // }
}
