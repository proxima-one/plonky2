use std::borrow::Borrow;
use std::marker::PhantomData;

use plonky2::field::{
    extension::{Extendable, FieldExtension},
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::ro_memory::RoMemoryDescriptor;
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

pub mod generation;
pub mod layout;

use layout::*;

pub struct RoMemoryStark<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const NUM_CHANNELS: usize>
    RoMemoryStark<F, D, NUM_CHANNELS>
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

macro_rules! impl_ro_memory_stark_for_n_channels {
    ($channels:expr) => {
        impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D>
            for RoMemoryStark<F, D, $channels>
        {
            const COLUMNS: usize = RO_MEMORY_NUM_COLS_BASE + $channels;
            const PUBLIC_INPUTS: usize = 0;

            fn eval_packed_generic<FE, P, const D2: usize>(
                &self,
                vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut ConstraintConsumer<P>,
            ) where
                FE: FieldExtension<D2, BaseField = F>,
                P: PackedField<Scalar = FE>,
            {
                // all constraints are applied by the ro memory argument. This is just a trace that holds the values
                // we check the address continuity again here because we have to have at least 1 constraint
                let curr_row: &RoMemoryRow<P, $channels> = vars.local_values.borrow();
                let next_row: &RoMemoryRow<P, $channels> = vars.next_values.borrow();
                yield_constr.constraint_transition(
                    (next_row.addr_sorted - curr_row.addr_sorted)
                        * (next_row.addr_sorted - curr_row.addr_sorted - P::ONES),
                );
            }

            fn eval_ext_circuit(
                &self,
                _builder: &mut CircuitBuilder<F, D>,
                _vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                _yield_constr: &mut RecursiveConstraintConsumer<F, D>,
            ) {
                // all constraints are applied by the ro memory argument. This is just a trace that holds the values
                // TODO: recursive read-only memory argument
                todo!()
            }

            fn constraint_degree(&self) -> usize {
                3
            }

            fn ro_memory_descriptors(&self) -> Option<Vec<RoMemoryDescriptor>> {
                Some(vec![RoMemoryDescriptor {
                    addr_col: 0,
                    value_col: 1,
                    addr_sorted_col: 2,
                    value_sorted_col: 3,
                }])
            }
        }
    };
}

impl_ro_memory_stark_for_n_channels!(1);
impl_ro_memory_stark_for_n_channels!(2);
impl_ro_memory_stark_for_n_channels!(3);
impl_ro_memory_stark_for_n_channels!(4);
impl_ro_memory_stark_for_n_channels!(34);

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::{Field, Field64};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use rand::Rng;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::stark_testing::test_stark_low_degree;
    use crate::starky2lib::ro_memory::generation::RoMemoryStarkGenerator;
    use crate::verifier::verify_stark_proof_no_ctl;


    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = RoMemoryStark<F, D, 1>;
        
        let stark = S::new();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_random_trace() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = RoMemoryStark<F, D, 1>;

        let mut rng = rand::thread_rng();
        let mut generator = RoMemoryStarkGenerator::<F, 1>::new();
        for i in 0u64..480 {
            let val_u64: u64 = rng.gen();
            let addr = F::from_canonical_u64(i);
            let val = F::from_noncanonical_u64(val_u64);
            generator.gen_access(addr, val, &[0]);
        }

        let config = StarkConfig::standard_fast_config();
        let stark = S::new();
        let trace = generator.into_polynomial_values();
        let mut timing = TimingTree::default();
        let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
        verify_stark_proof_no_ctl(&stark, &proof, &config)?;
        Ok(())
    }
}
