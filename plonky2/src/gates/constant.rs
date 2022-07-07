#[cfg(feature = "buffer_verifier")]
use std::io::Result as IoResult;

#[cfg(feature = "buffer_verifier")]
use byteorder::{ByteOrder, LittleEndian};
use plonky2_field::extension::Extendable;
use plonky2_field::packed::PackedField;

#[cfg(feature = "buffer_verifier")]
use super::gate::GateBox;
#[cfg(feature = "buffer_verifier")]
use crate::buffer_verifier::serialization::GateKind;
use crate::gates::gate::Gate;
use crate::gates::packed_util::PackedEvaluableBase;
use crate::gates::util::StridedConstraintConsumer;
use crate::hash::hash_types::RichField;
use crate::iop::ext_target::ExtensionTarget;
use crate::iop::generator::WitnessGenerator;
use crate::plonk::circuit_builder::CircuitBuilder;
use crate::plonk::vars::{
    EvaluationTargets, EvaluationVars, EvaluationVarsBase, EvaluationVarsBaseBatch,
    EvaluationVarsBasePacked,
};

/// A gate which takes a single constant parameter and outputs that value.
#[derive(Copy, Clone, Debug)]
pub struct ConstantGate {
    pub(crate) num_consts: usize,
}

impl ConstantGate {
    pub fn const_input(&self, i: usize) -> usize {
        debug_assert!(i < self.num_consts);
        i
    }

    pub fn wire_output(&self, i: usize) -> usize {
        debug_assert!(i < self.num_consts);
        i
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for ConstantGate {
    fn id(&self) -> String {
        format!("{:?}", self)
    }

    #[cfg(feature = "buffer_verifier")]
    fn kind(&self) -> GateKind {
        GateKind::Constant
    }

    #[cfg(feature = "buffer_verifier")]
    fn serialize(&self, dst: &mut [u8]) -> IoResult<usize> {
        LittleEndian::write_u64(dst, self.num_consts as u64);
        Ok(std::mem::size_of::<u64>())
    }

    #[cfg(feature = "buffer_verifier")]
    fn deserialize(src: &[u8]) -> IoResult<GateBox<F, D>> {
        let num_consts = LittleEndian::read_u64(src) as usize;
        Ok(GateBox::new(ConstantGate { num_consts }))
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        (0..self.num_consts)
            .map(|i| {
                vars.local_constants[self.const_input(i)] - vars.local_wires[self.wire_output(i)]
            })
            .collect()
    }

    fn eval_unfiltered_base_one(
        &self,
        _vars: EvaluationVarsBase<F>,
        _yield_constr: StridedConstraintConsumer<F>,
    ) {
        panic!("use eval_unfiltered_base_packed instead");
    }

    fn eval_unfiltered_base_batch(&self, vars_base: EvaluationVarsBaseBatch<F>) -> Vec<F> {
        self.eval_unfiltered_base_batch_packed(vars_base)
    }

    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        (0..self.num_consts)
            .map(|i| {
                builder.sub_extension(
                    vars.local_constants[self.const_input(i)],
                    vars.local_wires[self.wire_output(i)],
                )
            })
            .collect()
    }

    fn generators(&self, _row: usize, _local_constants: &[F]) -> Vec<Box<dyn WitnessGenerator<F>>> {
        vec![]
    }

    fn num_wires(&self) -> usize {
        self.num_consts
    }

    fn num_constants(&self) -> usize {
        self.num_consts
    }

    fn degree(&self) -> usize {
        1
    }

    fn num_constraints(&self) -> usize {
        self.num_consts
    }

    fn extra_constant_wires(&self) -> Vec<(usize, usize)> {
        (0..self.num_consts)
            .map(|i| (self.const_input(i), self.wire_output(i)))
            .collect()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for ConstantGate {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        mut yield_constr: StridedConstraintConsumer<P>,
    ) {
        yield_constr.many((0..self.num_consts).map(|i| {
            vars.local_constants[self.const_input(i)] - vars.local_wires[self.wire_output(i)]
        }));
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::goldilocks_field::GoldilocksField;

    use crate::gates::constant::ConstantGate;
    use crate::gates::gate_testing::{test_eval_fns, test_low_degree};
    use crate::plonk::circuit_data::CircuitConfig;
    use crate::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn low_degree() {
        let num_consts = CircuitConfig::standard_recursion_config().num_constants;
        let gate = ConstantGate { num_consts };
        test_low_degree::<GoldilocksField, _, 2>(gate)
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let num_consts = CircuitConfig::standard_recursion_config().num_constants;
        let gate = ConstantGate { num_consts };
        test_eval_fns::<F, C, _, D>(gate)
    }
}
