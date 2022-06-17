use plonky2::field::extension_field::{Extendable, FieldExtension};
use plonky2::field::packed_field::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::alu::*;
use super::alu_recursive::{
    constrain_boundary_constraints_recursively, constrain_insn_recursively,
    constrain_state_transition_recursively,
};
use super::layout::*;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::stark::Stark;
use crate::vars::StarkEvaluationTargets;
use crate::vars::StarkEvaluationVars;

#[derive(Clone, Debug)]
pub struct MaruSTARK<F: RichField + Extendable<D>, const D: usize> {
    public_mem: Vec<(F, F)>,
    num_padding_insns: u64,
}

impl<F: RichField + Extendable<D>, const D: usize> MaruSTARK<F, D> {
    pub fn new(public_mem: Vec<(F, F)>, num_padding_insns: u64) -> Self {
        Self {
            public_mem,
            num_padding_insns,
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for MaruSTARK<F, D> {
    const COLUMNS: usize = NUM_COLUMNS;
    const PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        constrainer: &mut ConstraintConsumer<P>,
        // interaction_challenges: Option<&Vec<FE>>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        constrain_insn(vars.local_values, vars.next_values, constrainer);
        constrain_state_transition(vars.local_values, vars.next_values, constrainer);
        constrain_boundary_constraints(
            vars.local_values,
            vars.next_values,
            vars.public_inputs,
            constrainer,
        );
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        constrainer: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let StarkEvaluationTargets::<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS> {
            local_values,
            next_values,
            public_inputs,
        } = vars;

        constrain_insn_recursively(builder, local_values, constrainer);
        constrain_state_transition_recursively(builder, local_values, next_values, constrainer);
        constrain_boundary_constraints_recursively(
            builder,
            local_values,
            public_inputs,
            constrainer,
        );
    }

    fn constraint_degree(&self) -> usize {
        // total degree or single variable degree?
        3
    }

    // fn public_memory_width() -> usize {
    //     4
    // }

    // fn public_memory_pis(&self) -> Option<Vec<usize>> {
    //     Some(vec![
    //         PUBLIC_MEMORY_PRODUCT_0,
    //         PUBLIC_MEMORY_PRODUCT_1,
    //         RC_MIN,
    //         RC_MAX,
    //         CLK_FINAL
    //     ])
    // }

    // fn public_memory_cols() -> Option<[usize; 4]> {
    //     Some([
    //         PC_COL,
    //         PC_MEM_COL,
    //         ADDR_SORTED_COLS[0],
    //         MEM_SORTED_COLS[0],
    //     ])
    // }
}
