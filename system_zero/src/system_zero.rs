use std::marker::PhantomData;

use plonky2::field::extension_field::{Extendable, FieldExtension};
use plonky2::field::packed_field::PackedField;
use plonky2::hash::hash_types::RichField;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::stark::Stark;
use starky::vars::StarkEvaluationTargets;
use starky::vars::StarkEvaluationVars;

use crate::column_layout::NUM_COLUMNS;
use crate::memory::TransactionMemory;
use crate::public_input_layout::NUM_PUBLIC_INPUTS;

pub struct SystemZero<F: RichField + Extendable<D>, const D: usize> {
    memory: TransactionMemory,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for SystemZero<F, D> {
    const COLUMNS: usize = NUM_COLUMNS;
    const PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn generate_first_row(&self) -> [F; NUM_COLUMNS] {
        let mut first_values = [F::ZERO; NUM_COLUMNS];
        self.generate_first_row_core_registers(&mut first_values);
        self.generate_permutation_unit(&mut first_values);
        first_values
    }

    fn generate_next_row(&self, local_values: &[F; NUM_COLUMNS]) -> [F; NUM_COLUMNS] {
        let mut next_values = [F::ZERO; NUM_COLUMNS];
        self.generate_next_row_core_registers(local_values, &mut next_values);
        self.generate_permutation_unit(&mut next_values);
        next_values
    }

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        self.eval_core_registers(vars, yield_constr);
        self.eval_permutation_unit(vars, yield_constr);
        todo!()
    }

    fn eval_ext_recursively(
        &self,
        vars: StarkEvaluationTargets<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        self.eval_core_registers_recursively(vars, yield_constr);
        self.eval_permutation_unit_recursively(vars, yield_constr);
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {
        // todo
    }
}
