use plonky2::field::extension_field::{Extendable, FieldExtension};
use plonky2::field::packed_field::PackedField;
use plonky2::hash::hash_types::RichField;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::vars::StarkEvaluationTargets;
use starky::vars::StarkEvaluationVars;

use crate::column_layout::NUM_COLUMNS;
use crate::public_input_layout::NUM_PUBLIC_INPUTS;
use crate::system_zero::SystemZero;

impl<F: RichField + Extendable<D>, const D: usize> SystemZero<F, D> {
    pub(crate) fn generate_permutation_unit(&self, values: &mut [F; NUM_COLUMNS]) {
        todo!()
    }

    #[inline]
    pub(crate) fn eval_permutation_unit<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        todo!()
    }

    pub(crate) fn eval_permutation_unit_recursively(
        &self,
        vars: StarkEvaluationTargets<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }
}
