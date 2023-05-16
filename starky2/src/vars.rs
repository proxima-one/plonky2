use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::iop::ext_target::ExtensionTarget;

#[derive(Debug, Copy, Clone)]
pub struct StarkEvaluationVars<'a, F, P>
where
    F: Field,
    P: PackedField<Scalar = F>,
{
    pub local_values: &'a [P],
    pub next_values: &'a [P],
    pub public_inputs: &'a [P::Scalar],
}

#[derive(Debug, Copy, Clone)]
pub struct StarkEvaluationTargets<
    'a,
    const D: usize
> {
    pub local_values: &'a [ExtensionTarget<D>],
    pub next_values: &'a [ExtensionTarget<D>],
    pub public_inputs: &'a [ExtensionTarget<D>],
}
