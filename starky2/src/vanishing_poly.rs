use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;

use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::cross_table_lookup::{eval_cross_table_lookup_checks, CtlCheckVars};
use crate::permutation::{eval_permutation_checks, PermutationCheckVars};
use crate::ro_memory::{eval_ro_memory_checks, RoMemoryCheckVars};
use crate::stark::Stark;
use crate::vars::StarkEvaluationVars;

pub(crate) fn eval_vanishing_poly<F, FE, P, C, S, const D: usize, const D2: usize>(
    stark: &S,
    config: &StarkConfig,
    vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
    ro_memory_vars: Option<RoMemoryCheckVars<F, FE, P, D2>>,
    permutation_vars: Option<PermutationCheckVars<F, FE, P, D2>>,
    ctl_vars: Option<&CtlCheckVars<F, FE, P, D2>>,
    consumer: &mut ConstraintConsumer<P>,
) where
    F: RichField + Extendable<D>,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    stark.eval_packed_generic(vars, consumer);

    if let Some(ref ro_memory_vars) = ro_memory_vars {
        eval_ro_memory_checks::<F, FE, P, C, S, D, D2>(vars, ro_memory_vars, consumer);
    }

    if let Some(permutation_data) = permutation_vars {
        eval_permutation_checks::<F, FE, P, C, S, D, D2>(
            stark,
            config,
            vars,
            permutation_data,
            consumer,
        );
    }

    if let Some(ctl_vars) = ctl_vars {
        eval_cross_table_lookup_checks::<F, FE, P, C, S, D, D2>(
            vars,
            ctl_vars,
            consumer,
            config.num_challenges,
        );
    }
}

// pub(crate) fn eval_vanishing_poly_circuit<F, C, S, const D: usize>(
//     builder: &mut CircuitBuilder<F, D>,
//     stark: &S,
//     config: &StarkConfig,
//     vars: StarkEvaluationTargets<D, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
//     permutation_data: Option<PermutationCheckDataTarget<D>>,
//     consumer: &mut RecursiveConstraintConsumer<F, D>,
// ) where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
//     S: Stark<F, D>,
//     [(); S::COLUMNS]:,
//     [(); S::PUBLIC_INPUTS]:,
// {
//     stark.eval_ext_circuit(builder, vars, consumer);
//     if let Some(permutation_data) = permutation_data {
//         eval_permutation_checks_circuit::<F, S, D>(
//             builder,
//             stark,
//             config,
//             vars,
//             permutation_data,
//             consumer,
//         );
//     }
// }
