use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::starky2lib::keccak_f::keccak_stark::NUM_ROUNDS;
use crate::starky2lib::keccak_f::layout::reg_step;
use crate::starky2lib::keccak_f::layout::NUM_COLUMNS;
use crate::starky2lib::keccak_f::layout::NUM_PUBLIC_INPUTS;
use crate::starky2lib::keccak_f::layout::{REG_INPUT_FILTER, REG_OUTPUT_FILTER};
use crate::vars::StarkEvaluationTargets;
use crate::vars::StarkEvaluationVars;

pub(crate) fn eval_round_flags<F: Field, P: PackedField<Scalar = F>>(
    vars: StarkEvaluationVars<F, P, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    // Initially, the first step flag should be 1 while the others should be 0.
    yield_constr.constraint_first_row(vars.local_values[reg_step(0)] - F::ONE);
    for i in 1..NUM_ROUNDS {
        yield_constr.constraint_first_row(vars.local_values[reg_step(i)]);
    }

    for i in 0..NUM_ROUNDS {
        let current_round_flag = vars.local_values[reg_step(i)];
        let next_round_flag = vars.next_values[reg_step((i + 1) % NUM_ROUNDS)];
        yield_constr.constraint_transition(next_round_flag - current_round_flag);
    }

    // check i/o filters are binary
    yield_constr.constraint(vars.local_values[REG_INPUT_FILTER] * (P::ONES - vars.local_values[REG_INPUT_FILTER]));
    yield_constr.constraint(vars.local_values[REG_OUTPUT_FILTER] * (P::ONES - vars.local_values[REG_OUTPUT_FILTER]));

    // check output filter is only set when it's the last round and input filter is only set when it's the first round
    yield_constr.constraint(vars.local_values[REG_INPUT_FILTER] * (P::ONES - vars.local_values[reg_step(0)]));
    yield_constr.constraint(vars.local_values[REG_OUTPUT_FILTER] * (P::ONES - vars.local_values[reg_step(NUM_ROUNDS - 1)]));
}

pub(crate) fn eval_round_flags_recursively<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vars: StarkEvaluationTargets<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();

    // Initially, the first step flag should be 1 while the others should be 0.
    let step_0_minus_1 = builder.sub_extension(vars.local_values[reg_step(0)], one);
    yield_constr.constraint_first_row(builder, step_0_minus_1);
    for i in 1..NUM_ROUNDS {
        yield_constr.constraint_first_row(builder, vars.local_values[reg_step(i)]);
    }

    for i in 0..NUM_ROUNDS {
        let current_round_flag = vars.local_values[reg_step(i)];
        let next_round_flag = vars.next_values[reg_step((i + 1) % NUM_ROUNDS)];
        let diff = builder.sub_extension(next_round_flag, current_round_flag);
        yield_constr.constraint_transition(builder, diff);
    }

    // check i/o filters are binary
    let mut c = builder.sub_extension(one, vars.local_values[REG_INPUT_FILTER]);
    c = builder.mul_extension(vars.local_values[REG_INPUT_FILTER], c);
    yield_constr.constraint(builder, c);

    let mut c = builder.sub_extension(one, vars.local_values[REG_OUTPUT_FILTER]);
    c = builder.mul_extension(vars.local_values[REG_OUTPUT_FILTER], c);
    yield_constr.constraint(builder, c);

    // check output filter is only set when it's the last round and input filter is only set when it's the first round
    let mut c = builder.sub_extension(one, vars.local_values[reg_step(0)]);
    c = builder.mul_extension(vars.local_values[REG_INPUT_FILTER], c);
    yield_constr.constraint(builder, c);

    let mut c = builder.sub_extension(one, vars.local_values[reg_step(NUM_ROUNDS - 1)]);
    c = builder.mul_extension(vars.local_values[REG_OUTPUT_FILTER], c);
    yield_constr.constraint(builder, c);
}
