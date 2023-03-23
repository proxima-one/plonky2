
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

mod layout;
mod generation;

use layout::FibonacciRow;

pub struct FibonacciStark;

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D>
for FibonacciStark
{
	const COLUMNS: usize = 5;
	const PUBLIC_INPUTS: usize = 1;

	fn eval_packed_generic<FE, P, const D2: usize>(
		&self,
		vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
		yield_constr: &mut ConstraintConsumer<P>,
	) where
		FE: FieldExtension<D2, BaseField = F>,
		P: PackedField<Scalar = FE>,
	{
		let curr_row = FibonacciRow::from_arr(vars.local_values);
		let next_row = FibonacciRow::from_arr(vars.next_values);
		let k = vars.public_inputs[0];

		// next_row.n - curr_row.n - 1 == 0
		let constraint = next_row.n - curr_row.n - F::ONE;
		yield_constr.constraint_transition(constraint);

		// next_row.f_n - (curr_row.f_n + curr_row.f_n-1) == 0
		let constraint = next_row.f_n - (curr_row.f_n + curr_row.f_n_minus_1);
		yield_constr.constraintt_transition(constraint);

		// next_row.f_n-1 - curr_row.f_n == 0
		let constraint = next_row.f_n_minus_1 - curr_row.f_n;
		yield_constr.constraint_transition(cointraint);

		// curr_row.is_done * (1 - curr_row.is_done) == 0
		let constraint = curr_row.is_done * (FE::ONE - curr_row.is_done);
		yield_constr.constraint_transition(constraint);

		// (1 - curr_row.is_done) * ((curr_row.n - k) * (curr_row.n_minus_k_inv) - 1) + curr_row.is_done * (curr_row.n - k) == 0
		let constraint = (FE::ONE - curr_row.is_done) * ((curr_row.n - k) * (curr_row.n_minus_k_inv) - FE::ONE)
			+ curr_row.is_done * (curr_row.n - k);
		yield_constr.constraint_transition(constraint);

		// start conditions
		// f_n = 1
		yield_constr.constraint_first_row(
			curr_row.f_n - F::ONE
		);

		// f_n-1 = 0
		yield_constr.constraint_first_row(
			curr_row.f_n_minus_1
		);

		// n = 1
		yield_constr.constraint_first_row(
			curr_row.n - F::ONE
		);

		// we enforce above that prover puts n_minus_k_inv = inv(-k) at the start		
	}
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use rand::Rng;

    use super::*;
	use generation::generate_trace;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::verifier::verify_stark_proof_no_ctl;

	#[test]
	fn test_fibonacci_stark() -> Result<()> {
		const D: usize = 2;
		type C = PoseidonGoldilocksConfig;
		type F = <C as GenericConfig<D>>::F;
		type S = FibonacciStark;

		let stark = FibonacciStark;
		let trace = generate_trace(5);
        let config = StarkConfig::standard_fast_config();

		let mut timing = TimingTree::default();
		let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [F::from_canonical_u64(5)], &mut timing)?;
		verify_stark_proof_no_ctl(&stark, &proof, &config)
	}
}
