
use std::borrow::Borrow;

use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

mod layout;
mod generation;

use layout::FibonacciRow;

pub struct FibonacciStark<F: RichField + Extendable<D>, const D: usize> {
	_phantom: std::marker::PhantomData<F>
}

impl<F: RichField + Extendable<D>, const D: usize> FibonacciStark<F, D> {
	pub fn new() -> Self {
		Self {
			_phantom: std::marker::PhantomData
		}
	}
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D>
for FibonacciStark<F, D>
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
		let curr_row: &FibonacciRow<P> = vars.local_values.borrow();
		let next_row: &FibonacciRow<P> = vars.next_values.borrow();
		let k = vars.public_inputs[0];

		// different constraint methods on `yield_constr` (didn't have time to discuss during call):
		// - `constraint`: enforce a state transition constraint, with "wraparound"
		//    in other words, when using this method, there is an additional "transition" from the last row to the first row.
		//    use this method when you want wraparound or you whant check a condition on every single row individually (polynomial only includes `curr_row`)
		//    
		// - `constraint_transition`: enforce a state transition constraint without "wraparound" 
		//    use this method when your constraint says something about a transition (polynomial includes both `next_row` and `curr_row`)
		//
		// - `constraint_first_row`: enforce a state transition constraint, but only on the first row of the trace.
		//    use this method to constrain initial state
		//
		// - `constraint_last_row`: enfore a state transition constraint, but only on the last row of the trace (the "wraparound" step, from the last to the first row)
		//    usually you don't want to use this because the trace must be padded to a power of two length
		//    but it can be something useful

		// next_row.n - curr_row.n - 1 == 0
		let constraint = next_row.n - curr_row.n - FE::ONE;
		yield_constr.constraint_transition(constraint);

		// next_row.f_n - (curr_row.f_n + curr_row.f_n-1) == 0
		let constraint = next_row.f_n - (curr_row.f_n + curr_row.f_n_minus_1);
		yield_constr.constraint_transition(constraint);

		// next_row.f_n-1 - curr_row.f_n == 0
		let constraint = next_row.f_n_minus_1 - curr_row.f_n;
		yield_constr.constraint_transition(constraint);

		// curr_row.is_done * (1 - curr_row.is_done) == 0
		let constraint = curr_row.is_done * (P::ONES - curr_row.is_done);
		yield_constr.constraint(constraint);

		// (1 - curr_row.is_done) * ((curr_row.n - k) * (curr_row.n_minus_k_inv) - 1) + curr_row.is_done * (curr_row.n - k) == 0
		let constraint = (P::ONES - curr_row.is_done) * ((curr_row.n - k) * curr_row.n_minus_k_inv - FE::ONE)
			+ curr_row.is_done * (curr_row.n - k);
		yield_constr.constraint(constraint);

		// start conditions
		// f_n = 1
		yield_constr.constraint_first_row(
			curr_row.f_n - FE::ONE
		);

		// f_n-1 = 0
		yield_constr.constraint_first_row(
			curr_row.f_n_minus_1
		);

		// n = 1
		yield_constr.constraint_first_row(
			curr_row.n - FE::ONE
		);

		// we enforce above that prover puts n_minus_k_inv = inv(-k) at the start		
	}

	fn constraint_degree(&self) -> usize {
		3
	}

	fn eval_ext_circuit(
			&self,
			builder: &mut CircuitBuilder<F, D>,
			vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
			yield_constr: &mut RecursiveConstraintConsumer<F, D>,
		) {
		todo!()
	}
}

#[cfg(test)]
pub mod tests {
    use anyhow::Result;
    use env_logger::{Env, try_init_from_env, DEFAULT_FILTER_ENV};
    use log::Level;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
	use crate::util::trace_rows_to_poly_values;

    use super::*;
	use generation::generate_trace;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::verifier::verify_stark_proof_no_ctl;
	use plonky2_field::types::Field;

	#[test]
	fn test_fibonacci_stark() -> Result<()> {
		const D: usize = 2;
		type C = PoseidonGoldilocksConfig;
		type F = <C as GenericConfig<D>>::F;
		type S = FibonacciStark<F, D>;

		// instantiate stark
		let stark = S::new();
		let config = StarkConfig::standard_fast_config();
		init_logger();

		// generate trace as Vec<Row>
		let trace = generate_trace::<F>(5);

		// convert to Vec<[F; 5]> and then to `Vec<PolynomialValues>>`
		let mut trace_arrs: Vec<[F; 5]> = trace.into_iter().map(|row| row.into()).collect::<Vec<_>>();

		// modify the trace with some random value
		trace_arrs[4][0] = F::rand();

		println!("trace: {:#?}", trace_arrs);

		let trace_polys = trace_rows_to_poly_values(trace_arrs);

		let mut timing = TimingTree::new("prove", Level::Debug);
		let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace_polys, [F::from_canonical_u64(5)], &mut timing)?;
		timing.print();

		verify_stark_proof_no_ctl(&stark, &proof, &config)?;

		Ok(())
	}

	fn init_logger() {
	    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
	}
}
