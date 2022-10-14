use itertools::{izip, Itertools};
use plonky2::{field::{
	types::Field,
	polynomial::PolynomialValues,
	extension::{Extendable, FieldExtension},
	packed::PackedField,
}, plonk::config::Hasher};
use plonky2::iop::challenger::Challenger;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use crate::{config::StarkConfig, proof::StarkProofWithPublicInputs, stark::Stark, vars::StarkEvaluationVars, constraint_consumer::ConstraintConsumer};

#[derive(Debug, Clone)]
pub struct RoMemoryDescriptor {
	pub addr_col: usize,
	pub value_col: usize,
	pub addr_sorted_col: usize,
	pub value_sorted_col: usize,
}

impl RoMemoryDescriptor {
	pub fn new(addr_col: usize, value_col: usize, addr_sorted_col: usize, value_sorted_col: usize) -> Self {
		Self {
			addr_col,
			value_col,
			addr_sorted_col,
			value_sorted_col,
		}
	}
}

#[derive(Debug, Clone)]
pub struct RoMemoryChallenge<F: Field> {
	zeta: F,
	alpha: F,
}

pub(crate) fn get_ro_memory_challenge<F: RichField, H: Hasher<F>>(challenger: &mut Challenger<F, H>) -> RoMemoryChallenge<F> {
	RoMemoryChallenge {
		zeta: challenger.get_challenge(),
		alpha: challenger.get_challenge(),
	}
}

pub(crate) fn get_n_ro_memory_challenges<F: RichField, H: Hasher<F>>(challenger: &mut Challenger<F, H>, n: usize) -> Vec<RoMemoryChallenge<F>> {
	(0..n).map(|_| get_ro_memory_challenge(challenger)).collect()
}

#[derive(Debug, Clone)]
pub(crate) struct RoMemoryData<F: Field> {
	pub(crate) challenges: Vec<RoMemoryChallenge<F>>,
	pub(crate) cumulative_products: Vec<PolynomialValues<F>>,
	pub(crate) addr_cols: Vec<usize>,
	pub(crate) value_cols: Vec<usize>,
	pub(crate) addr_sorted_cols: Vec<usize>,
	pub(crate) value_sorted_cols: Vec<usize>,
}

pub(crate) fn get_ro_memory_data<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, S: Stark<F, D>, const D: usize>(
	stark: &S,
	config: &StarkConfig,
	trace_poly_values: &[PolynomialValues<F>],
	challenger: &mut Challenger<F, C::Hasher>
) -> RoMemoryData<F> {
	let num_challenges = config.num_challenges;
	let ro_memory_descriptors = stark.ro_memory_descriptors().expect("ro_memory_descriptors() should be Some");
	let mut challenges = Vec::new();
	let mut cumulative_products = Vec::new();
	let mut addr_cols = Vec::new();
	let mut value_cols = Vec::new();
	let mut addr_sorted_cols = Vec::new();
	let mut value_sorted_cols = Vec::new();
	for descriptor in ro_memory_descriptors {
		let new_challenges = get_n_ro_memory_challenges(challenger, num_challenges);

		let RoMemoryDescriptor {
			addr_col,
			value_col,
			addr_sorted_col,
			value_sorted_col,
		} = descriptor;

		let new_products = (0..config.num_challenges)
			.map(|chal_idx| {
				let addr_values = &trace_poly_values[addr_col];
				let value_values = &trace_poly_values[value_col];
				let addr_sorted_values = &trace_poly_values[addr_sorted_col];
				let value_sorted_values = &trace_poly_values[value_sorted_col];
				let zeta = new_challenges[chal_idx].zeta;
				let alpha = new_challenges[chal_idx].alpha;

				izip!(addr_values.values.iter(), value_values.values.iter(), addr_sorted_values.values.iter(), value_sorted_values.values.iter())
					.scan(F::ONE, |p_prev, (&a, &v, &a_prime, &v_prime)| {
						let num = (zeta - (a + alpha * v)) * *p_prev;
						let denom = zeta - (a_prime + alpha * v_prime);
						let p = num * denom.inverse();
						let res = *p_prev;
						*p_prev = p;
						Some(res)
					})
					.collect_vec()
			})
			.map(|values| PolynomialValues::new(values));
		cumulative_products.extend(new_products);
		challenges.extend(new_challenges);

		addr_cols.extend(std::iter::repeat(addr_col).take(num_challenges));
		value_cols.extend(std::iter::repeat(value_col).take(num_challenges));
		addr_sorted_cols.extend(std::iter::repeat(addr_sorted_col).take(num_challenges));
		value_sorted_cols.extend(std::iter::repeat(value_sorted_col).take(num_challenges));
	}
	
	RoMemoryData {
		challenges,
		cumulative_products,
		addr_cols,
		value_cols,
		addr_sorted_cols,
		value_sorted_cols,
	}
}

#[derive(Debug, Clone)]
pub struct RoMemoryCheckVars<F, FE, P, const D2: usize>
where
    F: Field,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
	pub(crate) local_pps: Vec<P>,
	pub(crate) next_pps: Vec<P>,
	pub(crate) challenges: Vec<RoMemoryChallenge<F>>,
	pub(crate) addr_cols: Vec<usize>,
	pub(crate) value_cols: Vec<usize>,
	pub(crate) addr_sorted_cols: Vec<usize>,
	pub(crate) value_sorted_cols: Vec<usize>,
}

pub(crate) fn eval_ro_memory_checks<F, FE, P, C, S, const D: usize, const D2: usize>(
	vars: StarkEvaluationVars<FE, P, { S::COLUMNS }, { S::PUBLIC_INPUTS }>,
	ro_memory_vars: &RoMemoryCheckVars<F, FE, P, D2>,
	yield_constr: &mut ConstraintConsumer<P>,
	num_challenges: usize
) where
    F: RichField + Extendable<D>,
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
	let RoMemoryCheckVars {
		local_pps,
		next_pps,
		challenges,
		addr_cols,
		value_cols,
		addr_sorted_cols,
		value_sorted_cols,
	} = ro_memory_vars;

	let curr_row = vars.local_values;
	let next_row = vars.next_values;

	let mut instances = izip!(challenges.iter(), addr_cols.iter(), value_cols.iter(), addr_sorted_cols.iter(), value_sorted_cols.iter());
	let mut pps = izip!(local_pps.iter(), next_pps.iter());
	for ((&RoMemoryChallenge { alpha, zeta }, &addr_col, &value_col, &addr_sorted_col, &value_sorted_col), (&local_pp, &next_pp)) in instances.zip(pps) {
		// continuity - addresses fall into a continuous range
		yield_constr.constraint_transition(
			(next_row[addr_sorted_col] - curr_row[addr_sorted_col] - P::ONES)
			* (next_row[addr_sorted_col] - curr_row[addr_sorted_col])
		);

		// single-valued - if the value changes from one row to the next, the address must change as well
		yield_constr.constraint_transition(
			(next_row[value_sorted_col] - curr_row[value_sorted_col])
			* (next_row[addr_sorted_col] - curr_row[addr_sorted_col] - P::ONES)
		);

		// permutation
		// cumulative product starts from the right initial value
		let lhs = -(curr_row[addr_sorted_col] - curr_row[value_sorted_col] * FE::from_basefield(alpha)) + FE::from_basefield(zeta);
		let rhs = -(curr_row[addr_col] - curr_row[value_col] * FE::from_basefield(alpha)) + FE::from_basefield(zeta);
		yield_constr.constraint_first_row(
			lhs * local_pp - rhs
		);

		// cumulative product is computed correctly
		let lhs = -(next_row[addr_sorted_col] - next_row[value_sorted_col] * FE::from_basefield(alpha)) + FE::from_basefield(zeta);
		let rhs = -(next_row[addr_col] - next_row[value_col] * FE::from_basefield(alpha)) + FE::from_basefield(zeta);
		yield_constr.constraint_transition(
			lhs * next_pp - rhs * local_pp
		);

		// cumulative product is 1 at the end
		yield_constr.constraint_last_row(P::ONES - local_pp)
	}
}
