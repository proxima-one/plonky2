use plonky2::field::types::Field;

use super::layout::FibonacciRow;

pub fn generate_trace<F: Field>(k: usize) -> Vec<FibonacciRow<F>> {
	assert!(k > 1);

	let mut trace = Vec::new();
	let mut curr_row = FibonacciRow {
		n: F::ONE,
		f_n: F::ONE,
		f_n_minus_1: F::ZERO,
		n_minus_k_inv: (F::ONE - F::from_canonical_usize(k)).inverse(),
		is_done: F::ZERO
	};

	trace.push(curr_row);

	for n in 2..k {
		let next_row = FibonacciRow {
			n: F::from_canonical_usize(n),
			f_n: curr_row.f_n + curr_row.f_n_minus_1,
			f_n_minus_1: curr_row.f_n,
			n_minus_k_inv: (F::from_canonical_usize(n) - F::from_canonical_usize(k)).inverse(),
			is_done: F::ZERO
		};

		curr_row = next_row;
		trace.push(next_row);
	}

	// kth row
	assert!(trace.len() == k - 1);
	let next_row = FibonacciRow {
		n: F::from_canonical_usize(k),
		f_n: curr_row.f_n + curr_row.f_n_minus_1,
		f_n_minus_1: curr_row.f_n,
		n_minus_k_inv: F::ZERO,
		is_done: F::ONE
	};

	curr_row = next_row;
	trace.push(next_row);

	// pad to the next power of 2
	let next_power_of_two = usize::next_power_of_two(k);
	while trace.len() < next_power_of_two {
		let n = trace.len() + 1;
		let next_row = FibonacciRow {
			n: F::from_canonical_usize(n),
			f_n: curr_row.f_n + curr_row.f_n_minus_1,
			f_n_minus_1: curr_row.f_n,
			n_minus_k_inv: (F::from_canonical_usize(n) - F::from_canonical_usize(k)).inverse(),
			is_done: F::ZERO	
		};

		curr_row = next_row;
		trace.push(next_row);
	}

	trace
}
