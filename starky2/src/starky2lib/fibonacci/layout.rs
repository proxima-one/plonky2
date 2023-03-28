#[repr(C)]
#[derive(Eq, PartialEq, Debug)]
pub struct FibonacciRow<T: Copy> {
    pub n: T,
    pub f_n: T,
    pub f_n_minus_1: T,
	pub n_minus_k_inv: T,
	pub is_done: T
}

impl<T: Copy> FibonacciRow<T> {
	fn from_array(arr: &[T]) -> Self {
		debug_assert!(arr.len() == 5);
		FibonacciRow {
			n: arr[0],
			f_n: arr[1],
			f_n_minus_1: arr[2],
			n_minus_k_inv: arr[3],
			is_done: arr[4]
		}
	}

	fn to_array(&self) -> [T; 5] {
		[self.n, self.f_n, self.f_n_minus_1, self.n_minus_k_inv, self.is_done]
	}
}