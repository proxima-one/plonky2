use std::mem::{size_of, transmute_copy, ManuallyDrop};

use itertools::Itertools;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::util::transpose;

pub fn is_power_of_two(n: u64) -> bool {
    n & (n - 1) == 0
}

/// A helper function to transpose a row-wise trace and put it in the format that `prove` expects.
pub fn trace_rows_to_poly_values<F: Field, const COLUMNS: usize>(
    trace_rows: Vec<[F; COLUMNS]>,
) -> Vec<PolynomialValues<F>> {
    let trace_row_vecs = trace_rows.into_iter().map(|row| row.to_vec()).collect_vec();
    let trace_col_vecs: Vec<Vec<F>> = transpose(&trace_row_vecs);
    trace_col_vecs
        .into_iter()
        .map(|column| PolynomialValues::new(column))
        .collect()
}

pub fn to_u32_array_be<const N: usize>(block: [u8; N * 4]) -> [u32; N] {
    let mut block_u32 = [0; N];
    for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
        *o = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    block_u32
}

pub fn to_u32_array_le<const N: usize>(block: [u8; N * 4]) -> [u32; N] {
    let mut block_u32 = [0; N];
    for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    block_u32
}

pub fn to_u32_vec_le(data: &[u8]) -> Vec<u32> {
    let mut u32s = vec![0; (data.len() + 3) / 4];
    for (o, chunk) in u32s.iter_mut().zip(data.chunks(4)) {
        if chunk.len() != 4 {
            let mut block = [0; 4];
            (&mut block[..chunk.len()]).copy_from_slice(chunk);
            *o = u32::from_le_bytes(block);
        } else {
            *o = u32::from_le_bytes(chunk.try_into().unwrap());
        }
    }
    u32s
}

pub fn to_u32_vec_be(data: &[u8]) -> Vec<u32> {
    let mut u32s = vec![0; (data.len() + 3) / 4];
    for (o, chunk) in u32s.iter_mut().zip(data.chunks(4)) {
        if chunk.len() != 4 {
            let mut block = [0; 4];
            (&mut block[..chunk.len()]).copy_from_slice(chunk);
            *o = u32::from_be_bytes(block);
        } else {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }
    }
    u32s
}

pub(crate) unsafe fn transmute_no_compile_time_size_checks<T, U>(value: T) -> U {
    debug_assert_eq!(size_of::<T>(), size_of::<U>());
    // Need ManuallyDrop so that `value` is not dropped by this function.
    let value = ManuallyDrop::new(value);
    // Copy the bit pattern. The original value is no longer safe to use.
    transmute_copy(&value)
}

pub fn bit_decompose_n_le(mut num: usize, n: usize) -> Vec<u8> {
    let mut bits = vec![];
    for _ in 0..n {
        bits.push((num & 1) as u8);
        num >>= 1;
    }
    bits
}
