use itertools::Itertools;
use plonky2::field::field_types::Field;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::util::transpose;

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

/// A helper function to transpose the format `prove` expexts into a row-wise trace
/// 
/// # Panics
///
/// This function will panic if the rows in the column-wise poly_vals are not of length `COLUMNS`
pub fn poly_values_to_trace_rows<F: Field, const COLUMNS: usize>(
   trace_poly_values: Vec<PolynomialValues<F>>,
) -> Vec<[F; COLUMNS]> {
    let trace_col_vecs: Vec<_> = trace_poly_values
        .into_iter()
        .map(|column| column.values)
        .collect();
    let trace_row_vecs = transpose(&trace_col_vecs);
    trace_row_vecs
        .into_iter()
        .map(|row| {
            let mut row_vec = [F::ZERO; COLUMNS];
            row_vec.copy_from_slice(&row);
            row_vec
        })
        .collect()
}
