use plonky2::field::types::PrimeField64;

pub fn u32_byte_decomp_field_le<F: PrimeField64>(val: F) -> [F; 4] {
    let mut bytes = [F::ZERO; 4];
    let mut val = val.to_canonical_u64() as u32;
    for b in bytes.iter_mut() {
        *b = F::from_canonical_u32(val & 0xFF);
        val >>= 8;
    }
    bytes
}

pub fn u32_byte_recomp_field_le<F: PrimeField64>(bytes: [F; 4]) -> F {
    (0..4)
        .map(|i| bytes[i] * F::from_canonical_u32(1 << (i * 8)))
        .sum::<F>()
}
