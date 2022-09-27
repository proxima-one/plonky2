pub fn to_u32_array_be<const N: usize>(block: [u8; N * 4]) -> [u32; N] {
    let mut block_u32 = [0; N];
    for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
        *o = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    block_u32
}

pub fn compress(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
    use generic_array::{typenum::U64, GenericArray};
    use sha2::compress256;

    use super::constants::HASH_IV;

    let mut block = [0; 64];

    for (i, elem) in left.iter().enumerate() {
        block[i * 4..(i + 1) * 4].copy_from_slice(&elem.to_be_bytes());
    }

    let block_right = &mut block[32..];
    for (i, elem) in right.iter().enumerate() {
        block_right[i * 4..(i + 1) * 4].copy_from_slice(&elem.to_be_bytes());
    }

    let mut state = HASH_IV;
    let block_arr = GenericArray::<u8, U64>::from(block);
    compress256(&mut state, &[block_arr]);
    state
}
