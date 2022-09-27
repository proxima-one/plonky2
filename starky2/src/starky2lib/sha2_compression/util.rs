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
