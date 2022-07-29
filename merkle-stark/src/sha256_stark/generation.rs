#![allow(clippy::many_single_char_names)]

use super::constants::{HASH_IV, ROUND_CONSTANTS};
use crate::sha256_stark::layout::*;
use crate::util::trace_rows_to_poly_values;
use plonky2::field::{packed::PackedField, types::Field, polynomial::PolynomialValues};
use core::convert::TryInto;
use arrayref::{array_ref, array_mut_ref};

const BLOCK_LEN: usize = 16;

fn is_power_of_two(n: u64) -> bool {
    n & (n - 1) == 0 
}

#[repr(transparent)]
pub struct Sha2Trace<F: Field>(
    Vec<[F; NUM_COLS]>,
);

impl<F: Field> Sha2Trace<F> {
	pub fn new(max_rows: usize) -> Sha2Trace<F> {
        assert!(is_power_of_two(max_rows as u64), "max_rows must be a power of two");
		Sha2Trace(
            vec![[F::ZERO; NUM_COLS]; max_rows]
        )
	}
}

pub struct Sha2TraceGenerator<F: Field>{
	trace: Sha2Trace<F>,
	hash_idx: usize,
    left_input: [u32; 8],
    right_input: [u32; 8],
	step: usize
}

impl<F: Field> Sha2TraceGenerator<F> {
	pub fn new(max_rows: usize) -> Sha2TraceGenerator<F> {
		Sha2TraceGenerator {
			trace: Sha2Trace::new(max_rows),
			hash_idx: 0,
            left_input: [0; 8],
            right_input: [0; 8],
			step: 0
		}
	}

    fn max_rows(&self) -> usize {
        self.trace.0.len()
    }

    fn curr_row_idx(&self) -> usize {
        self.hash_idx * NUM_STEPS_PER_HASH + self.step
    }

    fn get_next_window(&mut self) -> (&mut [[F; NUM_COLS]; 2], usize, usize) {
        let idx = self.curr_row_idx();
        assert!(idx < self.max_rows(), "get_next_window exceeded MAX_ROWS");

        let hash_idx = self.hash_idx;
        let step = self.step;
        self.step += 1;

        (array_mut_ref![self.trace.0, idx, 2], hash_idx, step)
    }

    // returns wi
    fn gen_msg_schedule(next_row: &mut [F; NUM_COLS], w15: u32, w2: u32, w16: u32, w7: u32) -> u32 {
        let mut xor_tmp_0 = rotr(w15, 7) ^ rotr(w15, 18);
        let mut s0 = xor_tmp_0  ^ (w15 >> 3);

        let mut xor_tmp_1 = rotr(w2, 17) ^ rotr(w2, 19);
        let mut s1 = xor_tmp_1 ^ (w2 >> 10);

        let mut wi = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        let res = wi;
        let wi_u64 = w16 as u64 + s0 as u64 + w7 as u64 + s1 as u64;
        let quotient = wi_u64 / (1 << 32);
        for bit in 0..32 {
            next_row[xor_tmp_i_bit(0, bit)] = F::from_canonical_u32(xor_tmp_0 & 1);
            next_row[xor_tmp_i_bit(1, bit)] = F::from_canonical_u32(xor_tmp_1 & 1);

            next_row[little_s0_bit(bit)] = F::from_canonical_u32(s0 & 1);
            next_row[little_s1_bit(bit)] = F::from_canonical_u32(s1 & 1);

            next_row[wi_bit(15, bit)] = F::from_canonical_u32(wi & 1);

            xor_tmp_0 >>= 1;
            xor_tmp_1 >>= 1;
            s0 >>= 1;
            s1 >>= 1;
            wi >>= 1;
        }
        
        next_row[WI_FIELD] = F::from_canonical_u64(wi_u64);
        next_row[WI_QUOTIENT] = F::from_canonical_u64(quotient);

        res
    }

    // returns new (abcd, efgh)
    fn gen_round_fn(curr_row: &mut [F; NUM_COLS], next_row: &mut [F; NUM_COLS], wi: u32, ki: u32, abcd: [u32; 4], efgh: [u32; 4]) -> ([u32; 4], [u32; 4]) {
        let mut xor_tmp_2 = rotr(efgh[0], 6) ^ rotr(efgh[0], 11);
        let mut s1 =  xor_tmp_2 ^ rotr(efgh[0], 25);
        let mut ch = (efgh[0] & efgh[1]) ^ ((!efgh[0]) & efgh[2]);
        let mut e_and_f = efgh[0] & efgh[1];
        let mut not_e_and_g = (!efgh[0]) & efgh[2];
        let mut xor_tmp_3 = rotr(abcd[0], 2) ^ rotr(abcd[0], 13);
        let mut s0 = xor_tmp_3 ^ rotr(abcd[0], 22);
        let mut xor_tmp_4 = (abcd[0] & abcd[1]) ^ (abcd[0] & abcd[2]);
        let mut maj = xor_tmp_4 ^ (abcd[1] & abcd[2]);
        let mut a_and_b = abcd[0] & abcd[1];
        let mut a_and_c = abcd[0] & abcd[2];
        let mut b_and_c = abcd[1] & abcd[2];

        let temp1_u32 = efgh[3].wrapping_add(s1).wrapping_add(ch).wrapping_add(ki).wrapping_add(wi);
        let temp2_u32 = s0.wrapping_add(maj);
        let temp1_u64 = efgh[3] as u64 + s1 as u64 + ch as u64 + ki as u64 + wi as u64;
        let temp2_u64 = s0 as u64 + maj as u64;

        for bit in 0..32 {
            curr_row[xor_tmp_i_bit(2, bit)] = F::from_canonical_u32(xor_tmp_2 & 1);
            curr_row[xor_tmp_i_bit(3, bit)] = F::from_canonical_u32(xor_tmp_3 & 1);
            curr_row[xor_tmp_i_bit(4, bit)] = F::from_canonical_u32(xor_tmp_4 & 1);

            curr_row[big_s1_bit(bit)] = F::from_canonical_u32(s1 & 1);
            curr_row[big_s0_bit(bit)] = F::from_canonical_u32(s0 & 1);
            curr_row[ch_bit(bit)] = F::from_canonical_u32(ch & 1);
            curr_row[maj_bit(bit)] = F::from_canonical_u32(maj & 1);

            curr_row[e_and_f_bit(bit)] = F::from_canonical_u32(e_and_f & 1);
            curr_row[not_e_and_g_bit(bit)] = F::from_canonical_u32(not_e_and_g & 1);
            curr_row[a_and_b_bit(bit)] = F::from_canonical_u32(a_and_b & 1);
            curr_row[a_and_c_bit(bit)] = F::from_canonical_u32(a_and_c & 1);
            curr_row[b_and_c_bit(bit)] = F::from_canonical_u32(b_and_c & 1);

            xor_tmp_2 >>= 1;
            xor_tmp_3 >>= 1;
            xor_tmp_4 >>= 1;
            s1 >>= 1;
            s0 >>= 1;
            ch >>= 1;
            maj >>= 1;
            e_and_f >>= 1;
            not_e_and_g >>= 1;
            a_and_b >>= 1;
            a_and_c >>= 1;
            b_and_c >>= 1;
        }
        
        let (mut abcd, mut efgh) = swap(abcd, efgh);
    
        let a_next_u64 = temp1_u64 + temp2_u64;
        let a_next_quotient = a_next_u64 / (1 << 32);
        let e_next_u64 = efgh[0] as u64 + temp1_u64;
        let e_next_quotient = e_next_u64 / (1 << 32);

        abcd[0] = temp1_u32.wrapping_add(temp2_u32);
        efgh[0] = efgh[0].wrapping_add(temp1_u32);

        let res = (abcd.clone(), efgh.clone());

        curr_row[A_NEXT_FIELD] = F::from_canonical_u64(a_next_u64);
        curr_row[A_NEXT_QUOTIENT] = F::from_canonical_u64(a_next_quotient);
        curr_row[E_NEXT_FIELD] = F::from_canonical_u64(e_next_u64);
        curr_row[E_NEXT_QUOTIENT] = F::from_canonical_u64(e_next_quotient);
        
        for bit in 0..32 {
            next_row[a_bit(bit)] = F::from_canonical_u32(abcd[0] & 1);
            next_row[b_bit(bit)] = F::from_canonical_u32(abcd[1] & 1);
            next_row[c_bit(bit)] = F::from_canonical_u32(abcd[2] & 1);
            next_row[d_bit(bit)] = F::from_canonical_u32(abcd[3] & 1);
            next_row[e_bit(bit)] = F::from_canonical_u32(efgh[0] & 1);
            next_row[f_bit(bit)] = F::from_canonical_u32(efgh[1] & 1);
            next_row[g_bit(bit)] = F::from_canonical_u32(efgh[2] & 1);
            next_row[h_bit(bit)] = F::from_canonical_u32(efgh[3] & 1);

            abcd[0] >>= 1;
            abcd[1] >>= 1;
            abcd[2] >>= 1;
            abcd[3] >>= 1;
            efgh[0] >>= 1;
            efgh[1] >>= 1;
            efgh[2] >>= 1;
            efgh[3] >>= 1;
        }

        res
    }


    // fills in stuff the other fns don't at each row
    fn gen_misc(curr_row: &mut [F; NUM_COLS], next_row: &mut [F; NUM_COLS], step: usize, hash_idx: usize) {
        curr_row[HASH_IDX] = F::from_canonical_u64(hash_idx as u64);

        for i in 0..NUM_STEPS_PER_HASH {
            curr_row[step_bit(i)] = F::ZERO;
        }

        curr_row[step_bit(step)] = F::ONE;

        match step {
            // phase 0
            0..8 => {
                curr_row[phase_bit(0)] = F::ONE;
                curr_row[phase_bit(1)] = F::ZERO;
                curr_row[phase_bit(2)] = F::ZERO;
                curr_row[phase_bit(3)] = F::ZERO;
                curr_row[CHUNK_IDX] = F::from_canonical_u64(step as u64);

                for i in 0..8 {
                    next_row[h_i(i)] = curr_row[h_i(i)];
                }
            },
            // phase 1
            8..16 => {
                curr_row[phase_bit(0)] = F::ZERO;
                curr_row[phase_bit(1)] = F::ONE;
                curr_row[phase_bit(2)] = F::ZERO;
                curr_row[phase_bit(3)] = F::ZERO;
                curr_row[CHUNK_IDX] = F::from_canonical_u64(step as u64 - 8);

                for i in 0..8 {
                    next_row[h_i(i)] = curr_row[h_i(i)];
                }
            }
            // phase 2
            16..64 => {
                curr_row[phase_bit(0)] = F::ZERO;
                curr_row[phase_bit(1)] = F::ZERO;
                curr_row[phase_bit(2)] = F::ONE;
                curr_row[phase_bit(3)] = F::ZERO;
            },
            // phase 3
            64..72 => {
                curr_row[phase_bit(0)] = F::ZERO;
                curr_row[phase_bit(1)] = F::ZERO;
                curr_row[phase_bit(2)] = F::ZERO;
                curr_row[phase_bit(3)] = F::ONE;

                for i in 1..16 {
                    for bit in 0..32 {
                        next_row[wi_bit(i, bit)] = curr_row[wi_bit(i, bit)];
                    }
                }
            },
            _ => unreachable!()
        }
    }

    fn gen_shift_wis(curr_row: &mut [F; NUM_COLS], next_row: &mut [F; NUM_COLS]) {
        for i in 0..15 {
            for bit in 0..32 {
                next_row[wi_bit(i, bit)] = curr_row[wi_bit(i + 1, bit)];
            }
        }
    }

    fn gen_keep_his_same(curr_row: &mut [F; NUM_COLS], next_row: &mut [F; NUM_COLS]) {
        for i in 0..8 {
            next_row[h_i(i)] = curr_row[h_i(i)]
        }
    }

    // returns wis, abcd, efgh, last wi shifted out of scope
	fn gen_phase_0_and_1(&mut self, his: [u32; 8]) -> ([u32; 16], [u32; 4], [u32; 4]) {
        let left_input = self.left_input; 
        let right_input = self.right_input;
        let mut wis = [0; 16];
        let mut abcd = *array_ref![his, 0, 4];
        let mut efgh = *array_ref![his, 4, 4];

        // left inputs
        for i in 0..16 {
            let ([curr_row, next_row], hash_idx, step) = self.get_next_window();

            if i == 0 {
                let mut abcd = abcd;
                let mut efgh = efgh;
                for bit in 0..32 {
                    curr_row[a_bit(bit)] = F::from_canonical_u32(abcd[0] & 1);
                    curr_row[b_bit(bit)] = F::from_canonical_u32(abcd[1] & 1);
                    curr_row[c_bit(bit)] = F::from_canonical_u32(abcd[2] & 1);
                    curr_row[d_bit(bit)] = F::from_canonical_u32(abcd[3] & 1);
                    curr_row[e_bit(bit)] = F::from_canonical_u32(efgh[0] & 1);
                    curr_row[f_bit(bit)] = F::from_canonical_u32(efgh[1] & 1);
                    curr_row[g_bit(bit)] = F::from_canonical_u32(efgh[2] & 1);
                    curr_row[h_bit(bit)] = F::from_canonical_u32(efgh[3] & 1);
    
                    abcd[0] >>= 1;
                    abcd[1] >>= 1;
                    abcd[2] >>= 1;
                    abcd[3] >>= 1;
                    efgh[0] >>= 1;
                    efgh[1] >>= 1;
                    efgh[2] >>= 1;
                    efgh[3] >>= 1;
                }

                // set his to IV
                for j in 0..8 {
                    curr_row[h_i(j)] = F::from_canonical_u32(HASH_IV[j]);
                }
            } 

            Self::gen_misc(curr_row, next_row, step, hash_idx);

            // load input cols
            let mut wi = if i < 8 {
                let wi = left_input[i];
                curr_row[LEFT_INPUT_COL] = F::from_canonical_u64(hash_idx as u64) * F::from_canonical_u64(1 << 35) + F::from_canonical_u64(i as u64) * F::from_canonical_u64(1 << 32) + F::from_canonical_u32(wi);
                curr_row[RIGHT_INPUT_COL] = F::ZERO;
                wi
            } else {
                let wi = right_input[i - 8];
                curr_row[RIGHT_INPUT_COL] = F::from_canonical_u64(hash_idx as u64) * F::from_canonical_u64(1 << 35) + F::from_canonical_u64(i as u64 - 8) * F::from_canonical_u64(1 << 32) + F::from_canonical_u32(wi);
                curr_row[LEFT_INPUT_COL] = F::ZERO;
                wi
            };

            wis[15] = wi;


            // load wi
			for bit in 0..32 {
				curr_row[wi_bit(15, bit)] = F::from_canonical_u32(wi & 1);
				wi >>= 1;
			}

            Self::gen_keep_his_same(curr_row, next_row);

            let ki = ROUND_CONSTANTS[i];
            curr_row[KI] = F::from_canonical_u32(ki);
            (abcd, efgh) = Self::gen_round_fn(curr_row, next_row, wis[15], ki, abcd, efgh);

            if i == 15 {
                let w16 = wis[0];
                wis = shift_wis(wis);
                let wi = Self::gen_msg_schedule(next_row, wis[0], wis[13], w16, wis[8]);
                wis[15] = wi
            } else {
                wis = shift_wis(wis);
            }

            Self::gen_shift_wis(curr_row, next_row);
		}

        (wis, abcd, efgh)
	}

    // returns wis, abcd, efgh, his
    fn gen_phase_2(&mut self, mut wis: [u32; 16], mut abcd: [u32; 4], mut efgh: [u32; 4], mut his: [u32; 8]) -> ([u32; 16], [u32; 4], [u32; 4], [u32; 8]) {
        for i in 0..48 {
            let ([curr_row, next_row], hash_idx, step) = self.get_next_window();
            Self::gen_misc(curr_row, next_row, step, hash_idx);
            

            let ki = ROUND_CONSTANTS[i + 16];
            curr_row[KI] = F::from_canonical_u32(ki);
            (abcd, efgh) = Self::gen_round_fn(curr_row, next_row, wis[15], ki, abcd, efgh);

            let w16 = wis[0];
            wis = shift_wis(wis);


            if i != 47 {
                Self::gen_keep_his_same(curr_row, next_row);
                let mut wi = Self::gen_msg_schedule(next_row, wis[0], wis[13], w16, wis[8]);
                wis[15] = wi;
            }

            // update his during last row
            if i == 47 {
                for j in 0..4 {
                    let hj_next_u64 = his[j] as u64 + abcd[j] as u64;
                    let hj_next_quotient = hj_next_u64 / (1 << 32);
                    his[j] = his[j].wrapping_add(abcd[j]);
                    
                    curr_row[h_i_next_field(j)] = F::from_canonical_u64(hj_next_u64);
                    curr_row[h_i_next_quotient(j)] = F::from_canonical_u64(hj_next_quotient);
                    next_row[h_i(j)] = F::from_canonical_u32(his[j]); 
                }

                for j in 0..4 {
                    let hj_next_u64 = his[j + 4] as u64 + efgh[j] as u64;
                    let hj_next_quotient = hj_next_u64 / (1 << 32);
                    his[j + 4] = his[j + 4].wrapping_add(efgh[j]);
                    
                    curr_row[h_i_next_field(j + 4)] = F::from_canonical_u64(hj_next_u64);
                    curr_row[h_i_next_quotient(j + 4)] = F::from_canonical_u64(hj_next_quotient);
                    next_row[h_i(j + 4)] = F::from_canonical_u32(his[j + 4]); 
                }
            }

            Self::gen_shift_wis(curr_row, next_row);
        };

        (wis, abcd, efgh, his)
    }

    fn gen_phase_3(&mut self, mut his: [u32; 8]) {
        for i in 0..7 {
            let ([curr_row, next_row], hash_idx, step) = self.get_next_window();
            Self::gen_misc(curr_row, next_row, step, hash_idx);

            curr_row[CHUNK_IDX] = F::from_canonical_u64(i as u64);
            curr_row[OUTPUT_COL] = F::from_canonical_u32(his[0])
                + F::from_canonical_u64(hash_idx as u64) * F::from_canonical_u64(1 << 35)
                + F::from_canonical_u64(i as u64) * F::from_canonical_u64(1 << 32);
            
            for i in 0..7 {
                next_row[h_i(i)] = F::from_canonical_u32(his[i + 1]);
            }

            his = shift_his(his);

            Self::gen_shift_wis(curr_row, next_row);
        }


        let ([curr_row, next_row], hash_idx, step) = self.get_next_window();
        Self::gen_misc(curr_row, next_row, step, hash_idx);
        curr_row[CHUNK_IDX] = F::from_canonical_u64(7 as u64);
        curr_row[OUTPUT_COL] = F::from_canonical_u32(his[0]) + F::from_canonical_u64(hash_idx as u64) * F::from_canonical_u64(1 << 25) + F::from_canonical_u64(7 as u64) * F::from_canonical_u64(1 << 32);

        Self::gen_shift_wis(curr_row, next_row)
    }



    pub fn gen_hash(&mut self, left_input: [u32; 8], right_input: [u32; 8]) -> [u32; 8] {
        self.left_input = left_input;
        self.right_input = right_input;

        let his = HASH_IV;
        let (wis, abcd, efgh) = self.gen_phase_0_and_1(his);

        let (wis, abcd, efgh, his) = self.gen_phase_2(wis, abcd, efgh, his);
        self.gen_phase_3(his);

        self.hash_idx += 1;
        his
    }

    pub fn into_polynomial_values(self) -> Vec<PolynomialValues<F>> {
        trace_rows_to_poly_values(self.trace.0) 
    }
}

pub fn block_to_u32_array(block: [u8; 64]) -> [u32; BLOCK_LEN] {
    let mut block_u32 = [0; BLOCK_LEN];
    for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
        *o = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    block_u32
}

#[inline(always)]
fn shift_wis(mut wis: [u32; 16]) -> [u32; 16] {
    for i in 0..15 {
        wis[i] = wis[i + 1];
    }
    wis[15] = 0;
    wis
}

#[inline(always)]
fn shift_his(mut his: [u32; 8]) -> [u32; 8] {
    for i in 0..7 {
        his[i] = his[i + 1];
    }
    his[7] = 0;
    his
}

#[inline(always)]
fn swap(abcd: [u32; 4], efgh: [u32; 4]) -> ([u32; 4], [u32; 4]) {
    ([0, abcd[0], abcd[1], abcd[2]], [abcd[3], efgh[0], efgh[1], efgh[2]])
}

#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}


#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::{GenericArray, typenum::U64};
    use plonky2_field::goldilocks_field::GoldilocksField;
    use core::convert::TryInto;
    use sha2::compress256;

    type F = GoldilocksField;

    #[test]
    fn test_hash_of_zero() {
        let block = [0u8; 64];
        let block_arr = GenericArray::<u8, U64>::from(block);
        let mut state = HASH_IV;
        compress256(&mut state, &[block_arr]);

        let left_input = [0u32; 8];
        let right_input = [0u32; 8];
        let mut generator = Sha2TraceGenerator::<F>::new(128);

        let his = generator.gen_hash(left_input, right_input);

        assert_eq!(his, state);
    }


    #[test]
    fn test_hash_of_something() {
        let mut block = [0u8; 64];
        for i in 0..64 {
            block[i] = i as u8;
        }

        let block_arr = GenericArray::<u8, U64>::from(block);
        let mut state = HASH_IV;
        compress256(&mut state, &[block_arr]);

        let block = block_to_u32_array(block);
        let left_input = *array_ref![block, 0, 8];
        let right_input = *array_ref![block, 8, 8];
        let mut generator = Sha2TraceGenerator::<F>::new(128);

        let his = generator.gen_hash(left_input, right_input);
        assert_eq!(his, state);
    }
}