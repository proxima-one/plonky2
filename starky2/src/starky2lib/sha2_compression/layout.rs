pub(crate) const NUM_PIS: usize = 0;
pub(crate) const NUM_COLS: usize = LAST_COL + 1;
pub(crate) const NUM_STEPS_PER_HASH: usize = 65;

pub(crate) const HASH_IDX: usize = 0;
pub(crate) const STEP_BITS_START: usize = HASH_IDX + 1;
pub(crate) fn step_bit(i: usize) -> usize {
    STEP_BITS_START + i
}

pub(crate) const INPUT_START: usize = STEP_BITS_START + NUM_STEPS_PER_HASH;
pub fn input_i(i: usize) -> usize {
    INPUT_START + i
}
pub const INPUT_FILTER: usize = INPUT_START + 16;

pub(crate) const WI_BITS_START: usize = INPUT_FILTER + 1;
pub(crate) fn wi_bit(bit: usize) -> usize {
    WI_BITS_START + bit
}

pub(crate) const WI_MINUS_2_START: usize = WI_BITS_START + 32;
pub(crate) fn wi_minus_2_bit(bit: usize) -> usize {
    WI_MINUS_2_START + bit
}

pub(crate) const WI_MINUS_15_START: usize = WI_MINUS_2_START + 32;
pub(crate) fn wi_minus_15_bit(bit: usize) -> usize {
    WI_MINUS_15_START + bit
}

pub(crate) const NUM_WIS_FIELD: usize = 13;
pub(crate) const WIS_FIELD_START: usize = WI_MINUS_15_START + 32;
pub(crate) fn wi_field(i: usize) -> usize {
    match i {
        15 | 13 | 0 => panic!("invalid index into field-encoded wis"),
        1..=12 => WIS_FIELD_START + i - 1,
        14 => WIS_FIELD_START + i - 2,
        _ => unreachable!(),
    }
}

pub(crate) const XOR_TMP_0_START: usize = WIS_FIELD_START + NUM_WIS_FIELD;
pub(crate) fn xor_tmp_0_bit(bit: usize) -> usize {
    XOR_TMP_0_START + bit
}

pub(crate) const XOR_TMP_1_START: usize = XOR_TMP_0_START + 29;
pub(crate) fn xor_tmp_1_bit(bit: usize) -> usize {
    XOR_TMP_1_START + bit
}

pub(crate) const XOR_TMP_2_START: usize = XOR_TMP_1_START + 22;
pub(crate) fn xor_tmp_2_bit(bit: usize) -> usize {
    XOR_TMP_2_START + bit
}

pub(crate) const XOR_TMP_3_START: usize = XOR_TMP_2_START + 32;
pub(crate) fn xor_tmp_3_bit(bit: usize) -> usize {
    XOR_TMP_3_START + bit
}

pub(crate) const XOR_TMP_4_START: usize = XOR_TMP_3_START + 32;
pub(crate) fn xor_tmp_4_bit(bit: usize) -> usize {
    XOR_TMP_4_START + bit
}

pub(crate) const LITTLE_S0_START: usize = XOR_TMP_4_START + 32;
pub(crate) fn little_s0_bit(bit: usize) -> usize {
    LITTLE_S0_START + bit
}

pub(crate) const LITTLE_S1_START: usize = LITTLE_S0_START + 32;
pub(crate) fn little_s1_bit(bit: usize) -> usize {
    LITTLE_S1_START + bit
}

pub(crate) const KI: usize = LITTLE_S1_START + 32;
pub(crate) const WI_FIELD: usize = KI + 1;
pub(crate) const WI_QUOTIENT: usize = WI_FIELD + 1;

pub(crate) const A_START: usize = WI_QUOTIENT + 1;
pub(crate) fn a_bit(bit: usize) -> usize {
    A_START + bit
}

pub(crate) const B_START: usize = A_START + 32;
pub(crate) fn b_bit(bit: usize) -> usize {
    B_START + bit
}

pub(crate) const C_START: usize = B_START + 32;
pub(crate) fn c_bit(bit: usize) -> usize {
    C_START + bit
}

pub(crate) const D_COL: usize = C_START + 32;

pub(crate) const E_START: usize = D_COL + 1;
pub(crate) fn e_bit(bit: usize) -> usize {
    E_START + bit
}

pub(crate) const F_START: usize = E_START + 32;
pub(crate) fn f_bit(bit: usize) -> usize {
    F_START + bit
}

pub(crate) const G_START: usize = F_START + 32;
pub(crate) fn g_bit(bit: usize) -> usize {
    G_START + bit
}

pub(crate) const H_COL: usize = G_START + 32;

pub(crate) const BIG_S0_START: usize = H_COL + 1;
pub(crate) fn big_s0_bit(bit: usize) -> usize {
    BIG_S0_START + bit
}

pub(crate) const BIG_S1_START: usize = BIG_S0_START + 32;
pub(crate) fn big_s1_bit(bit: usize) -> usize {
    BIG_S1_START + bit
}

pub(crate) const NOT_E_AND_G_START: usize = BIG_S1_START + 32;
pub(crate) fn not_e_and_g_bit(bit: usize) -> usize {
    NOT_E_AND_G_START + bit
}

pub(crate) const E_AND_F_START: usize = NOT_E_AND_G_START + 32;
pub(crate) fn e_and_f_bit(bit: usize) -> usize {
    E_AND_F_START + bit
}

pub(crate) const CH_START: usize = E_AND_F_START + 32;
pub(crate) fn ch_bit(bit: usize) -> usize {
    CH_START + bit
}

pub(crate) const A_AND_B: usize = CH_START + 32;
pub(crate) fn a_and_b_bit(bit: usize) -> usize {
    A_AND_B + bit
}

pub(crate) const A_AND_C: usize = A_AND_B + 32;
pub(crate) fn a_and_c_bit(bit: usize) -> usize {
    A_AND_C + bit
}

pub(crate) const B_AND_C: usize = A_AND_C + 32;
pub(crate) fn b_and_c_bit(bit: usize) -> usize {
    B_AND_C + bit
}

pub(crate) const MAJ_START: usize = B_AND_C + 32;
pub(crate) fn maj_bit(bit: usize) -> usize {
    MAJ_START + bit
}

pub(crate) const BIG_SO_FIELD: usize = MAJ_START + 32;
pub(crate) const BIG_S1_FIELD: usize = BIG_SO_FIELD + 1;
pub(crate) const CH_FIELD: usize = BIG_S1_FIELD + 1;
pub(crate) const MAJ_FIELD: usize = CH_FIELD + 1;

pub(crate) const A_NEXT_FIELD: usize = MAJ_FIELD + 1;
pub(crate) const E_NEXT_FIELD: usize = A_NEXT_FIELD + 1;

pub(crate) const A_NEXT_QUOTIENT: usize = E_NEXT_FIELD + 1;
pub(crate) const E_NEXT_QUOTIENT: usize = A_NEXT_QUOTIENT + 1;

pub(crate) const HIS_START: usize = E_NEXT_QUOTIENT + 1;
pub(crate) fn h_i(i: usize) -> usize {
    HIS_START + i
}

pub(crate) const HIS_NEXT_FIELD_START: usize = HIS_START + 8;
pub(crate) fn h_i_next_field(i: usize) -> usize {
    HIS_NEXT_FIELD_START + i
}

pub(crate) const HIS_NEXT_QUOTIENT_START: usize = HIS_NEXT_FIELD_START + 8;
pub(crate) fn h_i_next_quotient(i: usize) -> usize {
    HIS_NEXT_QUOTIENT_START + i
}

pub(crate) const OUTPUT_COLS_START: usize = HIS_NEXT_QUOTIENT_START + 8;
pub fn output_i(i: usize) -> usize {
    OUTPUT_COLS_START + i
}

pub const OUTPUT_FILTER: usize = OUTPUT_COLS_START + 8;

pub(crate) const LAST_COL: usize = OUTPUT_FILTER;
