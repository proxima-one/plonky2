pub const NUM_PIS: usize = 0;
pub const NUM_COLS: usize = LAST_COL + 1;

pub const HASH_IDX: usize = 0;
pub const CHUNK_IDX: usize = HASH_IDX + 1;
pub const PC: usize = CHUNK_IDX + 1;

pub const PHASE_BITS_START: usize = PC + 1;
pub fn phase_bit(i: usize) -> usize {
	PHASE_BITS_START + i
}

pub const LEFT_INPUT_COL: usize = PHASE_BITS_START + 3;
pub const RIGHT_INPUT_COL: usize = LEFT_INPUT_COL + 1;

pub const NUM_WIS: usize = 16;
pub const WIS_START: usize = RIGHT_INPUT_COL + 1;
pub fn wi_bit(i: usize, bit: usize) -> usize {
	WIS_START + i * 32 + bit
}

pub const LITTLE_S0_START: usize = WIS_START + 16 * 32;
pub fn little_s0_bit(bit: usize) -> usize {
	LITTLE_S0_START + bit
}

pub const LITTLE_S1_START: usize = LITTLE_S0_START + 32;
pub fn little_s1_bit(bit: usize) -> usize {
	LITTLE_S1_START + bit
}

pub const WI_FIELD: usize = LITTLE_S1_START + 32;
pub const WI_MINUS_SEVEN_FIELD: usize = WI_FIELD + 1;
pub const WI_MINUS_SIXTEEN_FIELD: usize = WI_MINUS_SEVEN_FIELD + 1;

pub const LITTLE_S0_FIELD: usize = WI_MINUS_SIXTEEN_FIELD + 16;
pub const LITTLE_S1_FIELD: usize = LITTLE_S0_FIELD + 1;

pub const WI_ACC_START: usize = LITTLE_S1_START + 1;
pub fn wi_acc(i: usize) -> usize {
	WI_ACC_START + i
}

pub const A_START: usize = WI_ACC_START + 2;
pub fn a_bit(bit: usize) -> usize {
	A_START + bit
}

pub const B_START: usize = A_START + 32;
pub fn b_bit(bit: usize) -> usize {
	B_START + bit
}

pub const C_START: usize = B_START + 32;
pub fn c_bit(bit: usize) -> usize {
	C_START + bit
}

pub const D_START: usize = C_START + 32;
pub fn d_bit(bit: usize) -> usize {
	D_START + bit
}

pub const E_START: usize = D_START + 32;
pub fn e_bit(bit: usize) -> usize {
	E_START + bit
}

pub const F_START: usize = E_START + 32;
pub fn f_bit(bit: usize) -> usize {
	F_START + bit
}

pub const G_START: usize = F_START + 32;
pub fn g_bit(bit: usize) -> usize {
	G_START + bit
}

pub const H_START: usize = G_START + 32;
pub fn h_bit(bit: usize) -> usize {
	H_START + bit
}

pub const BIG_S0_START: usize = H_START + 32;
pub fn big_s0_bit(bit: usize) -> usize {
	BIG_S0_START + bit
}

pub const BIG_S1_START: usize = BIG_S0_START + 32;
pub fn big_s1_bit(bit: usize) -> usize {
	BIG_S1_START + bit
}

pub const NOT_E_AND_G_START: usize = BIG_S1_START + 32;
pub fn not_e_and_g_bit(bit: usize) -> usize {
	NOT_E_AND_G_START + bit
}

pub const E_AND_F_START: usize = NOT_E_AND_G_START + 32;
pub fn e_and_f_bit(bit: usize) -> usize {
	E_AND_F_START + bit
}

pub const CH_START: usize = E_AND_F_START + 32;
pub fn ch_bit(bit: usize) -> usize {
	CH_START + bit
}

pub const A_AND_B: usize = CH_START + 32;
pub fn a_and_b_bit(bit: usize) -> usize {
	A_AND_B + bit
}

pub const A_AND_C: usize = A_AND_B + 32;
pub fn a_and_c_bit(bit: usize) -> usize {
	A_AND_C + bit
}

pub const B_AND_C: usize = A_AND_C + 32;
pub fn b_and_c_bit(bit: usize) -> usize {
	B_AND_C + bit
}

pub const MAJ_START: usize = B_AND_C + 32;
pub fn maj_bit(bit: usize) -> usize {
	MAJ_START + bit
}

pub const BIG_SO_FIELD: usize = MAJ_START + 32;
pub const BIG_S1_FIELD: usize = BIG_SO_FIELD + 1;
pub const CH_FIELD: usize = BIG_S1_FIELD + 1;
pub const MAJ_FIELD: usize = CH_FIELD + 1;

pub const TEMP1_FIELD: usize = MAJ_FIELD + 1;
pub const TEMP1_ACC_START: usize = TEMP1_FIELD + 1;
pub fn temp1_acc(i: usize) -> usize {
	TEMP1_ACC_START + i
}

pub const TEMP2_FIELD: usize = TEMP1_ACC_START + 3;

pub const A_FIELD: usize = TEMP2_FIELD + 1;
pub const B_FIELD: usize = A_FIELD + 1;
pub const C_FIELD: usize = B_FIELD + 1;
pub const D_FIELD: usize = C_FIELD + 1;
pub const E_FIELD: usize = D_FIELD + 1;
pub const F_FIELD: usize = E_FIELD + 1;
pub const G_FIELD: usize = F_FIELD + 1;
pub const H_FIELD: usize = G_FIELD + 1;

pub const HIS_START: usize = H_FIELD + 1;
pub fn h_i(i: usize) -> usize {
	HIS_START + i
}

pub const OUTPUT_COL: usize = HIS_START + 8;

pub const LAST_COL: usize = OUTPUT_COL;
