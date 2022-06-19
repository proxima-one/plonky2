pub const NUM_PUBLIC_INPUTS: usize = 10;
pub const NUM_COLUMNS: usize =
    INSNS_NUM_COLS + REGISTERS_NUM_COLS + MEM_NUM_COLS + MEM_SORTED_NUM_COLS;
pub const MAX_ROWS: usize = 1 << 16;

// public input layout
pub const PC_INITIAL: usize = 0;
pub const PC_FINAL: usize = PC_INITIAL + 1;
pub const AP_INITIAL: usize = PC_FINAL + 1;
pub const AP_FINAL: usize = AP_INITIAL + 1;
pub const SP_INITIAL: usize = AP_FINAL + 1;
pub const CLK_FINAL: usize = SP_INITIAL + 1;
// ! Only works for a STARK config that uses 2 challenges
pub const PUBLIC_MEMORY_PRODUCT_0: usize = CLK_FINAL + 1;
pub const PUBLIC_MEMORY_PRODUCT_1: usize = PUBLIC_MEMORY_PRODUCT_0 + 1;
pub const RC_MIN: usize = PUBLIC_MEMORY_PRODUCT_1 + 1;
pub const RC_MAX: usize = RC_MIN + 1;

// define regions of trace columns
pub const START_INSNS: usize = 0;
pub const START_REGISTERS: usize = START_INSNS + INSNS_NUM_COLS;
pub const START_MEM: usize = START_REGISTERS + REGISTERS_NUM_COLS;
pub const START_MEM_SORTED: usize = START_MEM + MEM_NUM_COLS;

// Instruction cols
pub const OP0_OFFSET_COL: usize = START_INSNS;
pub const OP1_OFFSET_COL: usize = OP0_OFFSET_COL + 1;
pub const DST_OFFSET_COL: usize = OP1_OFFSET_COL + 1;
pub const FLAG_NUM_COLS: usize = 16;
pub const FLAG_COLS: [usize; FLAG_NUM_COLS] = [
    DST_OFFSET_COL + 1,
    DST_OFFSET_COL + 2,
    DST_OFFSET_COL + 3,
    DST_OFFSET_COL + 4,
    DST_OFFSET_COL + 5,
    DST_OFFSET_COL + 6,
    DST_OFFSET_COL + 7,
    DST_OFFSET_COL + 8,
    DST_OFFSET_COL + 9,
    DST_OFFSET_COL + 10,
    DST_OFFSET_COL + 11,
    DST_OFFSET_COL + 12,
    DST_OFFSET_COL + 13,
    DST_OFFSET_COL + 14,
    DST_OFFSET_COL + 15,
    DST_OFFSET_COL + 16,
];
pub const INSNS_NUM_COLS: usize = FLAG_COLS[FLAG_NUM_COLS - 1] - START_INSNS + 1;

// Register columns

pub const PC_COL: usize = START_REGISTERS;
pub const OP0_COL: usize = PC_COL + 1;
pub const OP1_COL: usize = OP0_COL + 1;
pub const DST_COL: usize = OP1_COL + 1;
pub const SP_COL: usize = DST_COL + 1;
pub const AP_COL: usize = SP_COL + 1;
// * when insn is a conditional relative jump, row[RES_COL] should contain inv(dst)
pub const RES_COL: usize = AP_COL + 1;
// * used to reduce the degree of some constraints
pub const TMP_0_COL: usize = RES_COL + 1;
pub const TMP_1_COL: usize = TMP_0_COL + 1;
pub const TMP_2_COL: usize = TMP_1_COL + 1;
pub const TMP_3_COL: usize = TMP_2_COL + 1;
pub const TMP_4_COL: usize = TMP_3_COL + 1;
pub const CLK_COL: usize = TMP_4_COL + 1;
pub const REGISTERS_NUM_COLS: usize = CLK_COL - START_REGISTERS + 1;

// Memory columns for each calculated address
pub const PC_MEM_COL: usize = START_MEM;
pub const OP0_MEM_COL: usize = PC_MEM_COL + 1;
pub const OP1_MEM_COL: usize = OP0_MEM_COL + 1;
pub const DST_MEM_COL: usize = OP1_MEM_COL + 1;
pub const MEM_NUM_COLS: usize = DST_MEM_COL - START_MEM + 1;

// Sorted memory addresses for the permuation check, staggered across
// three columns
pub const ADDR_SORTED_COLS: [usize; 4] = [
    START_MEM_SORTED,
    START_MEM_SORTED + 1,
    START_MEM_SORTED + 2,
    START_MEM_SORTED + 3,
];
pub const MEM_SORTED_COLS: [usize; 4] = [
    ADDR_SORTED_COLS[3] + 1,
    ADDR_SORTED_COLS[3] + 2,
    ADDR_SORTED_COLS[3] + 3,
    ADDR_SORTED_COLS[3] + 4,
];
pub const MEM_SORTED_NUM_COLS: usize = MEM_SORTED_COLS[3] - START_MEM_SORTED + 1;
