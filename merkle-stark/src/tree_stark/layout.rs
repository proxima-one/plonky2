pub const TREE_DEPTH: usize = 5;
pub const TREE_WIDTH: usize = 1 << (TREE_DEPTH - 1);
pub const WORDS_PER_HASH: usize = 8;

pub const NUM_PUBLIC_INPUTS: usize = TREE_WIDTH * WORDS_PER_HASH;
pub const NUM_COLS: usize = LAST_COL + 1;

pub const INPUT_FILTER: usize = 0;
pub const OUTPUT_FILTER: usize = INPUT_FILTER + 1;
pub const DEPTH_CTR: usize = OUTPUT_FILTER + 1;

pub const VALS_START: usize = 0;
pub fn val_i_word(i: usize, word: usize) -> usize {
	VALS_START + i * 8 + word
}

pub const HASH_INPUT_0_START: usize = VALS_START + TREE_WIDTH * WORDS_PER_HASH;
pub fn hash_input_0_word(word: usize) -> usize {
	HASH_INPUT_0_START + word
}

pub const HASH_INPUT_1: usize = HASH_INPUT_0_START + WORDS_PER_HASH;
pub fn hash_input_1_word(word: usize) -> usize {
	HASH_INPUT_1 + word
}

pub const HASH_OUTPUT: usize = HASH_INPUT_1 + WORDS_PER_HASH;
pub fn hash_output_word(word: usize) -> usize {
	HASH_OUTPUT + word
}

pub const LAST_COL: usize = HASH_OUTPUT + WORDS_PER_HASH;
