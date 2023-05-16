#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]
#![feature(array_windows)]
#![feature(array_chunks)]
#![feature(exclusive_range_pattern)]
#![feature(array_zip)]
#![feature(is_sorted)]

pub mod config;
pub mod constraint_consumer;
pub mod get_challenges;
pub mod permutation;
pub mod proof;
pub mod prover;
// pub mod recursive_verifier;
pub mod all_stark;
pub mod cross_table_lookup;
pub mod lookup;
pub mod ro_memory;
pub mod stark;
pub mod stark_testing;
// pub mod starky2lib;
pub mod util;
pub mod vanishing_poly;
pub mod vars;
pub mod verifier;
