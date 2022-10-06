use std::borrow::Borrow;
use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::packed::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use self::layout::XorLayout;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::stark::Stark;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

pub mod generation;
pub mod layout;

/// N-bit XOR up to 63 bits;
pub struct XorStark<F: RichField + Extendable<D>, const D: usize, const N: usize> {
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize> XorStark<F, D, N> {
    pub fn new() -> XorStark<F, D, N> {
        XorStark {
            _phantom: PhantomData,
        }
    }
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen<P: PackedField>(x: P, y: P) -> P {
    x + y - x * y.doubles()
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: ExtensionTarget<D>,
    y: ExtensionTarget<D>,
) -> ExtensionTarget<D> {
    let sum = builder.add_extension(x, y);
    builder.arithmetic_extension(-F::TWO, F::ONE, x, y, sum)
}

macro_rules! impl_xor_stark_n {
    ($n:expr) => {
        impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for XorStark<F, D, $n> {
            const COLUMNS: usize = 3 + 2 * $n;
            const PUBLIC_INPUTS: usize = 0;

            fn eval_packed_generic<FE, P, const D2: usize>(
                &self,
                vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut ConstraintConsumer<P>,
            ) where
                FE: FieldExtension<D2, BaseField = F>,
                P: PackedField<Scalar = FE>,
            {
                let row: &XorLayout<P, $n> = vars.local_values.borrow();

                let c: P = (0..$n)
                    .map(|i| row.a_bits[i] * FE::from_canonical_u64(1 << i))
                    .sum();
                yield_constr.constraint(row.a - c);

                let c: P = (0..$n)
                    .map(|i| row.b_bits[i] * FE::from_canonical_u64(1 << i))
                    .sum();
                yield_constr.constraint(row.b - c);

                let c: P = (0..$n)
                    .map(|i| xor_gen(row.a_bits[i], row.b_bits[i]) * FE::from_canonical_u64(1 << i))
                    .sum();
                yield_constr.constraint(row.output - c);
            }

            fn eval_ext_circuit(
                &self,
                builder: &mut CircuitBuilder<F, D>,
                vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
                yield_constr: &mut RecursiveConstraintConsumer<F, D>,
            ) {
                let row: &XorLayout<ExtensionTarget<D>, $n> = vars.local_values.borrow();

                let addends = (0..$n)
                    .map(|i| {
                        builder.mul_const_extension(F::from_canonical_u64(1 << i), row.a_bits[i])
                    })
                    .collect_vec();
                let mut c = builder.add_many_extension(addends);
                c = builder.sub_extension(row.a, c);
                yield_constr.constraint(builder, c);

                let addends = (0..$n)
                    .map(|i| {
                        builder.mul_const_extension(F::from_canonical_u64(1 << i), row.a_bits[i])
                    })
                    .collect_vec();
                let mut c = builder.add_many_extension(addends);
                c = builder.sub_extension(row.b, c);
                yield_constr.constraint(builder, c);

                let addends = (0..$n)
                    .map(|i| {
                        let xor = xor_gen_circuit(builder, row.a_bits[i], row.b_bits[i]);
                        builder.mul_const_extension(F::from_canonical_u64(1 << i), xor)
                    })
                    .collect_vec();
                let mut c = builder.add_many_extension(addends);
                c = builder.sub_extension(row.output, c);
                yield_constr.constraint(builder, c);
            }

            fn constraint_degree(&self) -> usize {
                3
            }
        }
    };
}

impl_xor_stark_n!(1);
impl_xor_stark_n!(2);
impl_xor_stark_n!(3);
impl_xor_stark_n!(4);
impl_xor_stark_n!(5);
impl_xor_stark_n!(6);
impl_xor_stark_n!(7);
impl_xor_stark_n!(8);
impl_xor_stark_n!(9);
impl_xor_stark_n!(10);
impl_xor_stark_n!(11);
impl_xor_stark_n!(12);
impl_xor_stark_n!(13);
impl_xor_stark_n!(14);
impl_xor_stark_n!(15);
impl_xor_stark_n!(16);
impl_xor_stark_n!(17);
impl_xor_stark_n!(18);
impl_xor_stark_n!(19);
impl_xor_stark_n!(20);
impl_xor_stark_n!(21);
impl_xor_stark_n!(22);
impl_xor_stark_n!(23);
impl_xor_stark_n!(24);
impl_xor_stark_n!(25);
impl_xor_stark_n!(26);
impl_xor_stark_n!(27);
impl_xor_stark_n!(28);
impl_xor_stark_n!(29);
impl_xor_stark_n!(30);
impl_xor_stark_n!(31);
impl_xor_stark_n!(32);
impl_xor_stark_n!(33);
impl_xor_stark_n!(34);
impl_xor_stark_n!(35);
impl_xor_stark_n!(36);
impl_xor_stark_n!(37);
impl_xor_stark_n!(38);
impl_xor_stark_n!(39);
impl_xor_stark_n!(40);
impl_xor_stark_n!(41);
impl_xor_stark_n!(42);
impl_xor_stark_n!(43);
impl_xor_stark_n!(44);
impl_xor_stark_n!(45);
impl_xor_stark_n!(46);
impl_xor_stark_n!(47);
impl_xor_stark_n!(48);
impl_xor_stark_n!(49);
impl_xor_stark_n!(50);
impl_xor_stark_n!(51);
impl_xor_stark_n!(52);
impl_xor_stark_n!(53);
impl_xor_stark_n!(54);
impl_xor_stark_n!(55);
impl_xor_stark_n!(56);
impl_xor_stark_n!(57);
impl_xor_stark_n!(58);
impl_xor_stark_n!(59);
impl_xor_stark_n!(60);
impl_xor_stark_n!(61);
impl_xor_stark_n!(62);
impl_xor_stark_n!(63);

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use rand::Rng;

    use super::*;
    use crate::config::StarkConfig;
    use crate::prover::prove_no_ctl;
    use crate::starky2lib::xor::generation::XorGenerator;
    use crate::verifier::verify_stark_proof_no_ctl;

    macro_rules! test_xor {
        ($n:expr, $fn_name:ident) => {
            paste::item! {
                #[test]
                fn [<$fn_name>] () -> Result<()> {
                    const D: usize = 2;
                    type C = PoseidonGoldilocksConfig;
                    type F = <C as GenericConfig<D>>::F;
                    type S = XorStark<F, D, $n>;

                    let mut rng = rand::thread_rng();
                    let mut generator = XorGenerator::<F, $n>::new();
                    for _ in 0..32 {
                        let a = rng.gen_range(0..(1 << $n));
                        let b = rng.gen_range(0..(1 << $n));
                        generator.gen_op(a, b);
                    }

                    let config = StarkConfig::standard_fast_config();
                    let stark = S::new();
                    let trace = generator.into_polynomial_values();
                    let mut timing = TimingTree::default();
                    let proof = prove_no_ctl::<F, C, S, D>(&stark, &config, &trace, [], &mut timing)?;
                    verify_stark_proof_no_ctl(&stark, &proof, &config)
                }
            }
        }
    }

    test_xor!(1, test_xor_1);
    test_xor!(2, test_xor_2);
    test_xor!(4, test_xor_4);
    test_xor!(12, test_xor_12);
    test_xor!(16, test_xor_16);
    test_xor!(32, test_xor_32);
    test_xor!(63, test_xor_64);
}
