use plonky2::field::{
    extension::Extendable,
    packed::PackedField,
};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};

pub trait ConstraintConsumerFiltered<P: PackedField> {
    fn constraint_filtered(&mut self, c: P, filter: P);
    fn constraint_transition_filtered(&mut self, c: P, filter: P);
}

impl<P: PackedField> ConstraintConsumerFiltered<P> for ConstraintConsumer<P> {
    fn constraint_filtered(&mut self, c: P, filter: P) {
        self.constraint(c * filter);
    }

    fn constraint_transition_filtered(&mut self, c: P, filter: P) {
        self.constraint_transition(c * filter);
    }
}

pub trait RecursiveConstraintConsumerFiltered<F: RichField + Extendable<D>, const D: usize> {
    fn constraint_filtered(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        c: ExtensionTarget<D>,
        filter: ExtensionTarget<D>,
    );
    fn constraint_transition_filtered(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        c: ExtensionTarget<D>,
        filter: ExtensionTarget<D>,
    );
}

impl<F: RichField + Extendable<D>, const D: usize> RecursiveConstraintConsumerFiltered<F, D>
    for RecursiveConstraintConsumer<F, D>
{
    fn constraint_filtered(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        c: ExtensionTarget<D>,
        filter: ExtensionTarget<D>,
    ) {
        let c = builder.mul_extension(c, filter);
        self.constraint(builder, c);
    }

    fn constraint_transition_filtered(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        c: ExtensionTarget<D>,
        filter: ExtensionTarget<D>,
    ) {
        let c = builder.mul_extension(c, filter);
        self.constraint_transition(builder, c);
    }
}

pub trait Starky2ConstraintConsumer<P: PackedField> {
    fn inv_check(&mut self, value: P, inv: P, binary_flag: P);
    fn inv_check_inverted(&mut self, value: P, inv: P, binary_flag: P);
    fn binary_check(&mut self, value: P);
    fn mutually_exclusive_binary_check(&mut self, values: &[P]);

    // TODO add more stuff
}

impl<P: PackedField> Starky2ConstraintConsumer<P> for ConstraintConsumer<P> {
    fn inv_check(&mut self, value: P, inv: P, binary_flag: P) {
        let prod = value * inv;

        self.constraint_filtered(prod, binary_flag);
        self.constraint_filtered(value, binary_flag);

        self.constraint_filtered(P::ONES - prod, P::ONES - binary_flag);
    }

    fn inv_check_inverted(&mut self, value: P, inv: P, binary_flag: P) {
        self.inv_check(value, inv, P::ONES - binary_flag);
    }

    fn binary_check(&mut self, value: P) {
        self.constraint(value * (P::ONES - value));
    }

    fn mutually_exclusive_binary_check(&mut self, values: &[P]) {
        for &val in values {
            self.binary_check(val);
        }

        let sum = values.iter().copied().sum::<P>();
        self.constraint(sum * (P::ONES - sum));
    }
}

pub trait RecursiveStarky2ConstraintConsumer<F: RichField + Extendable<D>, const D: usize> {
    fn inv_check(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: ExtensionTarget<D>,
        inv: ExtensionTarget<D>,
        binary_flag: ExtensionTarget<D>,
    );
    fn inv_check_inverted(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: ExtensionTarget<D>,
        inv: ExtensionTarget<D>,
        binary_flag: ExtensionTarget<D>,
    );
    fn binary_check(&mut self, builder: &mut CircuitBuilder<F, D>, value: ExtensionTarget<D>);
    fn mutually_exclusive_binary_check(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        values: &[ExtensionTarget<D>],
    );

    // TODO add more stuff
}

impl<F: RichField + Extendable<D>, const D: usize> RecursiveStarky2ConstraintConsumer<F, D>
    for RecursiveConstraintConsumer<F, D>
{
    fn inv_check(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: ExtensionTarget<D>,
        inv: ExtensionTarget<D>,
        binary_flag: ExtensionTarget<D>,
    ) {
        let prod = builder.mul_extension(value, inv);

        self.constraint_filtered(builder, prod, binary_flag);
        self.constraint_filtered(builder, value, binary_flag);

        let c = builder.add_const_extension(prod, -F::ONE);
        let f = builder.add_const_extension(binary_flag, -F::ONE);

        self.constraint_filtered(builder, c, f);
    }

    fn inv_check_inverted(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: ExtensionTarget<D>,
        inv: ExtensionTarget<D>,
        binary_flag: ExtensionTarget<D>,
    ) {
        let inverted_flag = builder.add_const_extension(binary_flag, -F::ONE);
        self.inv_check(builder, value, inv, inverted_flag);
    }

    fn binary_check(&mut self, builder: &mut CircuitBuilder<F, D>, value: ExtensionTarget<D>) {
        let c = builder.add_const_extension(value, -F::ONE);
        let c = builder.mul_extension(c, value);
        self.constraint(builder, c);
    }

    fn mutually_exclusive_binary_check(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        values: &[ExtensionTarget<D>],
    ) {
        for val in values {
            self.binary_check(builder, *val);
        }

        let sum = values.iter().fold(builder.zero_extension(), |acc, val| {
            builder.add_extension(acc, *val)
        });
        let c = builder.add_const_extension(sum, -F::ONE);
        let c = builder.mul_extension(c, sum);
        self.constraint(builder, c);
    }
}
