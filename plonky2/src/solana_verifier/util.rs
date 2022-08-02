use crate::plonk::config::{GenericConfig, Hasher};

#[allow(type_alias_bounds)]
pub(crate) type HashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

#[allow(type_alias_bounds)]
pub(crate) type InnerHashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::InnerHasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;
