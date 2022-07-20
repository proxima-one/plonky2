//! Information about the structure of a FRI instance, in terms of the oracles and polynomials
//! involved, and the points they are opened at.

use std::iter::Map;
use std::ops::Range;

use crate::field::extension::Extendable;
use crate::hash::hash_types::RichField;
use crate::iop::ext_target::ExtensionTarget;
use crate::plonk::proof::OpeningSet;

/// Describes an instance of a FRI-based batch opening.
#[derive(Debug)]
pub struct FriInstanceInfo<F: RichField + Extendable<D>, const D: usize> {
    /// The oracles involved, not counting oracles created during the commit phase.
    pub oracles: Vec<FriOracleInfo>,
    /// Batches of openings, where each batch is associated with a particular point.
    pub batches: Vec<FriBatchInfo<F, D>>,
}

/// Describes an instance of a FRI-based batch opening.
pub struct FriInstanceInfoTarget<const D: usize> {
    /// The oracles involved, not counting oracles created during the commit phase.
    pub oracles: Vec<FriOracleInfo>,
    /// Batches of openings, where each batch is associated with a particular point.
    pub batches: Vec<FriBatchInfoTarget<D>>,
}

#[derive(Debug, Copy, Clone)]
pub struct FriOracleInfo {
    pub blinding: bool,
}

/// A batch of openings at a particular point.
#[derive(Debug)]
pub struct FriBatchInfo<F: RichField + Extendable<D>, const D: usize> {
    pub point: F::Extension,
    pub polynomials: Vec<FriPolynomialInfo>,
}

/// A batch of openings at a particular point.
pub struct FriBatchInfoTarget<const D: usize> {
    pub point: ExtensionTarget<D>,
    pub polynomials: Vec<FriPolynomialInfo>,
}

#[derive(Copy, Clone, Debug)]
pub struct FriPolynomialInfo {
    /// Index into `FriInstanceInfoTarget`'s `oracles` list.
    pub oracle_index: usize,
    /// Index of the polynomial within the oracle.
    pub polynomial_index: usize,
}

impl FriPolynomialInfo {
    pub fn from_range(
        oracle_index: usize,
        polynomial_indices: Range<usize>,
    ) -> Vec<FriPolynomialInfo> {
        polynomial_indices
            .map(|polynomial_index| FriPolynomialInfo {
                oracle_index,
                polynomial_index,
            })
            .collect()
    }

    #[cfg(any(feature = "buffer_verifier", test))]
    pub fn iter_from_range(
        oracle_index: usize,
        polynomial_indices: Range<usize>,
    ) -> impl Iterator<Item = FriPolynomialInfo> {
        polynomial_indices.map(move |polynomial_index| FriPolynomialInfo {
            oracle_index,
            polynomial_index,
        })
    }
}

/// Opened values of each polynomial.
pub struct FriOpenings<F: RichField + Extendable<D>, const D: usize> {
    pub batches: Vec<FriOpeningBatch<F, D>>,
}

/// Opened values of each polynomial that's opened at a particular point.
pub struct FriOpeningBatch<F: RichField + Extendable<D>, const D: usize> {
    pub values: Vec<F::Extension>,
}

/// Opened values of each polynomial.
pub struct FriOpeningsTarget<const D: usize> {
    pub batches: Vec<FriOpeningBatchTarget<D>>,
}

/// Opened values of each polynomial that's opened at a particular point.
pub struct FriOpeningBatchTarget<const D: usize> {
    pub values: Vec<ExtensionTarget<D>>,
}

#[cfg(any(feature = "buffer_verifier", test))]
pub struct FriOpeningsIter<'a, F: RichField + Extendable<D>, const D: usize> {
    pub(crate) openings: &'a OpeningSet<F, D>,
    pub(crate) idx: usize,
}

#[cfg(any(feature = "buffer_verifier", test))]
impl<'a, F: RichField + Extendable<D>, const D: usize> Iterator for FriOpeningsIter<'a, F, D> {
    type Item = F::Extension;

    fn next(&mut self) -> Option<Self::Item> {
        let mut idx = self.idx;

        if self.idx < self.openings.constants.len() {
            self.idx += 1;
            return Some(self.openings.constants[idx])
        }
        idx -= self.openings.constants.len();

        if idx < self.openings.plonk_sigmas.len() {
            self.idx += 1;
            return Some(self.openings.plonk_sigmas[idx])
        }
        idx -= self.openings.plonk_sigmas.len();

        if idx < self.openings.wires.len() {
            self.idx += 1;
            return Some(self.openings.wires[idx])
        }
        idx -= self.openings.wires.len();

        if idx < self.openings.plonk_zs.len() {
            self.idx += 1;
            return Some(self.openings.plonk_zs[idx])
        }
        idx -= self.openings.plonk_zs.len();

        if idx < self.openings.partial_products.len() {
            self.idx += 1;
            return Some(self.openings.partial_products[idx])
        }
        idx -= self.openings.partial_products.len();

        if idx < self.openings.quotient_polys.len() {
            self.idx += 1;
            return Some(self.openings.quotient_polys[idx])
        }
        idx -= self.openings.quotient_polys.len();

        if idx < self.openings.plonk_zs_next.len() {
            self.idx += 1;
            return Some(self.openings.plonk_zs_next[idx])
        }

        None
    }
}
