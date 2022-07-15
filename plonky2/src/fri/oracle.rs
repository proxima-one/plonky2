use itertools::Itertools;
use plonky2_field::extension::Extendable;
use plonky2_field::fft::FftRootTable;
use plonky2_field::packed::PackedField;
use plonky2_field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2_field::types::Field;
use plonky2_util::{log2_strict, reverse_index_bits_in_place};

use crate::fri::proof::FriProof;
use crate::fri::prover::fri_proof;
use crate::fri::structure::{FriBatchInfo, FriInstanceInfo};
use crate::fri::FriParams;
use crate::hash::hash_types::RichField;
use crate::hash::merkle_tree::MerkleTree;
use crate::iop::challenger::Challenger;
use crate::plonk::config::{GenericConfig, Hasher};
use crate::util::reducing::ReducingFactor;
use crate::util::reverse_bits;
use crate::util::transpose;
use crate::{cfg_into_iter, cfg_iter};
#[cfg(any(feature = "log", test))]
use crate::util::timing::TimingTree;
#[cfg(any(feature = "log", test))]
use crate::timed;
#[cfg(any(feature = "parallel", test))]
use rayon::prelude::*;

/// Four (~64 bit) field elements gives ~128 bit security.
pub const SALT_SIZE: usize = 4;

/// Represents a FRI oracle, i.e. a batch of polynomials which have been Merklized.
pub struct PolynomialBatch<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub polynomials: Vec<PolynomialCoeffs<F>>,
    pub merkle_tree: MerkleTree<F, C::Hasher>,
    pub degree_log: usize,
    pub rate_bits: usize,
    pub blinding: bool,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    PolynomialBatch<F, C, D>
{
    /// Creates a list polynomial commitment for the polynomials interpolating the values in `values`.
    pub fn from_values(
        values: Vec<PolynomialValues<F>>,
        rate_bits: usize,
        blinding: bool,
        cap_height: usize,
        #[cfg(any(feature = "log", test))] timing: &mut TimingTree,
        fft_root_table: Option<&FftRootTable<F>>,
    ) -> Self
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
       
        #[cfg(any(feature = "log", test))]
        let coeffs = timed!(
            timing,
            "IFFT",
            cfg_into_iter!(values).map(|v| v.ifft()).collect::<Vec<_>>()
        );
        #[cfg(not(any(feature = "log", test)))]
        let coeffs = cfg_into_iter!(values).map(|v| v.ifft()).collect::<Vec<_>>();


        Self::from_coeffs(
            coeffs,
            rate_bits,
            blinding,
            cap_height,
            #[cfg(any(feature = "log", test))] timing,
            fft_root_table,
        )
    }

    /// Creates a list polynomial commitment for the polynomials `polynomials`.
    pub fn from_coeffs(
        polynomials: Vec<PolynomialCoeffs<F>>,
        rate_bits: usize,
        blinding: bool,
        cap_height: usize,
        #[cfg(any(feature = "log", test))] timing: &mut TimingTree,
        fft_root_table: Option<&FftRootTable<F>>,
    ) -> Self
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        let degree = polynomials[0].len();

        #[cfg(any(feature = "log", test))]
        let lde_values = timed!(
            timing,
            "FFT + blinding",
            Self::lde_values(&polynomials, rate_bits, blinding, fft_root_table)
        );
        #[cfg(not(any(feature = "log", test)))]
        let lde_values = Self::lde_values(&polynomials, rate_bits, blinding, fft_root_table);

        #[cfg(any(feature = "log", test))]
        let mut leaves = timed!(timing, "transpose LDEs", transpose(&lde_values));
        #[cfg(not(any(feature = "log", test)))]
        let mut leaves = transpose(&lde_values);

        reverse_index_bits_in_place(&mut leaves);
        #[cfg(any(feature = "log", test))]
        let merkle_tree = timed!(
            timing,
            "build Merkle tree",
            MerkleTree::new(leaves, cap_height)
        );
        #[cfg(not(any(feature = "log", test)))]
        let merkle_tree = MerkleTree::new(leaves, cap_height);

        Self {
            polynomials,
            merkle_tree,
            degree_log: log2_strict(degree),
            rate_bits,
            blinding,
        }
    }

    fn lde_values(
        polynomials: &[PolynomialCoeffs<F>],
        rate_bits: usize,
        blinding: bool,
        fft_root_table: Option<&FftRootTable<F>>,
    ) -> Vec<Vec<F>> {
        let degree = polynomials[0].len();

        // If blinding, salt with two random elements to each leaf vector.
        let salt_size = if blinding { SALT_SIZE } else { 0 };

        cfg_iter!(polynomials)
            .map(|p| {
                assert_eq!(p.len(), degree, "Polynomial degrees inconsistent");
                p.lde(rate_bits)
                    .coset_fft_with_options(F::coset_shift(), Some(rate_bits), fft_root_table)
                    .values
            })
            .chain(
                cfg_into_iter!((0..salt_size))
                    .map(|_| F::rand_vec(degree << rate_bits)),
            )
            .collect()
    }

    /// Fetches LDE values at the `index * step`th point.
    pub fn get_lde_values(&self, index: usize, step: usize) -> &[F] {
        let index = index * step;
        let index = reverse_bits(index, self.degree_log + self.rate_bits);
        let slice = &self.merkle_tree.leaves[index];
        &slice[..slice.len() - if self.blinding { SALT_SIZE } else { 0 }]
    }

    /// Like `get_lde_values`, but fetches LDE values from a batch of `P::WIDTH` points, and returns
    /// packed values.
    pub fn get_lde_values_packed<P>(&self, index_start: usize, step: usize) -> Vec<P>
    where
        P: PackedField<Scalar = F>,
    {
        let row_wise = (0..P::WIDTH)
            .map(|i| self.get_lde_values(index_start + i, step))
            .collect_vec();

        // This is essentially a transpose, but we will not use the generic transpose method as we
        // want inner lists to be of type P, not Vecs which would involve allocation.
        let leaf_size = row_wise[0].len();
        (0..leaf_size)
            .map(|j| {
                let mut packed = P::ZEROS;
                packed
                    .as_slice_mut()
                    .iter_mut()
                    .zip(&row_wise)
                    .for_each(|(packed_i, row_i)| *packed_i = row_i[j]);
                packed
            })
            .collect_vec()
    }

    /// Produces a batch opening proof.
    pub fn prove_openings(
        instance: &FriInstanceInfo<F, D>,
        oracles: &[&Self],
        challenger: &mut Challenger<F, C::Hasher>,
        fri_params: &FriParams,
        #[cfg(any(feature = "log", test))] timing: &mut TimingTree,
    ) -> FriProof<F, C::Hasher, D>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        assert!(D > 1, "Not implemented for D=1.");
        let alpha = challenger.get_extension_challenge::<D>();
        let mut alpha = ReducingFactor::new(alpha);

        // Final low-degree polynomial that goes into FRI.
        let mut final_poly = PolynomialCoeffs::empty();

        for FriBatchInfo { point, polynomials } in &instance.batches {
            let polys_coeff = polynomials.iter().map(|fri_poly| {
                &oracles[fri_poly.oracle_index].polynomials[fri_poly.polynomial_index]
            });

            #[cfg(any(feature = "log", test))]
            let composition_poly = timed!(
                timing,
                &format!("reduce batch of {} polynomials", polynomials.len()),
                alpha.reduce_polys_base(polys_coeff)
            );
            #[cfg(not(any(feature = "log", test)))]
            let composition_poly = alpha.reduce_polys_base(polys_coeff);

            let quotient = composition_poly.divide_by_linear(*point);
            alpha.shift_poly(&mut final_poly);
            final_poly += quotient;
        }
        // Multiply the final polynomial by `X`, so that `final_poly` has the maximum degree for
        // which the LDT will pass. See github.com/mir-protocol/plonky2/pull/436 for details.
        final_poly.coeffs.insert(0, F::Extension::ZERO);

        let lde_final_poly = final_poly.lde(fri_params.config.rate_bits);

        #[cfg(any(feature = "log", test))]
        let lde_final_values = timed!(
            timing,
            &format!("perform final FFT {}", lde_final_poly.len()),
            lde_final_poly.coset_fft(F::coset_shift().into())
        );
        #[cfg(not(any(feature = "log", test)))]
        let lde_final_values = lde_final_poly.coset_fft(F::coset_shift().into());

        let initial_merkle_trees = cfg_iter!(oracles)
            .map(|c| &c.merkle_tree)
            .collect::<Vec<_>>();

        let fri_proof = fri_proof::<F, C, D>(
            &initial_merkle_trees,
            lde_final_poly,
            lde_final_values,
            challenger,
            fri_params,
            #[cfg(any(feature = "log", test))] timing,
        );

        fri_proof
    }
}
