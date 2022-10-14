use itertools::Itertools;
use maybe_rayon::*;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::proof::{
    CompressedFriProof, FriChallenges, FriChallengesTarget, FriProof, FriProofTarget,
};
use plonky2::fri::structure::{
    FriOpeningBatch, FriOpeningBatchTarget, FriOpenings, FriOpeningsTarget,
};
use plonky2::hash::hash_types::{MerkleCapTarget, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::config::GenericConfig;

use crate::config::StarkConfig;
use crate::permutation::PermutationChallengeSet;
use crate::ro_memory::RoMemoryChallenge;

#[derive(Debug, Clone)]
pub struct StarkProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    // Merkle cap of LDEs of read-only memory product values
    pub ro_memory_cap: Option<MerkleCap<F, C::Hasher>>,
    /// Merkle cap of LDEs of permutation Z values.
    pub permutation_zs_cap: Option<MerkleCap<F, C::Hasher>>,
    /// Merkle cap of LDEs of cross-table-lookup Z values
    pub ctl_zs_cap: Option<MerkleCap<F, C::Hasher>>,
    /// Merkle cap of LDEs of trace values.
    pub quotient_polys_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: FriProof<F, C::Hasher, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> StarkProof<F, C, D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

pub struct StarkProofTarget<const D: usize> {
    pub trace_cap: MerkleCapTarget,
    pub permutation_zs_cap: Option<MerkleCapTarget>,
    pub quotient_polys_cap: MerkleCapTarget,
    pub openings: StarkOpeningSetTarget<D>,
    pub opening_proof: FriProofTarget<D>,
}

impl<const D: usize> StarkProofTarget<D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

#[derive(Debug, Clone)]
pub struct StarkProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: StarkProof<F, C, D>,
    // TODO: Maybe make it generic over a `S: Stark` and replace with `[F; S::PUBLIC_INPUTS]`.
    pub public_inputs: Vec<F>,
}

pub struct StarkProofWithPublicInputsTarget<const D: usize> {
    pub proof: StarkProofTarget<D>,
    pub public_inputs: Vec<Target>,
}

pub struct CompressedStarkProof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: CompressedFriProof<F, C::Hasher, D>,
}

pub struct CompressedStarkProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: CompressedStarkProof<F, C, D>,
    pub public_inputs: Vec<F>,
}

pub(crate) struct StarkProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    /// Randomness used in read-only memory argument
    pub ro_memory_challenges: Option<Vec<RoMemoryChallenge<F>>>,

    /// Randomness used in any permutation arguments.
    pub permutation_challenge_sets: Option<Vec<PermutationChallengeSet<F>>>,

    /// Random values used to combine STARK constraints.
    pub stark_alphas: Vec<F>,

    /// Point at which the STARK polynomials are opened.
    pub stark_zeta: F::Extension,

    pub fri_challenges: FriChallenges<F, D>,
}

pub(crate) struct StarkProofChallengesTarget<const D: usize> {
    pub permutation_challenge_sets: Option<Vec<PermutationChallengeSet<Target>>>,
    pub stark_alphas: Vec<Target>,
    pub stark_zeta: ExtensionTarget<D>,
    pub fri_challenges: FriChallengesTarget<D>,
}

/// Purported values of each polynomial at the challenge point.
#[derive(Debug, Clone)]
pub struct StarkOpeningSet<F: RichField + Extendable<D>, const D: usize> {
    /// Openings of trace polynomials at `zeta`.
    pub local_values: Vec<F::Extension>,
    /// Openings of trace polynomials at `g * zeta`.
    pub next_values: Vec<F::Extension>,
    /// Openings of read-only memory product polynomials at `zeta`.
    pub ro_memory_pps: Option<Vec<F::Extension>>,
    /// Openings of permutation polynomials at `g * zeta`.
    pub ro_memory_pps_next: Option<Vec<F::Extension>>,
    /// Openings of permutation `Z` polynomials at `zeta`.
    pub permutation_zs: Option<Vec<F::Extension>>,
    /// Openings of permutation `Z` polynomials at `g * zeta`.
    pub permutation_zs_next: Option<Vec<F::Extension>>,
    /// Openings of cross-table-lookup `Z` polynomials at `zeta`.
    pub ctl_zs: Option<Vec<F::Extension>>,
    /// Openings of cross-table-lookup `Z` polynomials at `g * zeta`.
    pub ctl_zs_next: Option<Vec<F::Extension>>,
    /// Openings of cross-table lookup `Z` polynomials at `g^-1`.
    pub ctl_zs_last: Option<Vec<F>>,
    /// Opening of cross-table lookup `Z` polynomials at `g^0`
    pub ctl_zs_first: Option<Vec<F>>,
    /// Openings of quotient polynomials at `zeta`.
    pub quotient_polys: Vec<F::Extension>,
}

impl<F: RichField + Extendable<D>, const D: usize> StarkOpeningSet<F, D> {
    pub fn new<C: GenericConfig<D, F = F>>(
        zeta: F::Extension,
        g: F,
        trace_commitment: &PolynomialBatch<F, C, D>,
        ro_memory_pps_commitment: Option<&PolynomialBatch<F, C, D>>,
        permutation_zs_commitment: Option<&PolynomialBatch<F, C, D>>,
        ctl_zs_commitment: Option<&PolynomialBatch<F, C, D>>,
        quotient_commitment: &PolynomialBatch<F, C, D>,
        degree_bits: usize,
    ) -> Self {
        let eval_commitment = |z: F::Extension, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.to_extension().eval(z))
                .collect::<Vec<_>>()
        };
        let eval_commitment_base = |z: F, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.eval(z))
                .collect::<Vec<_>>()
        };
        let zeta_next = zeta.scalar_mul(g);

        let ctl_zs_first = ctl_zs_commitment.map(|c| eval_commitment_base(F::ONE, c).to_vec());
        let ctl_zs_last = ctl_zs_commitment.map(|c| {
            eval_commitment_base(F::primitive_root_of_unity(degree_bits).inverse(), c).to_vec()
        });

        Self {
            local_values: eval_commitment(zeta, trace_commitment),
            next_values: eval_commitment(zeta_next, trace_commitment),
            ro_memory_pps: ro_memory_pps_commitment.map(|c| eval_commitment(zeta, c)),
            ro_memory_pps_next: ro_memory_pps_commitment.map(|c| eval_commitment(zeta_next, c)),
            permutation_zs: permutation_zs_commitment.map(|c| eval_commitment(zeta, c)),
            permutation_zs_next: permutation_zs_commitment.map(|c| eval_commitment(zeta_next, c)),
            ctl_zs: ctl_zs_commitment.map(|c| eval_commitment(zeta, c)),
            ctl_zs_next: ctl_zs_commitment.map(|c| eval_commitment(zeta_next, c)),
            ctl_zs_first,
            ctl_zs_last,
            quotient_polys: eval_commitment(zeta, quotient_commitment),
        }
    }

    pub(crate) fn to_fri_openings(&self) -> FriOpenings<F, D> {
        let zeta_batch = FriOpeningBatch {
            values: self
                .local_values
                .iter()
                .chain(self.permutation_zs.iter().flatten())
                .chain(self.ctl_zs.iter().flatten())
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatch {
            values: self
                .next_values
                .iter()
                .chain(self.permutation_zs_next.iter().flatten())
                .chain(self.ctl_zs_next.iter().flatten())
                .copied()
                .collect_vec(),
        };

        let ctl_first_last_batches = match (self.ctl_zs_first.as_ref(), self.ctl_zs_last.as_ref()) {
            (Some(first), Some(last)) => {
                let first_batch = FriOpeningBatch {
                    values: first
                        .iter()
                        .copied()
                        .map(F::Extension::from_basefield)
                        .collect(),
                };

                let last_batch = FriOpeningBatch {
                    values: last
                        .iter()
                        .copied()
                        .map(F::Extension::from_basefield)
                        .collect(),
                };

                Some((first_batch, last_batch))
            }
            (None, None) => None,
            _ => panic!("ctl_zs_first.is_some() != ctl_zs_last.is_some()"),
        };

        let mut batches = vec![zeta_batch, zeta_next_batch];
        if let Some((first_batch, last_batch)) = ctl_first_last_batches {
            batches.push(first_batch);
            batches.push(last_batch);
        }

        FriOpenings { batches }
    }
}

pub struct StarkOpeningSetTarget<const D: usize> {
    pub local_values: Vec<ExtensionTarget<D>>,
    pub next_values: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs_next: Vec<ExtensionTarget<D>>,
    pub quotient_polys: Vec<ExtensionTarget<D>>,
}

impl<const D: usize> StarkOpeningSetTarget<D> {
    pub(crate) fn to_fri_openings(&self, zero: Target) -> FriOpeningsTarget<D> {
        let zeta_batch = FriOpeningBatchTarget {
            values: self
                .local_values
                .iter()
                .chain(&self.permutation_ctl_zs)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatchTarget {
            values: self
                .next_values
                .iter()
                .chain(&self.permutation_ctl_zs_next)
                .copied()
                .collect_vec(),
        };
        // debug_assert!(!self.ctl_zs_last.is_empty());
        // let ctl_last_batch = FriOpeningBatchTarget {
        //     values: self
        //         .ctl_zs_last
        //         .iter()
        //         .copied()
        //         .map(|t| t.to_ext_target(zero))
        //         .collect(),
        // };

        FriOpeningsTarget {
            batches: vec![zeta_batch, zeta_next_batch],
        }
    }
}
