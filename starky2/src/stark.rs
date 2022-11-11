use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::fri::structure::{
    FriBatchInfo, FriBatchInfoTarget, FriInstanceInfo, FriInstanceInfoTarget, FriOracleInfo,
    FriPolynomialInfo,
};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_util::ceil_div_usize;

use crate::config::StarkConfig;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::permutation::PermutationPair;
use crate::ro_memory::RoMemoryDescriptor;
use crate::vars::StarkEvaluationTargets;
use crate::vars::StarkEvaluationVars;

/// Represents a STARK system.
pub trait Stark<F: RichField + Extendable<D>, const D: usize>: Sync {
    /// The total number of columns in the trace.
    const COLUMNS: usize;
    /// The number of public inputs.
    const PUBLIC_INPUTS: usize;

    /// Evaluate constraints at a vector of points.
    ///
    /// The points are elements of a field `FE`, a degree `D2` extension of `F`. This lets us
    /// evaluate constraints over a larger domain if desired. This can also be called with `FE = F`
    /// and `D2 = 1`, in which case we are using the trivial extension, i.e. just evaluating
    /// constraints over `F`.
    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    /// Evaluate constraints at a vector of points from the base field `F`.
    fn eval_packed_base<P: PackedField<Scalar = F>>(
        &self,
        vars: StarkEvaluationVars<F, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) {
        self.eval_packed_generic(vars, yield_constr)
    }

    /// Evaluate constraints at a single point from the degree `D` extension field.
    fn eval_ext(
        &self,
        vars: StarkEvaluationVars<
            F::Extension,
            F::Extension,
            { Self::COLUMNS },
            { Self::PUBLIC_INPUTS },
        >,
        yield_constr: &mut ConstraintConsumer<F::Extension>,
    ) {
        self.eval_packed_generic(vars, yield_constr)
    }

    /// Evaluate constraints at a vector of points from the degree `D` extension field. This is like
    /// `eval_ext`, except in the context of a recursive circuit.
    /// Note: constraints must be added through`yeld_constr.constraint(builder, constraint)` in the
    /// same order as they are given in `eval_packed_generic`.
    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    );

    /// The maximum constraint degree.
    fn constraint_degree(&self) -> usize;

    /// The maximum constraint degree.
    fn quotient_degree_factor(&self) -> usize {
        1.max(self.constraint_degree() - 1)
    }

    fn num_quotient_polys(&self, config: &StarkConfig) -> usize {
        self.quotient_degree_factor() * config.num_challenges
    }

    /// Computes the FRI instance used to prove this Stark.
    fn fri_instance(
        &self,
        zeta: F::Extension,
        g: F,
        degree_bits: usize,
        num_ctl_zs: usize,
        config: &StarkConfig,
    ) -> FriInstanceInfo<F, D> {
        let mut oracle_indices = 0..;

        let trace_info =
            FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..Self::COLUMNS);
        let trace_oracle = FriOracleInfo {
            num_polys: Self::COLUMNS,
            blinding: false,
        };

        let ro_memory_oracle_info = if let Some(descriptors) = self.ro_memory_descriptors() {
            let num_ro_memory_challenges = config.num_challenges;
            let num_ro_memory_polys = descriptors.len() * num_ro_memory_challenges;
            let info = FriPolynomialInfo::from_range(
                oracle_indices.next().unwrap(),
                0..num_ro_memory_polys,
            );

            let oracle = FriOracleInfo {
                num_polys: num_ro_memory_polys,
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let permutation_oracle_info = if self.uses_permutation_args() {
            let info = FriPolynomialInfo::from_range(
                oracle_indices.next().unwrap(),
                0..self.num_permutation_batches(config),
            );
            let oracle = FriOracleInfo {
                num_polys: self.num_permutation_batches(config),
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let ctl_zs_oracle_info = if num_ctl_zs > 0 {
            let info = FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..num_ctl_zs);
            let oracle = FriOracleInfo {
                num_polys: num_ctl_zs,
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let num_quotient_polys = self.num_quotient_polys(config);
        let quotient_info =
            FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..num_quotient_polys);

        let quotient_oracle = FriOracleInfo {
            num_polys: num_quotient_polys,
            blinding: false,
        };

        let zeta_batch = FriBatchInfo {
            point: zeta,
            polynomials: std::iter::once(&trace_info)
                .chain(ro_memory_oracle_info.as_ref().map(|(_, info)| info))
                .chain(permutation_oracle_info.as_ref().map(|(_, info)| info))
                .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| info))
                .chain(std::iter::once(&quotient_info))
                .flat_map(|info| info.iter().cloned())
                .collect_vec(),
        };
        let zeta_next_batch = FriBatchInfo {
            point: zeta.scalar_mul(g),
            polynomials: std::iter::once(&trace_info)
                .chain(ro_memory_oracle_info.as_ref().map(|(_, info)| info))
                .chain(permutation_oracle_info.as_ref().map(|(_, info)| info))
                .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| info))
                .flat_map(|info| info.iter().cloned())
                .collect(),
        };

        let oracles = std::iter::once(trace_oracle)
            .chain(ro_memory_oracle_info.map(|(oracle, _)| oracle))
            .chain(permutation_oracle_info.map(|(oracle, _)| oracle))
            .chain(
                ctl_zs_oracle_info
                    .as_ref()
                    .map(|(oracle, _)| *oracle),
            )
            .chain(std::iter::once(quotient_oracle))
            .collect_vec();

        let batches = std::iter::once(zeta_batch)
            .chain(std::iter::once(zeta_next_batch))
            .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| FriBatchInfo {
                point: F::Extension::ONE,
                polynomials: info.clone(),
            }))
            .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| FriBatchInfo {
                point: F::Extension::primitive_root_of_unity(degree_bits).inverse(),
                polynomials: info.clone(),
            }))
            .collect_vec();

        FriInstanceInfo { oracles, batches }
    }

    /// Computes the FRI instance used to prove this Stark.
    fn fri_instance_target(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        zeta: ExtensionTarget<D>,
        g: F,
        degree_bits: usize,
        config: &StarkConfig,
        num_ctl_zs: usize,
    ) -> FriInstanceInfoTarget<D> {
        let mut oracle_indices = 0..;

        let trace_info =
            FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..Self::COLUMNS);
        let trace_oracle = FriOracleInfo {
            num_polys: Self::COLUMNS,
            blinding: false,
        };

        let ro_memory_oracle_info = if let Some(descriptors) = self.ro_memory_descriptors() {
            let num_ro_memory_challenges = config.num_challenges;
            let num_ro_memory_polys = descriptors.len() * num_ro_memory_challenges;
            let info = FriPolynomialInfo::from_range(
                oracle_indices.next().unwrap(),
                0..num_ro_memory_polys,
            );

            let oracle = FriOracleInfo {
                num_polys: num_ro_memory_polys,
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let permutation_oracle_info = if self.uses_permutation_args() {
            let info = FriPolynomialInfo::from_range(
                oracle_indices.next().unwrap(),
                0..self.num_permutation_batches(config),
            );
            let oracle = FriOracleInfo {
                num_polys: self.num_permutation_batches(config),
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let ctl_zs_oracle_info = if num_ctl_zs > 0 {
            let info = FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..num_ctl_zs);
            let oracle = FriOracleInfo {
                num_polys: num_ctl_zs,
                blinding: false,
            };
            Some((oracle, info))
        } else {
            None
        };

        let num_quotient_polys = self.num_quotient_polys(config);
        let quotient_info =
            FriPolynomialInfo::from_range(oracle_indices.next().unwrap(), 0..num_quotient_polys);

        let quotient_oracle = FriOracleInfo {
            num_polys: num_quotient_polys,
            blinding: false,
        };

        let zeta_batch = FriBatchInfoTarget {
            point: zeta,
            polynomials: std::iter::once(&trace_info)
                .chain(ro_memory_oracle_info.as_ref().map(|(_, info)| info))
                .chain(permutation_oracle_info.as_ref().map(|(_, info)| info))
                .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| info))
                .chain(std::iter::once(&quotient_info))
                .flat_map(|info| info.iter().cloned())
                .collect_vec(),
        };
        let zeta_next = builder.mul_const_extension(g, zeta);
        let zeta_next_batch = FriBatchInfoTarget {
            point: zeta_next,
            polynomials: std::iter::once(&trace_info)
                .chain(ro_memory_oracle_info.as_ref().map(|(_, info)| info))
                .chain(permutation_oracle_info.as_ref().map(|(_, info)| info))
                .chain(ctl_zs_oracle_info.as_ref().map(|(_, info)| info))
                .flat_map(|info| info.iter().cloned())
                .collect(),
        };

        let oracles = std::iter::once(trace_oracle)
            .chain(ro_memory_oracle_info.map(|(oracle, _)| oracle))
            .chain(permutation_oracle_info.map(|(oracle, _)| oracle))
            .chain(
                ctl_zs_oracle_info
                    .as_ref()
                    .map(|(oracle, _)| *oracle),
            )
            .chain(std::iter::once(quotient_oracle))
            .collect_vec();

        let batches = std::iter::once(zeta_batch)
            .chain(std::iter::once(zeta_next_batch))
            .chain(
                ctl_zs_oracle_info
                    .as_ref()
                    .map(|(_, info)| FriBatchInfoTarget {
                        point: builder.constant_extension(F::Extension::ONE),
                        polynomials: info.clone(),
                    }),
            )
            .chain(
                ctl_zs_oracle_info
                    .as_ref()
                    .map(|(_, info)| FriBatchInfoTarget {
                        point: builder.constant_extension(
                            F::Extension::primitive_root_of_unity(degree_bits).inverse(),
                        ),
                        polynomials: info.clone(),
                    }),
            )
            .collect_vec();

        FriInstanceInfoTarget { oracles, batches }
    }

    fn ro_memory_descriptors(&self) -> Option<Vec<RoMemoryDescriptor>> {
        None
    }

    fn uses_ro_memory_args(&self) -> bool {
        self.ro_memory_descriptors().is_some()
    }

    /// Pairs of lists of columns that should be permutations of one another. A permutation argument
    /// will be used for each such pair. Empty by default.
    fn permutation_pairs(&self) -> Vec<PermutationPair> {
        vec![]
    }

    fn uses_permutation_args(&self) -> bool {
        !self.permutation_pairs().is_empty()
    }

    /// The number of permutation argument instances that can be combined into a single constraint.
    fn permutation_batch_size(&self) -> usize {
        // The permutation argument constraints look like
        //     Z(x) \prod(...) = Z(g x) \prod(...)
        // where each product has a number of terms equal to the batch size. So our batch size
        // should be one less than our constraint degree, which happens to be our quotient degree.
        self.quotient_degree_factor()
    }

    fn num_permutation_instances(&self, config: &StarkConfig) -> usize {
        self.permutation_pairs().len() * config.num_challenges
    }

    fn num_permutation_batches(&self, config: &StarkConfig) -> usize {
        ceil_div_usize(
            self.num_permutation_instances(config),
            self.permutation_batch_size(),
        )
    }
}
