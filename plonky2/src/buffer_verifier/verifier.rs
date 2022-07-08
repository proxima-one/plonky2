use anyhow::{ensure, Result};
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;

use super::circuit_buf::CircuitBuf;
use super::proof_buf::ProofBuf;
use crate::buffer_verifier::fri_verifier::{
    fri_verifier_query_round, fri_verify_proof_of_work, precompute_reduced_evals, get_fri_instance,
};
use crate::buffer_verifier::get_challenges::get_challenges;
use crate::buffer_verifier::vanishing_poly::eval_vanishing_poly;
use crate::fri::proof::FriChallenges;
use crate::fri::verifier::verify_fri_proof;
use crate::hash::hash_types::RichField;
use crate::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use crate::plonk::config::{GenericConfig, Hasher};
use crate::plonk::plonk_common::reduce_with_powers;
use crate::plonk::proof::{OpeningSet, Proof, ProofChallenges};
use crate::plonk::vars::EvaluationVars;

pub fn verify<'a, 'b, C: GenericConfig<D>, const D: usize>(
    proof_buf: &mut ProofBuf<C, &'a mut [u8], D>,
    circuit_buf: &mut CircuitBuf<C, &'b [u8], D>,
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let pis = proof_buf.read_pis()?;
    let num_pis = circuit_buf.read_num_pis()?;

    ensure!(
        pis.len() == num_pis,
        "Number of public inputs doesn't match circuit data."
    );

    let pis_hash =
        <<C as GenericConfig<D>>::InnerHasher as Hasher<C::F>>::hash_no_pad(pis.as_slice());
    let cap_height = circuit_buf.read_cap_height()?;
    let wires_cap = proof_buf.read_wires_cap(cap_height)?;
    let plonk_zs_partial_products_cap = proof_buf.read_zs_pp_cap(cap_height)?;
    let quotient_polys_cap = proof_buf.read_quotient_polys_cap(cap_height)?;

    let num_constants = circuit_buf.read_num_constants()?;
    let num_routed_wires = circuit_buf.read_num_routed_wires()?;
    let num_wires = circuit_buf.read_num_wires()?;
    let num_challenges = circuit_buf.read_num_challenges()?;
    let num_partial_products = circuit_buf.read_num_partial_products()?;
    let quotient_degree_factor = circuit_buf.read_quotient_degree_factor()?;

    let constants = proof_buf.read_constants_openings(num_constants)?;
    let plonk_sigmas = proof_buf.read_plonk_sigmas_openings(num_routed_wires)?;
    let wires = proof_buf.read_wires_openings(num_wires)?;
    let plonk_zs = proof_buf.read_plonk_zs_openings(num_challenges)?;
    let partial_products = proof_buf.read_pps_openings(num_partial_products, num_challenges)?;
    let quotient_polys =
        proof_buf.read_quotient_polys_openings(quotient_degree_factor, num_challenges)?;
    let plonk_zs_next = proof_buf.read_plonk_zs_next_openings(num_challenges)?;

    let openings = OpeningSet {
        constants,
        plonk_sigmas,
        wires,
        plonk_zs,
        partial_products,
        quotient_polys,
        plonk_zs_next,
    };

    let fri_reduction_arity_bits = circuit_buf.read_fri_reduction_arity_bits()?;
    let fri_commit_phase_merkle_caps =
        proof_buf.read_fri_commit_phase_merkle_caps(fri_reduction_arity_bits.len(), cap_height)?;
    let fri_final_poly = proof_buf.read_fri_final_poly(fri_reduction_arity_bits.len())?;
    let fri_pow_witness = proof_buf.read_fri_pow_witness()?;
    let circuit_digest = circuit_buf.read_circuit_digest()?;
    let degree_bits = circuit_buf.read_degree_bits()?;
    let fri_num_query_rounds = circuit_buf.read_fri_num_query_rounds()?;
    let fri_rate_bits = circuit_buf.read_fri_rate_bits()?;

    let challenges = get_challenges::<C::F, C, D>(
        pis_hash,
        &wires_cap,
        &plonk_zs_partial_products_cap,
        &quotient_polys_cap,
        &openings,
        fri_commit_phase_merkle_caps.as_slice(),
        &fri_final_poly,
        fri_pow_witness,
        circuit_digest,
        degree_bits,
        num_challenges,
        fri_num_query_rounds,
        fri_rate_bits,
    )?;

    proof_buf.write_challenges(&challenges)?;

    let num_gate_constraints = circuit_buf.read_num_gate_constraints()?;
    verify_constraints(
        proof_buf,
        circuit_buf,
        &challenges,
        &openings,
        pis_hash,
        degree_bits,
        quotient_degree_factor,
        num_partial_products,
        num_gate_constraints,
        num_routed_wires,
        num_challenges,
    )?;

    let fri_pow_response = proof_buf.read_fri_pow_response()?;
    let fri_pow_bits = circuit_buf.read_fri_proof_of_work_bits()?;
    fri_verify_proof_of_work(fri_pow_response, fri_pow_bits)?;

    let fri_openings = openings.to_fri_openings();
    let precomputed_reduced_evals =
        precompute_reduced_evals::<C::F, D>(&fri_openings, challenges.fri_challenges.fri_alpha);

    let fri_instance = get_fri_instance(
        num_constants,
        num_wires,
        num_routed_wires,
        num_challenges,
        num_partial_products,
        quotient_degree_factor,
        degree_bits,
        challenges.plonk_zeta
    );
    proof_buf.write_fri_instance(&fri_instance)?;

    let fri_alpha = proof_buf.read_fri_alpha()?;
    let fri_betas = proof_buf.read_fri_betas(fri_reduction_arity_bits.len())?;

    let fri_query_indices = proof_buf.read_fri_query_indices(fri_num_query_rounds)?;
    let constants_sigmas_cap = circuit_buf.read_sigmas_cap(cap_height)?;
    let hiding = circuit_buf.read_fri_is_hiding()?;
    let fri_degree_bits = circuit_buf.read_fri_degree_bits()?;

    let initial_merkle_caps = &[
        constants_sigmas_cap,
        wires_cap,
        plonk_zs_partial_products_cap,
        quotient_polys_cap,
    ];

    for round in 0..fri_num_query_rounds {
        let x_index = fri_query_indices[round];
        let round_proof = proof_buf.read_fri_query_round_proof(
            round,
            hiding,
            num_constants,
            num_routed_wires,
            num_wires,
            num_challenges,
            num_partial_products,
            quotient_degree_factor,
            fri_reduction_arity_bits.as_slice(),
        )?;

        let lde_bits = fri_degree_bits + fri_rate_bits;
        let lde_size = 1 << lde_bits;

        // fri_verifier_query_round::<C::F, C, D>(
        //     &fri_instance,
        //     &precomputed_reduced_evals,
        //     initial_merkle_caps,
        //     &fri_commit_phase_merkle_caps,
        //     &fri_final_poly,
        //     &round_proof,
        //     fri_alpha,
        //     fri_betas.as_slice(),
        //     fri_reduction_arity_bits.as_slice(),
        //     x_index,
        //     lde_size,
        //     hiding,
        // )?;
    }

    Ok(())
}

pub fn verify_constraints<'a, 'b, C: GenericConfig<D>, const D: usize>(
    proof_buf: &mut ProofBuf<C, &'a mut [u8], D>,
    circuit_buf: &mut CircuitBuf<C, &'b [u8], D>,
    challenges: &ProofChallenges<C::F, D>,
    openings: &OpeningSet<C::F, D>,
    pis_hash: <<C as GenericConfig<D>>::InnerHasher as Hasher<C::F>>::Hash,
    degree_bits: usize,
    quotient_degree_factor: usize,
    num_partial_products: usize,
    num_gate_constraints: usize,
    num_routed_wires: usize,
    num_challenges: usize,
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let vars = EvaluationVars {
        local_constants: &openings.constants,
        local_wires: &openings.wires,
        public_inputs_hash: &pis_hash,
    };

    let local_zs = &openings.plonk_zs;
    let next_zs = &openings.plonk_zs_next;
    let s_sigmas = &openings.plonk_sigmas;
    let partial_products = &openings.partial_products;

    // Evaluate the vanishing polynomial at our challenge point, zeta.
    let k_is = circuit_buf.read_k_is(num_routed_wires)?;
    let selectors_info = circuit_buf.read_selectors_info()?;
    let gates = circuit_buf.read_gates()?;
    let vanishing_polys_zeta = eval_vanishing_poly::<C::F, C, D>(
        challenges.plonk_zeta,
        vars,
        local_zs,
        next_zs,
        partial_products,
        s_sigmas,
        &challenges.plonk_betas,
        &challenges.plonk_gammas,
        &challenges.plonk_alphas,
        gates.as_slice(),
        &selectors_info,
        k_is.as_slice(),
        degree_bits,
        quotient_degree_factor,
        num_partial_products,
        num_gate_constraints,
        num_challenges,
        num_routed_wires,
    );

    // Check each polynomial identity, of the form `vanishing(x) = Z_H(x) quotient(x)`, at zeta.
    let quotient_polys_zeta = &openings.quotient_polys;
    let zeta_pow_deg = challenges.plonk_zeta.exp_power_of_2(degree_bits);
    let z_h_zeta = zeta_pow_deg - C::FE::ONE;
    // `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
    // Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
    // where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
    // So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
    // `quotient_degree_factor`-sized chunk of the original evaluations.
    for (i, chunk) in quotient_polys_zeta
        .chunks(quotient_degree_factor)
        .enumerate()
    {
        ensure!(vanishing_polys_zeta[i] == z_h_zeta * reduce_with_powers(chunk, zeta_pow_deg));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use log::{info, Level};
    use plonky2_field::extension::Extendable;
    
    use super::*;
    use crate::{
        buffer_verifier::{
            fri_verifier::get_final_poly_len, serialization::{serialize_proof_with_pis, serialize_circuit_data},
        },
        gates::noop::NoopGate,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
            prover::prove,
        },
        util::timing::TimingTree,
    };
    
    type ProofTuple<F, C, const D: usize> = (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
        CommonCircuitData<F, C, D>,
    );

    /// Creates a dummy proof which should have `2 ** log2_size` rows.
    fn dummy_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        config: &CircuitConfig,
        log2_size: usize,
    ) -> Result<ProofTuple<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        // 'size' is in degree, but we want number of noop gates. A non-zero amount of padding will be added and size will be rounded to the next power of two. To hit our target size, we go just under the previous power of two and hope padding is less than half the proof.
        let num_dummy_gates = match log2_size {
            0 => return Err(anyhow!("size must be at least 1")),
            1 => 0,
            2 => 1,
            n => (1 << (n - 1)) + 1,
        };
        info!("Constructing inner proof with {} gates", num_dummy_gates);
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for _ in 0..num_dummy_gates {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.print_gate_counts(0);

        let data = builder.build::<C>();
        let inputs = PartialWitness::new();

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
        timing.print();
        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }

    #[test]
    fn test_buffer_verifier() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let (proof, verifier_data, common_data) =
            dummy_proof::<F, C, D>(&CircuitConfig::default(), 10)?;
        
        let mut proof_bytes = vec![0u8; 200_000];
        let mut circuit_bytes = vec![0u8; 200_000];
        serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof)?;
        serialize_circuit_data(circuit_bytes.as_mut_slice(), &common_data, &verifier_data)?;
        let mut proof_buf = ProofBuf::<C, &mut [u8], D>::new(proof_bytes.as_mut_slice())?;
        let mut circuit_buf = CircuitBuf::<C, &[u8], D>::new(circuit_bytes.as_slice())?;

        verify(&mut proof_buf, &mut circuit_buf)
    }
}