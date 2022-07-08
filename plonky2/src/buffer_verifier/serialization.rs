use std::io::Result as IoResult;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    buffer_verifier::{
        buf::Buffer, circuit_buf::NUM_CIRCUIT_BUF_OFFSETS, proof_buf::NUM_PROOF_BUF_OFFSETS,
    },
    gates::gate::GateBox,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{GenericConfig, Hasher},
        proof::{Proof, ProofWithPublicInputs},
    },
};

pub fn serialize_proof_with_pis<'a, C: GenericConfig<D>, const D: usize>(
    buf: &'a mut [u8],
    proof: &ProofWithPublicInputs<C::F, C, D>,
) -> IoResult<()> {
    serialize_proof(buf, &proof.proof, proof.public_inputs.as_slice())
}

pub fn serialize_proof<'a, C: GenericConfig<D>, const D: usize>(
    buf: &'a mut [u8],
    proof: &Proof<C::F, C, D>,
    pis: &[C::F],
) -> IoResult<()> {
    let mut buf = Buffer::new(buf);

    // start after the place where len goes
    buf.0.set_position(std::mem::size_of::<u64>() as u64);

    let mut val_offset = NUM_PROOF_BUF_OFFSETS * std::mem::size_of::<u64>() as usize;

    // write pis_hash_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += C::InnerHasher::HASH_SIZE;

    // write pis_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * (1 + pis.len());

    // write wires_cap_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += C::Hasher::HASH_SIZE * proof.wires_cap.0.len();

    // write zs_pp_cap_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += C::Hasher::HASH_SIZE * proof.wires_cap.0.len();

    // write quotient_polys_cap_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += C::Hasher::HASH_SIZE * proof.quotient_polys_cap.0.len();

    // write constants_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.constants.len();

    // write plonk_sigmas_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.plonk_sigmas.len();

    // write wires_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.wires.len();

    // write plonk_zs_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.plonk_zs.len();

    // write_pps_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.partial_products.len();

    // write quotient_polys_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.quotient_polys.len();

    // write plonk_zs_next_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * D * proof.openings.plonk_zs_next.len();

    // write fri_pow_witness_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write fri_commit_phase_merkle_caps_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write fri_commit_phase_merkle_caps
    let fri_query_round_proofs_offset_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.write_fri_commit_phase_merkle_caps::<C::F, C, D>(
        proof.opening_proof.commit_phase_merkle_caps.as_slice(),
    )?;
    val_offset = buf.0.position() as usize;
    buf.0.set_position(fri_query_round_proofs_offset_offset);

    // write fri_query_round_proofs_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write fri_query_round_proofs
    let fri_final_poly_offset_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.write_fri_query_rounds::<C::F, C, D>(proof.opening_proof.query_round_proofs.as_slice())?;
    val_offset = buf.0.position() as usize;
    buf.0.set_position(fri_final_poly_offset_offset);

    // write fri_final_poly_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write fri_final_poly
    let challenge_offsets_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.write_field_ext_vec::<C::F, D>(proof.opening_proof.final_poly.coeffs.as_slice())?;
    val_offset = buf.0.position() as usize;
    buf.0.set_position(challenge_offsets_offset);

    // write all challenge & fri_instance offsets - 9 in total
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write len
    let val_start = buf.0.position() as usize;
    buf.0.set_position(0);
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    let len = val_offset;

    // skip pis_hash
    buf.0
        .set_position((val_start + C::Hasher::HASH_SIZE) as u64);

    // write pis
    buf.0.write_u64::<LittleEndian>(pis.len() as u64)?;
    buf.write_field_vec(pis)?;

    // write caps
    buf.write_merkle_cap(&proof.wires_cap)?;
    buf.write_merkle_cap(&proof.plonk_zs_partial_products_cap)?;
    buf.write_merkle_cap(&proof.quotient_polys_cap)?;

    // write openings
    buf.write_field_ext_vec::<C::F, D>(proof.openings.constants.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.plonk_sigmas.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.wires.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.plonk_zs.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.partial_products.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.quotient_polys.as_slice())?;
    buf.write_field_ext_vec::<C::F, D>(proof.openings.plonk_zs_next.as_slice())?;
    buf.write_field(proof.opening_proof.pow_witness)?;

    Ok(())
}

pub fn serialize_circuit_data<'a, C: GenericConfig<D>, const D: usize>(
    buf: &'a mut [u8],
    common_data: &CommonCircuitData<C::F, C, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> IoResult<()> {
    let mut buf = Buffer::new(buf);

    // start after the place where the len goes
    buf.0.set_position(std::mem::size_of::<u64>() as u64);
    let mut val_offset = NUM_CIRCUIT_BUF_OFFSETS * std::mem::size_of::<u64>() as usize;

    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += C::Hasher::HASH_SIZE;

    // write num_pis_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write num_challenges_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write num_constants_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write num_gate_constraints_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write gates_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    let selectors_info_offset_offset = buf.0.position();

    // write gates
    buf.0.set_position(val_offset as u64);
    let gates_boxed = common_data
        .gates
        .iter()
        .map(|g| GateBox::from_dyn_gate(g.as_ref()))
        .collect::<Vec<_>>();
    buf.write_gates::<C, D>(gates_boxed.as_slice())?;
    let selectors_info_offset = buf.0.position();

    // write selectors_info_offset
    buf.0.set_position(selectors_info_offset_offset);
    buf.0.write_u64::<LittleEndian>(selectors_info_offset)?;
    let degree_bits_offset_offset = buf.0.position();

    // write selector info
    buf.0.set_position(selectors_info_offset);
    buf.0
        .write_u64::<LittleEndian>(common_data.selectors_info.selector_indices.len() as u64)?;
    buf.write_usize_vec(common_data.selectors_info.selector_indices.as_slice())?;
    buf.0
        .write_u64::<LittleEndian>(common_data.selectors_info.groups.len() as u64)?;
    buf.write_range_vec(common_data.selectors_info.groups.as_slice())?;
    let degree_bits_offset = buf.0.position();

    // write degree_bits_offset
    buf.0.set_position(degree_bits_offset_offset);
    val_offset = degree_bits_offset as usize;

    buf.0.write_u64::<LittleEndian>(degree_bits_offset)?;
    val_offset += std::mem::size_of::<u64>();

    // write num_wires_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write_num_routed_wires_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write k_is_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>() * common_data.config.num_routed_wires;

    // write num_partial_products_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write quotient_degree_factor_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write cap_height_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write fri_is_hiding_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u8>();

    // write sigmas_cap_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write sigmas_cap
    let fri_rate_bits_offset_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.write_merkle_cap::<C::F, C::Hasher>(&verifier_data.constants_sigmas_cap)?;
    let fri_hiding_offset = buf.0.position();
    val_offset = fri_hiding_offset as usize;
    buf.0.set_position(fri_rate_bits_offset_offset);

    // write fri_degree_bits_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write fri_rate_bits_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write fri_proof_of_work_bits_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u32>();

    // write fri_num_query_rounds_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;
    val_offset += std::mem::size_of::<u64>();

    // write fri_reduction_arity_bits_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write fri_reduction_arity_bits
    let fri_reduction_strategy_offset_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.0
        .write_u64::<LittleEndian>(common_data.fri_params.reduction_arity_bits.len() as u64)?;
    buf.write_usize_vec(common_data.fri_params.reduction_arity_bits.as_slice())?;
    val_offset = buf.0.position() as usize;
    buf.0.set_position(fri_reduction_strategy_offset_offset);

    // write fri_reduction_strategy_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write fri_reduction_strategy
    let fri_instance_offset_offset = buf.0.position();
    buf.0.set_position(val_offset as u64);
    buf.write_fri_reduction_strategy(&common_data.fri_params.config.reduction_strategy)?;
    val_offset = buf.0.position() as usize;
    buf.0.set_position(fri_instance_offset_offset);

    // write fri_instance_offset
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write len to reflect initially-empty fri instance
    buf.0.set_position(0);
    buf.0.write_u64::<LittleEndian>(val_offset as u64)?;

    // write non-gate, non-selector, non-fri_reduction_strategy values
    buf.0
        .set_position((NUM_CIRCUIT_BUF_OFFSETS * std::mem::size_of::<u64>()) as u64);

    buf.write_hash::<C::F, C::Hasher>(common_data.circuit_digest)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.num_public_inputs as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.config.num_challenges as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.num_constants as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.num_gate_constraints as u64)?;

    // skip over gates and selector info
    buf.0.set_position(degree_bits_offset);

    buf.0
        .write_u64::<LittleEndian>(common_data.degree_bits as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.config.num_wires as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.config.num_routed_wires as u64)?;
    buf.write_field_vec::<C::F>(common_data.k_is.as_slice())?;
    buf.0
        .write_u64::<LittleEndian>(common_data.num_partial_products as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.quotient_degree_factor as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.fri_params.config.cap_height as u64)?;
    buf.0.write_u8(common_data.fri_params.hiding as u8)?;

    // skip over sigmas_cap
    buf.0.set_position(fri_hiding_offset);
    buf.0
        .write_u64::<LittleEndian>(common_data.fri_params.degree_bits as u64)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.fri_params.config.rate_bits as u64)?;
    buf.0
        .write_u32::<LittleEndian>(common_data.fri_params.config.proof_of_work_bits)?;
    buf.0
        .write_u64::<LittleEndian>(common_data.fri_params.config.num_query_rounds as u64)?;

    Ok(())
}
