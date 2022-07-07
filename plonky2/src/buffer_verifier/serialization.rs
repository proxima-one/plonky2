use std::io::{
    Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write,
};
use std::marker::PhantomData;
use std::ops::Range;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::{Field64, PrimeField64};

use crate::fri::reduction_strategies::FriReductionStrategy;
use crate::fri::structure::{FriBatchInfo, FriInstanceInfo, FriOracleInfo, FriPolynomialInfo};
use crate::gates::arithmetic_base::ArithmeticGate;
use crate::gates::arithmetic_extension::ArithmeticExtensionGate;
use crate::gates::assert_le::AssertLessThanGate;
use crate::gates::base_sum::BaseSumGate;
use crate::gates::constant::ConstantGate;
use crate::gates::exponentiation::ExponentiationGate;
use crate::gates::gate::{Gate, GateBox};
use crate::gates::interpolation::HighDegreeInterpolationGate;
use crate::gates::low_degree_interpolation::LowDegreeInterpolationGate;
use crate::gates::multiplication_extension::MulExtensionGate;
use crate::gates::noop::NoopGate;
use crate::gates::poseidon::PoseidonGate;
use crate::gates::poseidon_mds::PoseidonMdsGate;
use crate::gates::public_input::PublicInputGate;
use crate::gates::random_access::RandomAccessGate;
use crate::gates::reducing::ReducingGate;
use crate::gates::reducing_extension::ReducingExtensionGate;
use crate::gates::selectors::SelectorsInfo;
use crate::hash::hash_types::RichField;
use crate::hash::merkle_tree::MerkleCap;
use crate::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use crate::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use crate::plonk::proof::{Proof, ProofChallenges, ProofWithPublicInputs};

#[allow(type_alias_bounds)]
type HashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

#[allow(type_alias_bounds)]
type InnerHashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::InnerHasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

pub struct ProofBuf<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> {
    buf: Buffer<R>,
    offsets: ProofBufOffsets,
    _phantom: PhantomData<C>,
}

#[derive(Debug, Clone, Copy)]
struct ProofBufOffsets {
    len: usize,
    // this offset is set, but the hash is written by the verifier during the first step
    pis_hash_offset: usize,
    pis_offset: usize,
    wires_cap_offset: usize,
    zs_pp_cap_offset: usize,
    quotient_polys_cap_offset: usize,
    constants_offset: usize,
    plonk_sigmas_offset: usize,
    wires_offset: usize,
    plonk_zs_offset: usize,
    pps_offset: usize,
    quotient_polys_offset: usize,
    plonk_zs_next_offset: usize,
    // The following offsets should all be initially set to `plonk_zs_next_offset`.
    // once the verifier computes the challenges, they should be updated accordingly
    challenge_betas_offset: usize,
    challenge_gammas_offset: usize,
    challenge_alphas_offset: usize,
    challenge_zeta_offset: usize,
    fri_alpha_offset: usize,
    fri_pow_response_offset: usize,
    fri_betas_offset: usize,
    fri_query_indices_offset: usize,
    fri_instance_offset: usize,
}

const NUM_PROOF_BUF_OFFSETS: usize = 22;

// TODO: check to ensure offsets are valid and return a IoResult
fn get_proof_buf_offsets<R: AsRef<[u8]>>(buf: &mut Buffer<R>) -> IoResult<ProofBufOffsets> {
    let len = buf.0.read_u64::<LittleEndian>()? as usize;
    let pis_hash_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let pis_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let wires_cap_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let zs_pp_cap_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let quotient_polys_cap_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let constants_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let plonk_sigmas_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let wires_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let plonk_zs_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let pps_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let quotient_polys_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let plonk_zs_next_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let challenge_betas_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let challenge_gammas_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let challenge_alphas_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let challenge_zeta_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_alpha_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_pow_response_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_betas_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_query_indices_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_instance_offset = buf.0.read_u64::<LittleEndian>()? as usize;

    Ok(ProofBufOffsets {
        len,
        pis_hash_offset,
        pis_offset,
        wires_cap_offset,
        zs_pp_cap_offset,
        quotient_polys_cap_offset,
        constants_offset,
        plonk_sigmas_offset,
        wires_offset,
        plonk_zs_offset,
        pps_offset,
        quotient_polys_offset,
        plonk_zs_next_offset,
        challenge_betas_offset,
        challenge_gammas_offset,
        challenge_alphas_offset,
        challenge_zeta_offset,
        fri_alpha_offset,
        fri_pow_response_offset,
        fri_betas_offset,
        fri_query_indices_offset,
        fri_instance_offset,
    })
}

impl<R: AsRef<[u8]>, C: GenericConfig<D>, const D: usize> ProofBuf<C, R, D> {
    pub fn new(buf: R) -> IoResult<Self> {
        let buf = Buffer::new(buf);
        Self::from_buffer(buf)
    }

    pub fn from_buffer(mut buf: Buffer<R>) -> IoResult<Self> {
        let offsets = get_proof_buf_offsets(&mut buf)?;
        Ok(ProofBuf {
            buf,
            offsets,
            _phantom: PhantomData,
        })
    }

    pub fn len(&mut self) -> usize {
        self.offsets.len
    }

    pub fn read_pis_hash(&mut self) -> IoResult<InnerHashForConfig<C, D>> {
        self.buf.0.set_position(self.offsets.pis_hash_offset as u64);
        self.buf.read_hash::<C::F, C::InnerHasher>()
    }

    pub fn read_pis(&mut self) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.pis_offset as u64);
        let len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        self.buf.read_field_vec::<C::F>(len)
    }

    pub fn read_wires_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf
            .0
            .set_position(self.offsets.wires_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_zs_pp_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf
            .0
            .set_position(self.offsets.zs_pp_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_quotient_polys_cap(
        &mut self,
        cap_height: usize,
    ) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf
            .0
            .set_position(self.offsets.quotient_polys_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_constants_openings(&mut self, num_constants: usize) -> IoResult<Vec<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.constants_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_constants)
    }

    pub fn read_plonk_sigmas_openings(&mut self, num_routed_wires: usize) -> IoResult<Vec<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.plonk_sigmas_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_routed_wires)
    }

    pub fn read_wires_openings(&mut self, num_wires: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.wires_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_wires)
    }

    pub fn read_plonk_zs_openings(&mut self, num_challenges: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.plonk_zs_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_challenges)
    }

    pub fn read_plonk_zs_next_openings(&mut self, num_challenges: usize) -> IoResult<Vec<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.plonk_zs_next_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_challenges)
    }

    pub fn read_pps_openings(
        &mut self,
        num_partial_products: usize,
        num_challenges: usize,
    ) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.pps_offset as u64);
        self.buf
            .read_field_ext_vec::<C::F, D>(num_partial_products * num_challenges)
    }

    pub fn read_quotient_polys_openings(
        &mut self,
        quotient_degree_factor: usize,
        num_challenges: usize,
    ) -> IoResult<Vec<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.quotient_polys_offset as u64);
        self.buf
            .read_field_ext_vec::<C::F, D>(quotient_degree_factor * num_challenges)
    }

    pub fn read_challenge_betas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf
            .0
            .set_position(self.offsets.challenge_betas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_gammas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf
            .0
            .set_position(self.offsets.challenge_gammas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_alphas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf
            .0
            .set_position(self.offsets.challenge_alphas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_zeta(&mut self) -> IoResult<C::FE> {
        self.buf.read_field_ext::<C::F, D>()
    }

    pub fn read_fri_alpha(&mut self) -> IoResult<C::FE> {
        self.buf
            .0
            .set_position(self.offsets.fri_alpha_offset as u64);
        self.buf.read_field_ext::<C::F, D>()
    }

    pub fn read_fri_pow_response(&mut self) -> IoResult<C::F> {
        self.buf.read_field()
    }

    pub fn read_fri_betas(&mut self, fri_reduction_arity_bits_len: usize) -> IoResult<Vec<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.fri_betas_offset as u64);
        self.buf
            .read_field_ext_vec::<C::F, D>(fri_reduction_arity_bits_len)
    }

    pub fn read_fri_query_indices(&mut self, num_query_rounds: usize) -> IoResult<Vec<usize>> {
        self.buf
            .0
            .set_position(self.offsets.fri_query_indices_offset as u64);
        self.buf.read_usize_vec(num_query_rounds)
    }

    pub fn read_fri_instance(&mut self) -> IoResult<FriInstanceInfo<C::F, D>> {
        self.buf
            .0
            .set_position(self.offsets.fri_instance_offset as u64);

        let num_oracles = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let mut oracles = Vec::with_capacity(num_oracles);
        for _ in 0..num_oracles {
            let oracle = self.buf.read_fri_oracle_info()?;
            oracles.push(oracle);
        }

        let num_batches = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let mut batches = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            let batch = self.buf.read_fri_batch_info::<C::F, D>()?;
            batches.push(batch);
        }

        Ok(FriInstanceInfo { oracles, batches })
    }
}

impl<'a, C: GenericConfig<D>, const D: usize> ProofBuf<C, &'a mut [u8], D> {
    pub fn write_challenges(&mut self, challenges: &ProofChallenges<C::F, D>) -> IoResult<()> {
        self.buf
            .0
            .set_position(self.offsets.challenge_betas_offset as u64);
        self.buf
            .write_field_vec(challenges.plonk_betas.as_slice())?;

        self.offsets.challenge_gammas_offset = self.buf.0.position() as usize;
        self.buf
            .write_field_vec(challenges.plonk_gammas.as_slice())?;

        self.offsets.challenge_alphas_offset = self.buf.0.position() as usize;
        self.buf
            .write_field_vec(challenges.plonk_alphas.as_slice())?;

        self.offsets.challenge_zeta_offset = self.buf.0.position() as usize;
        self.buf.write_field_ext::<C::F, D>(challenges.plonk_zeta)?;

        self.offsets.fri_alpha_offset = self.buf.0.position() as usize;
        self.buf
            .write_field_ext::<C::F, D>(challenges.fri_challenges.fri_alpha)?;

        self.offsets.fri_pow_response_offset = self.buf.0.position() as usize;
        self.buf
            .write_field(challenges.fri_challenges.fri_pow_response)?;

        self.offsets.fri_betas_offset = self.buf.0.position() as usize;
        self.buf
            .write_field_ext_vec::<C::F, D>(challenges.fri_challenges.fri_betas.as_slice())?;

        self.offsets.fri_query_indices_offset = self.buf.0.position() as usize;
        self.buf
            .write_usize_vec(challenges.fri_challenges.fri_query_indices.as_slice())?;

        self.offsets.len = self.buf.0.position() as usize;
        self.set_offsets()?;

        Ok(())
    }

    pub fn set_offsets(&mut self) -> IoResult<()> {
        self.buf.0.set_position(0);

        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.len as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.wires_cap_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.zs_pp_cap_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.quotient_polys_cap_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.constants_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.plonk_sigmas_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.wires_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.plonk_zs_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.pps_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.quotient_polys_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.plonk_zs_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.challenge_betas_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.challenge_gammas_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.challenge_alphas_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.challenge_zeta_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.fri_alpha_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.fri_pow_response_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.fri_betas_offset as u64)?;
        self.buf
            .0
            .write_u64::<LittleEndian>(self.offsets.fri_query_indices_offset as u64)?;

        Ok(())
    }

    pub fn write_pis_hash(
        &mut self,
        pis_hash: <<C as GenericConfig<D>>::InnerHasher as Hasher<C::F>>::Hash,
    ) -> IoResult<()> {
        self.buf.0.set_position(self.offsets.pis_hash_offset as u64);
        self.buf.write_hash::<C::F, C::InnerHasher>(pis_hash)
    }

    pub fn write_fri_instance(&mut self, fri_instance: &FriInstanceInfo<C::F, D>) -> IoResult<()> {
        self.buf
            .0
            .set_position(self.offsets.fri_instance_offset as u64);
        self.buf
            .0
            .write_u64::<LittleEndian>(fri_instance.oracles.len() as u64)?;
        for oracle in &fri_instance.oracles {
            self.buf.write_fri_oracle_info(oracle)?;
        }

        self.buf
            .0
            .write_u64::<LittleEndian>(fri_instance.batches.len() as u64)?;
        for batch in &fri_instance.batches {
            self.buf.write_fri_batch_info(batch)?;
        }

        let new_buf_len = self.buf.0.position();
        self.buf.0.set_position(0);
        self.buf.0.write_u64::<LittleEndian>(new_buf_len)?;

        Ok(())
    }
}

pub struct CircuitBuf<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> {
    buf: Buffer<R>,
    offsets: CircuitBufOffsets,
    _phantom: PhantomData<C>,
}

pub struct CircuitBufOffsets {
    len: usize,
    circuit_digest_offset: usize,
    num_challenges_offset: usize,
    num_constants_offset: usize,
    num_gate_constraints_offset: usize,
    gates_offset: usize,
    selectors_info_offset: usize,
    degree_bits_offset: usize,
    num_wires_offset: usize,
    num_routed_wires_offset: usize,
    k_is_offset: usize,
    num_partial_products_offset: usize,
    quotient_degree_factor_offset: usize,
    cap_height_offset: usize,
    fri_is_hiding_offset: usize,
    sigmas_cap_offset: usize,
    fri_degree_bits_offset: usize,
    fri_rate_bits_offset: usize,
    fri_proof_of_work_bits_offset: usize,
    fri_num_query_rounds_offset: usize,
    fri_reduction_arity_bits_offset: usize,
    fri_reduction_strategy_offset: usize,
}

const NUM_CIRCUIT_BUF_OFFSETS: usize = 22;

fn get_circuit_buf_offsets<R: AsRef<[u8]>>(buf: &mut Buffer<R>) -> IoResult<CircuitBufOffsets> {
    let len = buf.0.read_u64::<LittleEndian>()? as usize;
    let circuit_digest_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_challenges_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_constants_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_gate_constraints_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let gates_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let selectors_info_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let degree_bits_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_wires_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_routed_wires_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let k_is_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_partial_products_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let quotient_degree_factor_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let cap_height_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_is_hiding_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let sigmas_cap_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_degree_bits_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_rate_bits_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_proof_of_work_bits_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_num_query_rounds_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_reduction_arity_bits_offset: usize = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_reduction_strategy_offset = buf.0.read_u64::<LittleEndian>()? as usize;

    Ok(CircuitBufOffsets {
        len,
        circuit_digest_offset,
        num_challenges_offset,
        num_constants_offset,
        num_gate_constraints_offset,
        gates_offset,
        selectors_info_offset,
        degree_bits_offset,
        num_wires_offset,
        num_routed_wires_offset,
        k_is_offset,
        num_partial_products_offset,
        quotient_degree_factor_offset,
        cap_height_offset,
        fri_is_hiding_offset,
        sigmas_cap_offset,
        fri_degree_bits_offset,
        fri_rate_bits_offset,
        fri_proof_of_work_bits_offset,
        fri_num_query_rounds_offset,
        fri_reduction_arity_bits_offset,
        fri_reduction_strategy_offset,
    })
}

impl<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> CircuitBuf<C, R, D> {
    pub fn new(buf: R) -> IoResult<Self> {
        let mut buf = Buffer::new(buf);
        let offsets = get_circuit_buf_offsets(&mut buf)?;
        Ok(CircuitBuf {
            buf,
            offsets,
            _phantom: PhantomData,
        })
    }

    pub fn len(&mut self) -> usize {
        self.offsets.len
    }

    pub fn read_circuit_digest(&mut self) -> IoResult<HashForConfig<C, D>> {
        self.buf
            .0
            .set_position(self.offsets.circuit_digest_offset as u64);
        self.buf.read_hash::<C::F, C::Hasher>()
    }

    pub fn read_num_challenges(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_challenges_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_constants(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_constants_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_gate_constraints(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_gate_constraints_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_selectors_info(&mut self) -> IoResult<SelectorsInfo> {
        self.buf
            .0
            .set_position(self.offsets.selectors_info_offset as u64);
        let indices_len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let selector_indices = self.buf.read_usize_vec(indices_len)?;

        let groups_len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let groups = self.buf.read_range_vec(groups_len)?;

        Ok(SelectorsInfo {
            selector_indices,
            groups,
        })
    }

    pub fn read_gates(&mut self) -> IoResult<Vec<GateBox<C::F, D>>> {
        self.buf.0.set_position(self.offsets.gates_offset as u64);
        let num_gates = self.buf.0.read_u64::<LittleEndian>()? as usize;

        let mut gates = Vec::with_capacity(num_gates);
        for _ in 0..num_gates {
            let gate = self.buf.read_gate::<C, D>()?;
            gates.push(gate);
        }

        Ok(gates)
    }

    pub fn read_degree_bits(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.degree_bits_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_wires(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_wires_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_routed_wires(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_routed_wires_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_k_is(&mut self, num_routed_wires: usize) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.k_is_offset as u64);
        self.buf.read_field_vec(num_routed_wires)
    }

    pub fn read_num_partial_products(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.num_partial_products_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_quotient_degree_factor(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.quotient_degree_factor_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_sigmas_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf
            .0
            .set_position(self.offsets.sigmas_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_cap_height(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.cap_height_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_fri_is_hiding(&mut self) -> IoResult<bool> {
        self.buf
            .0
            .set_position(self.offsets.fri_is_hiding_offset as u64);

        self.buf.read_bool()
    }

    pub fn read_fri_degree_bits(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.fri_degree_bits_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_fri_rate_bits(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.fri_rate_bits_offset as u64);

        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_fri_proof_of_work_bits(&mut self) -> IoResult<u32> {
        self.buf
            .0
            .set_position(self.offsets.fri_proof_of_work_bits_offset as u64);
        self.buf.0.read_u32::<LittleEndian>()
    }

    pub fn read_fri_num_query_rounds(&mut self) -> IoResult<usize> {
        self.buf
            .0
            .set_position(self.offsets.fri_num_query_rounds_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_fri_reduction_arity_bits(&mut self) -> IoResult<Vec<usize>> {
        self.buf
            .0
            .set_position(self.offsets.fri_reduction_arity_bits_offset as u64);
        let len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        self.buf.read_usize_vec(len)
    }

    pub fn read_fri_reduction_strategy(&mut self) -> IoResult<FriReductionStrategy> {
        self.buf
            .0
            .set_position(self.offsets.fri_reduction_strategy_offset as u64);
        self.buf.read_fri_reduction_strategy()
    }
}

macro_rules! base_sum_match_statement {
    ( $matched_base:expr, $buf:expr, $( $base:expr ),* ) => {
        match $matched_base {
            $(
                $base => BaseSumGate::<$base>::deserialize($buf)?,
            )*
            _ => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
        }
    }
}

pub fn read_gate<C: GenericConfig<D>, const D: usize>(
    buf: &[u8],
    tag: u8,
) -> IoResult<GateBox<C::F, D>> {
    Ok(match tag {
        ARITHMETIC_BASE_TAG => ArithmeticGate::deserialize(buf)?,
        ARITHMETIC_EXT_TAG => ArithmeticExtensionGate::deserialize(buf)?,
        ASSERT_LE_TAG => AssertLessThanGate::deserialize(buf)?,
        // ! When serializing BaseSumGate, must prepend the limb base!
        BASE_SUM_TAG => {
            let base = buf[0];
            let buf = &buf[1..];

            base_sum_match_statement!(
                base, buf, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
                63, 64
            )
        }
        CONSTANT_TAG => ConstantGate::deserialize(buf)?,
        EXPONENTIATION_TAG => ExponentiationGate::deserialize(buf)?,
        INTERPOLATION_TAG => HighDegreeInterpolationGate::deserialize(buf)?,
        LOW_DEGREE_INTERPOLATION_TAG => LowDegreeInterpolationGate::deserialize(buf)?,
        MUL_EXT_TAG => MulExtensionGate::deserialize(buf)?,
        NOOP_TAG => NoopGate::deserialize(buf)?,
        POSEIDON_MDS_TAG => PoseidonMdsGate::deserialize(buf)?,
        POSEIDON_TAG => PoseidonGate::deserialize(buf)?,
        PUBLIC_INPUT_TAG => PublicInputGate::deserialize(buf)?,
        RANDOM_ACCESS_TAG => RandomAccessGate::deserialize(buf)?,
        REDUCING_EXT_TAG => ReducingExtensionGate::deserialize(buf)?,
        REDUCING_TAG => ReducingGate::deserialize(buf)?,
        _ => return Err(IoError::from(IoErrorKind::InvalidData)),
    })
}

/// returns the number of bytes written
pub fn write_gate<C: GenericConfig<D>, const D: usize>(
    buf: &mut [u8],
    gate: &dyn Gate<C::F, D>,
) -> IoResult<usize> {
    let tag = gate_kind_tag(gate.kind());
    buf[0] = tag;

    Ok(gate.serialize(&mut buf[1..])? + std::mem::size_of::<u8>())
}

// Gates supported by buffer verifier
const ARITHMETIC_BASE_TAG: u8 = 0;
const ARITHMETIC_EXT_TAG: u8 = 1;
const ASSERT_LE_TAG: u8 = 2;
const BASE_SUM_TAG: u8 = 3;
const CONSTANT_TAG: u8 = 4;
const EXPONENTIATION_TAG: u8 = 5;
const INTERPOLATION_TAG: u8 = 6;
const LOW_DEGREE_INTERPOLATION_TAG: u8 = 7;
const MUL_EXT_TAG: u8 = 8;
const NOOP_TAG: u8 = 9;
const POSEIDON_MDS_TAG: u8 = 10;
const POSEIDON_TAG: u8 = 11;
const PUBLIC_INPUT_TAG: u8 = 12;
const RANDOM_ACCESS_TAG: u8 = 13;
const REDUCING_EXT_TAG: u8 = 14;
const REDUCING_TAG: u8 = 15;

pub enum GateKind {
    ArithmeticBase,
    ArithmeticExt,
    AssertLe,
    BaseSum,
    Constant,
    Exponentiation,
    Interpolation,
    LowDegreeInterpolation,
    MulExt,
    Noop,
    PoseidonMds,
    Poseidon,
    PublicInput,
    RandomAccess,
    ReducingExt,
    Reducing,
}

fn gate_kind_tag(gate_kind: GateKind) -> u8 {
    match gate_kind {
        GateKind::ArithmeticBase => ARITHMETIC_BASE_TAG,
        GateKind::ArithmeticExt => ARITHMETIC_EXT_TAG,
        GateKind::AssertLe => ASSERT_LE_TAG,
        GateKind::BaseSum => BASE_SUM_TAG,
        GateKind::Constant => CONSTANT_TAG,
        GateKind::Exponentiation => EXPONENTIATION_TAG,
        GateKind::Interpolation => INTERPOLATION_TAG,
        GateKind::LowDegreeInterpolation => LOW_DEGREE_INTERPOLATION_TAG,
        GateKind::MulExt => MUL_EXT_TAG,
        GateKind::Noop => NOOP_TAG,
        GateKind::PoseidonMds => POSEIDON_MDS_TAG,
        GateKind::Poseidon => POSEIDON_TAG,
        GateKind::PublicInput => PUBLIC_INPUT_TAG,
        GateKind::RandomAccess => RANDOM_ACCESS_TAG,
        GateKind::ReducingExt => REDUCING_EXT_TAG,
        GateKind::Reducing => REDUCING_TAG,
    }
}

pub struct Buffer<R: AsRef<[u8]>>(pub(crate) Cursor<R>);

impl<R: AsRef<[u8]>> Buffer<R> {
    pub fn new(buffer: R) -> Self {
        Self(Cursor::new(buffer))
    }

    pub fn len(&self) -> usize {
        self.0.get_ref().as_ref().len()
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.0.get_ref().as_ref().to_vec()
    }

    pub fn read_range(&mut self) -> IoResult<Range<usize>> {
        let start = self.0.read_u64::<LittleEndian>()? as usize;
        let end = self.0.read_u64::<LittleEndian>()? as usize;
        Ok(Range { start, end })
    }

    pub fn read_bool(&mut self) -> IoResult<bool> {
        Ok(self.0.read_u8()? != 0)
    }

    fn read_field<F: Field64>(&mut self) -> IoResult<F> {
        Ok(F::from_canonical_u64(self.0.read_u64::<LittleEndian>()?))
    }

    fn read_field_ext<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> IoResult<F::Extension> {
        let mut arr = [F::ZERO; D];
        for a in arr.iter_mut() {
            *a = self.read_field()?;
        }
        Ok(<F::Extension as FieldExtension<D>>::from_basefield_array(
            arr,
        ))
    }

    fn read_hash<F: RichField, H: Hasher<F>>(&mut self) -> IoResult<H::Hash> {
        let mut buf = vec![0; H::HASH_SIZE];
        self.0.read_exact(&mut buf)?;
        Ok(H::Hash::from_bytes(&buf))
    }

    fn read_merkle_cap<F: RichField, H: Hasher<F>>(
        &mut self,
        cap_height: usize,
    ) -> IoResult<MerkleCap<F, H>> {
        let cap_length = 1 << cap_height;
        Ok(MerkleCap(
            (0..cap_length)
                .map(|_| self.read_hash::<F, H>())
                .collect::<IoResult<Vec<_>>>()?,
        ))
    }

    pub fn read_field_vec<F: Field64>(&mut self, length: usize) -> IoResult<Vec<F>> {
        (0..length)
            .map(|_| self.read_field())
            .collect::<IoResult<Vec<_>>>()
    }

    fn read_field_ext_vec<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        length: usize,
    ) -> IoResult<Vec<F::Extension>> {
        (0..length)
            .map(|_| self.read_field_ext::<F, D>())
            .collect::<IoResult<Vec<_>>>()
    }

    pub fn read_bool_vec(&mut self, len: usize) -> IoResult<Vec<bool>> {
        let mut res = Vec::with_capacity(len);
        for i in 0..len {
            res.push(self.read_bool()?);
        }

        Ok(res)
    }

    pub fn read_usize_vec(&mut self, len: usize) -> IoResult<Vec<usize>> {
        let mut res = Vec::with_capacity(len);
        for i in 0..len {
            res.push(self.0.read_u64::<LittleEndian>()? as usize);
        }

        Ok(res)
    }

    pub fn read_range_vec(&mut self, len: usize) -> IoResult<Vec<Range<usize>>> {
        let mut res = Vec::with_capacity(len);
        for i in 0..len {
            res.push(self.read_range()?);
        }

        Ok(res)
    }

    pub fn read_gate<C: GenericConfig<D>, const D: usize>(&mut self) -> IoResult<GateBox<C::F, D>> {
        let len = self.0.read_u64::<LittleEndian>()? as usize;
        let tag = self.0.read_u8()?;
        let position = self.0.position() as usize;
        let buf = self.0.get_ref().as_ref();
        let gate = read_gate::<C, D>(&buf[position..], tag)?;
        self.0.set_position(len as u64 + self.0.position() - 1);

        Ok(gate)
    }

    pub fn read_fri_reduction_strategy(&mut self) -> IoResult<FriReductionStrategy> {
        let enum_tag = self.0.read_u8()?;
        match enum_tag {
            // Fixed
            0 => {
                let arity_bitses_len = self.0.read_u64::<LittleEndian>()? as usize;
                let arity_bitses = self.read_usize_vec(arity_bitses_len)?;
                Ok(FriReductionStrategy::Fixed(arity_bitses))
            }
            // ConstantArityBits
            1 => {
                let arity_bits = self.0.read_u64::<LittleEndian>()? as usize;
                let final_poly_bits = self.0.read_u64::<LittleEndian>()? as usize;
                Ok(FriReductionStrategy::ConstantArityBits(
                    arity_bits,
                    final_poly_bits,
                ))
            }
            // MinSize
            2 => {
                let is_some_tag = self.0.read_u8()?;
                match is_some_tag {
                    0 => Ok(FriReductionStrategy::MinSize(None)),
                    1 => {
                        let min_size = self.0.read_u64::<LittleEndian>()? as usize;
                        Ok(FriReductionStrategy::MinSize(Some(min_size)))
                    }
                    _ => Err(IoError::from(IoErrorKind::InvalidData)),
                }
            }
            _ => Err(IoError::from(IoErrorKind::InvalidData)),
        }
    }

    fn read_fri_oracle_info(&mut self) -> IoResult<FriOracleInfo> {
        let blinding = self.read_bool()?;
        Ok(FriOracleInfo { blinding })
    }

    fn read_fri_polynomial_info(&mut self) -> IoResult<FriPolynomialInfo> {
        let oracle_index = self.0.read_u64::<LittleEndian>()? as usize;
        let polynomial_index = self.0.read_u64::<LittleEndian>()? as usize;
        Ok(FriPolynomialInfo {
            oracle_index,
            polynomial_index,
        })
    }

    fn read_fri_batch_info<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> IoResult<FriBatchInfo<F, D>> {
        let point = self.read_field_ext::<F, D>()?;

        let len = self.0.read_u64::<LittleEndian>()? as usize;
        let mut polynomials = Vec::with_capacity(len);
        for _ in 0..len {
            let poly_info = self.read_fri_polynomial_info()?;
            polynomials.push(poly_info);
        }

        Ok(FriBatchInfo { point, polynomials })
    }
}

impl<'a> Buffer<&'a mut [u8]> {
    fn write_field<F: PrimeField64>(&mut self, x: F) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(x.to_canonical_u64())
    }

    fn write_field_ext<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        x: F::Extension,
    ) -> IoResult<()> {
        for &a in &x.to_basefield_array() {
            self.write_field(a)?;
        }
        Ok(())
    }

    fn write_hash<F: RichField, H: Hasher<F>>(&mut self, h: H::Hash) -> IoResult<()> {
        self.0.write_all(&h.to_bytes())
    }

    fn write_merkle_cap<F: RichField, H: Hasher<F>>(
        &mut self,
        cap: &MerkleCap<F, H>,
    ) -> IoResult<()> {
        for &a in &cap.0 {
            self.write_hash::<F, H>(a)?;
        }
        Ok(())
    }

    pub fn write_field_vec<F: PrimeField64>(&mut self, v: &[F]) -> IoResult<()> {
        for &a in v {
            self.write_field(a)?;
        }
        Ok(())
    }

    fn write_field_ext_vec<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        v: &[F::Extension],
    ) -> IoResult<()> {
        for &a in v {
            self.write_field_ext::<F, D>(a)?;
        }
        Ok(())
    }

    fn write_usize_vec(&mut self, v: &[usize]) -> IoResult<()> {
        for &a in v {
            self.0.write_u64::<LittleEndian>(a as u64)?;
        }
        Ok(())
    }

    fn write_range_vec(&mut self, v: &[Range<usize>]) -> IoResult<()> {
        for &Range { start, end } in v {
            self.0.write_u64::<LittleEndian>(start as u64)?;
            self.0.write_u64::<LittleEndian>(end as u64)?;
        }
        Ok(())
    }

    fn write_gate<C: GenericConfig<D>, const D: usize>(
        &mut self,
        gate: &GateBox<C::F, D>,
    ) -> IoResult<()> {
        let position = self.0.position() as usize;
        let buf: &mut [u8] = self.0.get_mut().as_mut();
        let gate_start = position + std::mem::size_of::<u64>();
        let gate_len = write_gate::<C, D>(&mut buf[gate_start..], gate.as_ref())? as u64;
        LittleEndian::write_u64(&mut buf[position..gate_start], gate_len as u64);
        self.0.set_position(gate_start as u64 + gate_len);

        Ok(())
    }

    fn write_gates<C: GenericConfig<D>, const D: usize>(
        &mut self,
        gates: &[GateBox<C::F, D>],
    ) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(gates.len() as u64)?;
        for gate in gates {
            self.write_gate::<C, D>(gate)?;
        }

        Ok(())
    }

    pub fn write_fri_reduction_strategy(
        &mut self,
        strategy: &FriReductionStrategy,
    ) -> IoResult<()> {
        match strategy {
            FriReductionStrategy::Fixed(arity_bitses) => {
                self.0.write_u8(0)?;
                self.0
                    .write_u64::<LittleEndian>(arity_bitses.len() as u64)?;
                self.write_usize_vec(arity_bitses)?;
            }
            FriReductionStrategy::ConstantArityBits(arity_bits, final_poly_bits) => {
                self.0.write_u8(1)?;
                self.0.write_u64::<LittleEndian>(*arity_bits as u64)?;
                self.0.write_u64::<LittleEndian>(*final_poly_bits as u64)?;
            }
            FriReductionStrategy::MinSize(opt_max_arity_bits) => {
                self.0.write_u8(2)?;
                match opt_max_arity_bits {
                    Some(opt_max_arity_bits) => {
                        self.0.write_u8(1)?;
                        self.0
                            .write_u64::<LittleEndian>(*opt_max_arity_bits as u64)?;
                    }
                    None => {
                        self.0.write_u8(0)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn write_fri_oracle_info(&mut self, info: &FriOracleInfo) -> IoResult<()> {
        self.0.write_u8(info.blinding as u8)
    }

    fn write_fri_polynomial_info(&mut self, info: &FriPolynomialInfo) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(info.oracle_index as u64)?;
        self.0
            .write_u64::<LittleEndian>(info.polynomial_index as u64)
    }

    fn write_fri_batch_info<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        info: &FriBatchInfo<F, D>,
    ) -> IoResult<()> {
        self.write_field_ext::<F, D>(info.point)?;

        self.0
            .write_u64::<LittleEndian>(info.polynomials.len() as u64)?;
        for poly_info in info.polynomials.iter() {
            self.write_fri_polynomial_info(poly_info)?;
        }

        Ok(())
    }
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

    assert_eq!(buf.0.position() as usize, len);

    Ok(())
}

pub fn serialize_proof_with_pis<'a, C: GenericConfig<D>, const D: usize>(
    buf: &'a mut [u8],
    proof: &ProofWithPublicInputs<C::F, C, D>,
) -> IoResult<()> {
    serialize_proof(buf, &proof.proof, proof.public_inputs.as_slice())
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

    inspect(&mut buf);

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

    inspect(&mut buf);

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

    inspect(&mut buf);

    Ok(())
}

fn inspect<R: AsRef<[u8]>>(buf: &mut Buffer<R>) {
    let tmp = buf.0.position();
    buf.0.set_position(13 * std::mem::size_of::<u64>() as u64);
    let offset = buf.0.read_u64::<LittleEndian>().unwrap();
    buf.0.set_position(offset);
    let val = buf.0.read_u8().unwrap();
    buf.0.set_position(tmp)
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use log::{info, Level};

    use super::super::fri_verifier::get_fri_instance;
    use super::*;
    use crate::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig, prover::prove,
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
    fn test_circuit_data_serialization() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut circuit_bytes = vec![0u8; 200_000];

        let (_proof, verifier_only, common) =
            dummy_proof::<F, C, D>(&CircuitConfig::default(), 10)?;

        serialize_circuit_data(circuit_bytes.as_mut_slice(), &common, &verifier_only)?;
        let mut circuit_buf = CircuitBuf::<C, &[u8], D>::new(circuit_bytes.as_slice())?;

        let circuit_digest = circuit_buf.read_circuit_digest()?;
        assert_eq!(circuit_digest, common.circuit_digest);

        let num_challenges = circuit_buf.read_num_challenges()?;
        assert_eq!(num_challenges, common.config.num_challenges);

        let num_gate_constraints = circuit_buf.read_num_gate_constraints()?;
        assert_eq!(num_gate_constraints, common.num_gate_constraints);

        let degree_bits = circuit_buf.read_degree_bits()?;
        assert_eq!(degree_bits, common.degree_bits);

        let num_wires = circuit_buf.read_num_wires()?;
        assert_eq!(num_wires, common.config.num_wires);

        let num_routed_wires = circuit_buf.read_num_routed_wires()?;
        assert_eq!(num_routed_wires, common.config.num_routed_wires);

        let k_is = circuit_buf.read_k_is(num_routed_wires)?;
        assert_eq!(k_is, common.k_is);

        let num_partial_products = circuit_buf.read_num_partial_products()?;
        assert_eq!(num_partial_products, common.num_partial_products);

        let quotient_degree_factor = circuit_buf.read_quotient_degree_factor()?;
        assert_eq!(quotient_degree_factor, common.quotient_degree_factor);

        let cap_height = circuit_buf.read_cap_height()?;
        assert_eq!(cap_height, common.fri_params.config.cap_height);

        let fri_is_hiding = circuit_buf.read_fri_is_hiding()?;
        assert_eq!(fri_is_hiding, common.fri_params.hiding);

        let fri_degree_bits = circuit_buf.read_fri_degree_bits()?;
        assert_eq!(fri_degree_bits, common.fri_params.degree_bits);

        let fri_proof_of_work_bits = circuit_buf.read_fri_proof_of_work_bits()?;
        assert_eq!(
            fri_proof_of_work_bits,
            common.fri_params.config.proof_of_work_bits
        );

        let fri_num_query_rounds = circuit_buf.read_fri_num_query_rounds()?;
        assert_eq!(
            fri_num_query_rounds,
            common.fri_params.config.num_query_rounds
        );

        let constants_sigmas_cap = circuit_buf.read_sigmas_cap(cap_height)?;
        assert_eq!(constants_sigmas_cap, verifier_only.constants_sigmas_cap);

        let fri_reduction_arity_bits = circuit_buf.read_fri_reduction_arity_bits()?;
        assert_eq!(
            fri_reduction_arity_bits,
            common.fri_params.reduction_arity_bits
        );

        let fri_reduction_strategy = circuit_buf.read_fri_reduction_strategy()?;
        assert_eq!(
            fri_reduction_strategy,
            common.fri_params.config.reduction_strategy
        );

        let selectors_info = circuit_buf.read_selectors_info()?;
        assert_eq!(
            selectors_info.selector_indices,
            common.selectors_info.selector_indices
        );
        assert_eq!(selectors_info.groups, common.selectors_info.groups);

        let gates = circuit_buf.read_gates()?;
        for (g1, g2) in gates.iter().zip(common.gates.iter()) {
            assert_eq!(g1.as_ref().id(), g2.as_ref().id())
        }

        Ok(())
    }

    #[test]
    fn test_proof_serialization() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut proof_bytes = vec![0u8; 200_000];

        let (proof, _verifier_only, common) =
            dummy_proof::<F, C, D>(&CircuitConfig::default(), 10)?;

        serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof)?;
        let mut proof_buf = ProofBuf::<C, &[u8], D>::new(proof_bytes.as_slice())?;

        let cap_height = common.fri_params.config.cap_height;
        let wires_cap = proof_buf.read_wires_cap(cap_height)?;
        assert_eq!(wires_cap, proof.proof.wires_cap);

        let zs_pp_cap = proof_buf.read_zs_pp_cap(cap_height)?;
        assert_eq!(zs_pp_cap, proof.proof.plonk_zs_partial_products_cap);

        let quotient_polys_cap = proof_buf.read_quotient_polys_cap(cap_height)?;
        assert_eq!(quotient_polys_cap, proof.proof.quotient_polys_cap);

        let constants = proof_buf.read_constants_openings(common.num_constants)?;
        assert_eq!(constants, proof.proof.openings.constants);

        let plonk_sigmas = proof_buf.read_plonk_sigmas_openings(common.config.num_routed_wires)?;
        assert_eq!(plonk_sigmas, proof.proof.openings.plonk_sigmas);

        let plonk_wires = proof_buf.read_wires_openings(common.config.num_wires)?;
        assert_eq!(plonk_wires, proof.proof.openings.wires);

        let plonk_zs = proof_buf.read_plonk_zs_openings(common.config.num_challenges)?;
        assert_eq!(plonk_zs, proof.proof.openings.plonk_zs);

        let plonk_zs_next = proof_buf.read_plonk_zs_next_openings(common.config.num_challenges)?;
        assert_eq!(plonk_zs_next, proof.proof.openings.plonk_zs_next);

        let plonk_zs_partial_products = proof_buf
            .read_pps_openings(common.num_partial_products, common.config.num_challenges)?;
        assert_eq!(
            plonk_zs_partial_products,
            proof.proof.openings.partial_products
        );

        let quotient_polys = proof_buf.read_quotient_polys_openings(
            common.quotient_degree_factor,
            common.config.num_challenges,
        )?;
        assert_eq!(quotient_polys, proof.proof.openings.quotient_polys);

        Ok(())
    }

    #[test]
    fn test_init_challenges() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut proof_bytes = vec![0u8; 200_000];
        let (proof, _verifier_only, common) =
            dummy_proof::<F, C, D>(&CircuitConfig::default(), 10)?;
        serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof)?;
        let mut proof_buf = ProofBuf::<C, &mut [u8], D>::new(proof_bytes.as_mut_slice())?;

        let pis = proof_buf.read_pis()?;
        assert_eq!(&pis, &proof.public_inputs);

        let pis_hash =
            <<C as GenericConfig<D>>::InnerHasher as Hasher<F>>::hash_no_pad(pis.as_slice());
        assert_eq!(pis_hash, proof.get_public_inputs_hash());

        proof_buf.write_pis_hash(pis_hash)?;
        let challenges = proof.get_challenges(pis_hash, &common)?;
        proof_buf.write_challenges(&challenges)?;

        let plonk_betas = proof_buf.read_challenge_betas(common.config.num_challenges)?;
        let plonk_gammas = proof_buf.read_challenge_gammas(common.config.num_challenges)?;
        let plonk_alphas = proof_buf.read_challenge_alphas(common.config.num_challenges)?;
        let plonk_zeta = proof_buf.read_challenge_zeta()?;

        let fri_alpha = proof_buf.read_fri_alpha()?;
        let fri_pow_response = proof_buf.read_fri_pow_response()?;
        let fri_betas = proof_buf.read_fri_betas(common.fri_params.reduction_arity_bits.len())?;
        let fri_query_indices =
            proof_buf.read_fri_query_indices(common.fri_params.config.num_query_rounds)?;

        assert_eq!(plonk_betas, challenges.plonk_betas);
        assert_eq!(plonk_gammas, challenges.plonk_gammas);
        assert_eq!(plonk_alphas, challenges.plonk_alphas);
        assert_eq!(plonk_zeta, challenges.plonk_zeta);

        assert_eq!(fri_alpha, challenges.fri_challenges.fri_alpha);
        assert_eq!(fri_pow_response, challenges.fri_challenges.fri_pow_response);
        assert_eq!(fri_betas, challenges.fri_challenges.fri_betas);
        assert_eq!(
            fri_query_indices,
            challenges.fri_challenges.fri_query_indices
        );

        Ok(())
    }

    #[test]
    fn test_init_fri_instance() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut proof_bytes = vec![0u8; 200_000];
        let (proof, _verifier_only, common) =
            dummy_proof::<F, C, D>(&CircuitConfig::default(), 10)?;
        serialize_proof_with_pis(proof_bytes.as_mut_slice(), &proof)?;
        let mut proof_buf = ProofBuf::<C, &mut [u8], D>::new(proof_bytes.as_mut_slice())?;

        let pis_hash = proof.get_public_inputs_hash();
        let challenges = proof.get_challenges(pis_hash, &common)?;
        let fri_instance = common.get_fri_instance(challenges.plonk_zeta);

        proof_buf.write_fri_instance(&fri_instance)?;

        let fri_instance_read = proof_buf.read_fri_instance()?;
        for (a, b) in fri_instance_read
            .oracles
            .iter()
            .zip(fri_instance.oracles.iter())
        {
            assert_eq!(a.blinding, b.blinding);
        }

        for (a, b) in fri_instance_read
            .batches
            .iter()
            .zip(fri_instance.batches.iter())
        {
            assert_eq!(a.point, b.point);
            for (a, b) in a.polynomials.iter().zip(b.polynomials.iter()) {
                assert_eq!(a.oracle_index, b.oracle_index);
                assert_eq!(a.polynomial_index, b.polynomial_index);
            }
        }

        Ok(())
    }
}
