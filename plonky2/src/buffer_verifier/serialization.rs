use std::marker::PhantomData;
use std::ops::Range;
use std::io::{
    Result as IoResult,
    Error as IoError,
    ErrorKind as IoErrorKind,
};

use byteorder::{ByteOrder, LittleEndian};
use plonky2_field::extension::FieldExtension;
use plonky2_field::types::{Field, PrimeField64};

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
use crate::hash::merkle_tree::MerkleCap;
use crate::plonk::config::{GenericConfig, GenericHashOut, Hasher};

#[allow(type_alias_bounds)]
type HashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

pub struct ProofBuf<'a, C: GenericConfig<D>, const D: usize> {
    buf: &'a [u8],
    offsets: ProofBufOffsets,
    _phantom: PhantomData<C>,
}

pub struct ProofBufMut<'a, C: GenericConfig<D>, const D: usize> {
    buf: &'a mut [u8],
    offsets: ProofBufOffsets,
    _phantom: PhantomData<C>,
}

#[derive(Debug, Clone, Copy)]
struct ProofBufOffsets {
    len: usize,
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
}

// TODO: check to ensure offsets are valid and return a result
fn get_proof_buf_offsets<'a>(buf: &'a [u8]) -> (ProofBufOffsets, usize) {
    let original_len = buf.len();

    let len = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let wires_cap_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let zs_pp_cap_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let quotient_polys_cap_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let constants_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let plonk_sigmas_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let wires_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let plonk_zs_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let pps_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let quotient_polys_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let plonk_zs_next_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let challenge_betas_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let challenge_gammas_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let challenge_alphas_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let challenge_zeta_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_alpha_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_pow_response_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_betas_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_query_indices_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    (
        ProofBufOffsets {
            len,
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
        },
        original_len - buf.len(),
    )
}

impl<'a, C: GenericConfig<D>, const D: usize> ProofBuf<'a, C, D> {
    pub fn new(buf: &'a [u8]) -> Self {
        let (offsets, start_offset) = get_proof_buf_offsets(buf);
        ProofBuf {
            buf: &buf[start_offset..],
            offsets,
            _phantom: PhantomData,
        }
    }

    pub fn read_pis_hash(&self) -> HashForConfig<C, D> {
        let hash_bytes = &self.buf[..<C as GenericConfig<D>>::Hasher::HASH_SIZE];
        HashForConfig::<C, D>::from_bytes(hash_bytes)
    }

    pub fn read_wires_cap(&self) -> MerkleCap<C::F, C::Hasher> {
        let width =
            (self.offsets.zs_pp_cap_offset - self.offsets.wires_cap_offset) / C::Hasher::HASH_SIZE;
        read_merkle_cap::<C, D>(self.buf, self.offsets.wires_cap_offset, width)
    }

    pub fn read_zs_pp_cap(&self) -> MerkleCap<C::F, C::Hasher> {
        let width = (self.offsets.quotient_polys_cap_offset - self.offsets.zs_pp_cap_offset)
            / C::Hasher::HASH_SIZE;
        read_merkle_cap::<C, D>(self.buf, self.offsets.zs_pp_cap_offset, width)
    }

    pub fn read_quotient_polys_cap(&self) -> MerkleCap<C::F, C::Hasher> {
        let width = (self.offsets.constants_offset - self.offsets.quotient_polys_cap_offset)
            / C::Hasher::HASH_SIZE;
        read_merkle_cap::<C, D>(self.buf, self.offsets.quotient_polys_cap_offset, width)
    }

    pub fn read_constants_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.plonk_sigmas_offset - self.offsets.constants_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.constants_offset, len)
    }

    pub fn read_plonk_sigmas_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.wires_offset - self.offsets.plonk_sigmas_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.plonk_sigmas_offset, len)
    }

    pub fn read_wires_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.plonk_zs_offset - self.offsets.wires_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.wires_offset, len)
    }

    pub fn read_plonk_zs_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.pps_offset - self.offsets.plonk_zs_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.plonk_zs_offset, len)
    }

    pub fn read_pps_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.quotient_polys_offset - self.offsets.pps_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.pps_offset, len)
    }

    pub fn read_quotient_polys_openings(&self) -> Vec<C::FE> {
        let len = (self.offsets.plonk_zs_next_offset - self.offsets.quotient_polys_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.quotient_polys_offset, len)
    }

    pub fn read_plonk_zs_next_openings(&self) -> Vec<C::F> {
        let len = (self.offsets.challenge_betas_offset - self.offsets.plonk_zs_next_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_vec::<C, D>(self.buf, self.offsets.plonk_zs_next_offset, len)
    }

    pub fn read_challenge_betas(&self) -> Vec<C::F> {
        let len = (self.offsets.challenge_gammas_offset - self.offsets.challenge_betas_offset)
            / std::mem::size_of::<u64>();
        read_field_vec::<C, D>(self.buf, self.offsets.challenge_betas_offset, len)
    }

    pub fn read_challenge_gammas(&self) -> Vec<C::F> {
        let len = (self.offsets.challenge_alphas_offset - self.offsets.challenge_gammas_offset)
            / std::mem::size_of::<u64>();
        read_field_vec::<C, D>(self.buf, self.offsets.challenge_gammas_offset, len)
    }

    pub fn read_challenge_alphas(&self) -> Vec<C::F> {
        let len = (self.offsets.challenge_zeta_offset - self.offsets.challenge_alphas_offset)
            / std::mem::size_of::<u64>();
        read_field_vec::<C, D>(self.buf, self.offsets.challenge_alphas_offset, len)
    }

    pub fn read_challenge_zeta(&self) -> C::FE {
        read_field_ext::<C, D>(self.buf, self.offsets.challenge_zeta_offset)
    }

    pub fn read_fri_alpha(&self) -> C::FE {
        read_field_ext::<C, D>(self.buf, self.offsets.fri_alpha_offset)
    }

    pub fn read_fri_pow_response(&self) -> C::F {
        C::F::from_canonical_u64(LittleEndian::read_u64(
            &self.buf[self.offsets.fri_pow_response_offset..],
        ))
    }

    pub fn read_fri_betas(&self) -> Vec<C::FE> {
        let len = (self.offsets.fri_query_indices_offset - self.offsets.fri_betas_offset)
            / (std::mem::size_of::<u64>() * D);
        read_field_ext_vec::<C, D>(self.buf, self.offsets.fri_betas_offset, len)
    }

    pub fn read_fri_query_indices(&self) -> Vec<usize> {
        let len =
            (self.offsets.len - self.offsets.fri_query_indices_offset) / std::mem::size_of::<u64>();
        read_usize_vec(self.buf, self.offsets.fri_query_indices_offset, len)
    }
}

pub struct BufferVerifierChallenges<C: GenericConfig<D>, const D: usize> {
    betas: Vec<C::F>,
    gammas: Vec<C::F>,
    alphas: Vec<C::F>,
    zeta: C::FE,
    fri_alpha: C::FE,
    fri_pow_response: C::F,
    fri_betas: Vec<C::FE>,
    fri_query_indices: Vec<usize>,
}

impl<'a, C: GenericConfig<D>, const D: usize> ProofBufMut<'a, C, D> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        let (offsets, start_offset) = get_proof_buf_offsets(buf);
        ProofBufMut {
            buf: &mut buf[start_offset..],
            offsets,
            _phantom: PhantomData,
        }
    }

    pub fn as_readonly<'b>(&'a self) -> ProofBuf<'b, C, D>
    where
        'a: 'b,
    {
        ProofBuf {
            buf: self.buf,
            offsets: self.offsets,
            _phantom: PhantomData,
        }
    }

    pub fn write_challenges(&mut self, challenges: BufferVerifierChallenges<C, D>) {
        self.write_challenge_betas(&challenges.betas);
        self.write_challenge_gammas(&challenges.gammas);
        self.write_challenge_alphas(&challenges.alphas);
        self.write_challenge_zeta(challenges.zeta);
        self.write_fri_alpha(challenges.fri_alpha);
        self.write_fri_pow_response(challenges.fri_pow_response);
        self.write_fri_betas(&challenges.fri_betas);
        self.write_fri_query_indices(&challenges.fri_query_indices);
    }

    fn write_challenge_betas(&mut self, betas: &[C::F]) {
        self.write_field_vec(self.offsets.challenge_betas_offset, betas);
        self.offsets.challenge_gammas_offset =
            self.offsets.challenge_betas_offset + betas.len() * std::mem::size_of::<u64>();
    }

    fn write_challenge_gammas(&mut self, gammas: &[C::F]) {
        self.write_field_vec(self.offsets.challenge_gammas_offset, gammas);
        self.offsets.challenge_alphas_offset =
            self.offsets.challenge_gammas_offset + gammas.len() * std::mem::size_of::<u64>();
    }

    fn write_challenge_alphas(&mut self, alphas: &[C::F]) {
        self.write_field_vec(self.offsets.challenge_alphas_offset, alphas);
        self.offsets.challenge_zeta_offset =
            self.offsets.challenge_alphas_offset + alphas.len() * std::mem::size_of::<u64>();
    }

    fn write_challenge_zeta(&mut self, zeta: C::FE) {
        self.write_field_ext(self.offsets.challenge_zeta_offset, zeta);
        self.offsets.fri_alpha_offset =
            self.offsets.challenge_zeta_offset + std::mem::size_of::<u64>() * D;
    }

    fn write_fri_alpha(&mut self, alpha: C::FE) {
        self.write_field_ext(self.offsets.fri_alpha_offset, alpha);
        self.offsets.fri_pow_response_offset =
            self.offsets.fri_alpha_offset + std::mem::size_of::<u64>() * D;
    }

    fn write_fri_pow_response(&mut self, pow_response: C::F) {
        let buf = &mut self.buf[self.offsets.fri_pow_response_offset..];
        LittleEndian::write_u64(buf, pow_response.to_canonical_u64());
        self.offsets.fri_betas_offset =
            self.offsets.fri_pow_response_offset + std::mem::size_of::<u64>();
    }

    fn write_fri_betas(&mut self, fri_betas: &[C::FE]) {
        self.write_field_ext_vec(self.offsets.fri_betas_offset, fri_betas);
        self.offsets.fri_query_indices_offset =
            self.offsets.fri_betas_offset + std::mem::size_of::<u64>() * D * fri_betas.len();
    }

    fn write_fri_query_indices(&mut self, fri_query_indices: &[usize]) {
        self.write_usize_vec(self.offsets.fri_query_indices_offset, fri_query_indices);
        self.offsets.len = self.offsets.fri_query_indices_offset
            + std::mem::size_of::<u64>() * fri_query_indices.len();
    }

    fn write_field_ext_vec(&mut self, mut offset: usize, fri_betas: &[C::FE]) {
        for i in 0..fri_betas.len() {
            self.write_field_ext(offset, fri_betas[i]);
            offset += std::mem::size_of::<u64>() * D;
        }
    }

    fn write_field_vec(&mut self, offset: usize, elems: &[C::F]) {
        let mut buf = &mut self.buf[offset..];
        for elem in elems {
            LittleEndian::write_u64(
                &mut buf[0..std::mem::size_of::<u64>()],
                elem.to_canonical_u64(),
            );
            buf = &mut buf[std::mem::size_of::<u64>()..];
        }
    }

    fn write_usize_vec(&mut self, offset: usize, elems: &[usize]) {
        let mut buf = &mut self.buf[offset..];
        for elem in elems {
            LittleEndian::write_u64(&mut buf[0..std::mem::size_of::<u64>()], *elem as u64);
            buf = &mut buf[std::mem::size_of::<u64>()..];
        }
    }

    fn write_field_ext(&mut self, offset: usize, elem: C::FE) {
        let buf = &mut self.buf[offset..];
        let basefield_arr = elem.to_basefield_array();
        for i in 0..D {
            LittleEndian::write_u64(
                &mut buf[i * std::mem::size_of::<u64>()..],
                basefield_arr[i].to_canonical_u64(),
            );
        }
    }
}

pub struct CircuitBuf<'a, C: GenericConfig<D>, const D: usize> {
    buf: &'a [u8],
    offsets: CircuitBufOffsets,
    _phantom: PhantomData<C>,
}

pub struct CircuitBufMut<'a, C: GenericConfig<D>, const D: usize> {
    buf: &'a mut [u8],
    offsets: CircuitBufOffsets,
    _phantom: PhantomData<C>,
}

pub struct CircuitBufOffsets {
    len: usize,
    circuit_digest_offset: usize,
    num_challenges_offset: usize,
    num_gate_constraints_offset: usize,
    gates_offset: usize,
    selector_indices_offset: usize,
    selector_groups_offset: usize,
    degree_bits_offset: usize,
    num_routed_wires_offset: usize,
    k_is_offset: usize,
    num_partial_products_offset: usize,
    quotient_degree_factor_offset: usize,
    sigmas_cap_offset: usize,
    // these offsets are initially set to `sigmas_cap_offset` and is updated via "circuit initialization" method
    fri_instance_oracles_offset: usize,
    fri_instance_batches_offset: usize,
}

fn get_circuit_buf_offsets<'a>(buf: &'a [u8]) -> (CircuitBufOffsets, usize) {
    let original_len = buf.len();

    let len = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let circuit_digest_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let num_challenges_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let num_gate_constraints_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let gates_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let selector_indices_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let selector_groups_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let degree_bits_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let num_routed_wires_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let k_is_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let num_partial_products_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let quotient_degree_factor_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let sigmas_cap_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_instance_oracles_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    let fri_instance_batches_offset = LittleEndian::read_u64(buf) as usize;
    let buf = &buf[std::mem::size_of::<u64>()..];

    (
        CircuitBufOffsets {
            len,
            circuit_digest_offset,
            num_challenges_offset,
            num_gate_constraints_offset,
            gates_offset,
            selector_indices_offset,
            selector_groups_offset,
            degree_bits_offset,
            num_routed_wires_offset,
            k_is_offset,
            num_partial_products_offset,
            quotient_degree_factor_offset,
            sigmas_cap_offset,
            fri_instance_oracles_offset,
            fri_instance_batches_offset,
        },
        original_len - buf.len(),
    )
}

impl<'a, C: GenericConfig<D>, const D: usize> CircuitBuf<'a, C, D> {
    pub fn new(buf: &'a [u8]) -> Self {
        let (offsets, start_offset) = get_circuit_buf_offsets(buf);
        CircuitBuf {
            buf: &buf[start_offset..],
            offsets,
            _phantom: PhantomData,
        }
    }

    pub fn read_circuit_digest(&self) -> HashForConfig<C, D> {
        let hash_bytes = &self.buf[..<C as GenericConfig<D>>::Hasher::HASH_SIZE];
        HashForConfig::<C, D>::from_bytes(hash_bytes)
    }

    pub fn read_num_challenges(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.num_challenges_offset..]) as usize
    }

    pub fn read_num_gate_constraints(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.num_gate_constraints_offset..]) as usize
    }

    pub fn read_selectors_info(&self) -> SelectorsInfo {
        let len = (self.offsets.selector_groups_offset - self.offsets.selector_indices_offset)
            / std::mem::size_of::<u64>();
        let selector_indices = read_usize_vec(self.buf, self.offsets.selector_indices_offset, len);

        let len = (self.offsets.degree_bits_offset - self.offsets.selector_groups_offset)
            / (std::mem::size_of::<u64>() * 2);
        let groups = read_range_vec(self.buf, self.offsets.selector_groups_offset, len);

        SelectorsInfo {
            selector_indices,
            groups,
        }
    }

    pub fn read_degree_bits(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.degree_bits_offset..]) as usize
    }

    pub fn read_num_routed_wires(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.num_routed_wires_offset..]) as usize
    }

    pub fn read_k_is(&self) -> Vec<C::F> {
        let len = (self.offsets.num_partial_products_offset - self.offsets.k_is_offset)
            / std::mem::size_of::<u64>();
        read_field_vec::<C, D>(self.buf, self.offsets.k_is_offset, len)
    }

    pub fn read_num_partial_products(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.num_partial_products_offset..]) as usize
    }

    pub fn read_quotient_degree_factor(&self) -> usize {
        LittleEndian::read_u64(&self.buf[self.offsets.quotient_degree_factor_offset..]) as usize
    }

    pub fn read_sigmas_cap(&self) -> MerkleCap<C::F, C::Hasher> {
        let len = (self.offsets.sigmas_cap_offset - self.offsets.quotient_degree_factor_offset)
            / std::mem::size_of::<u64>();
        read_merkle_cap::<C, D>(self.buf, self.offsets.quotient_degree_factor_offset, len)
    }

    pub fn read_fri_instance(&self) -> FriInstanceInfo<C::F, D> {
        let len = (self.offsets.fri_instance_batches_offset
            - self.offsets.fri_instance_oracles_offset)
            / std::mem::size_of::<u8>();
        let blinding_vec = read_bool_vec(self.buf, self.offsets.fri_instance_oracles_offset, len);
        let oracles = blinding_vec
            .into_iter()
            .map(|blinding| FriOracleInfo { blinding })
            .collect();

        let num_batches =
            LittleEndian::read_u64(&self.buf[self.offsets.fri_instance_batches_offset..]) as usize;
        let mut offset = self.offsets.fri_instance_batches_offset + std::mem::size_of::<u64>();
        let mut batches = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            let point = read_field_ext::<C, D>(self.buf, offset);
            offset += std::mem::size_of::<u64>() * D;

            let num_polys = LittleEndian::read_u64(&self.buf[offset..]) as usize;
            offset += std::mem::size_of::<u64>();

            let mut polynomials = Vec::with_capacity(num_polys);
            for _ in 0..num_polys {
                let oracle_index = LittleEndian::read_u64(&self.buf[offset..]) as usize;
                offset += std::mem::size_of::<u64>();

                let polynomial_index = LittleEndian::read_u64(&self.buf[offset..]) as usize;
                offset += std::mem::size_of::<u64>();

                polynomials.push(FriPolynomialInfo {
                    oracle_index,
                    polynomial_index,
                });
            }

            batches.push(FriBatchInfo { point, polynomials });
        }

        FriInstanceInfo { oracles, batches }
    }
}

// util functions

pub fn read_merkle_cap<C: GenericConfig<D>, const D: usize>(
    buf: &[u8],
    offset: usize,
    width: usize,
) -> MerkleCap<C::F, C::Hasher> {
    let cap_bytes = &buf[offset..];
    let mut hashes = Vec::new();
    for i in 0..width {
        let hash_bytes =
            &cap_bytes[i * <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::HASH_SIZE..];
        hashes.push(HashForConfig::<C, D>::from_bytes(hash_bytes));
    }

    MerkleCap(hashes)
}

pub fn read_field_ext<C: GenericConfig<D>, const D: usize>(buf: &[u8], offset: usize) -> C::FE {
    let bytes = &buf[offset..];
    let mut basefield_arr = [C::F::ZERO; D];
    for i in 0..D {
        basefield_arr[i] = C::F::from_canonical_u64(LittleEndian::read_u64(
            &bytes[i * std::mem::size_of::<u64>()..],
        ));
    }

    C::FE::from_basefield_array(basefield_arr)
}

pub fn read_range(buf: &[u8], offset: usize) -> Range<usize> {
    let start = LittleEndian::read_u64(&buf[offset..]) as usize;
    let end = LittleEndian::read_u64(&buf[offset + std::mem::size_of::<u64>()..]) as usize;
    Range { start, end }
}

pub fn read_bool(buf: &[u8], offset: usize) -> bool {
    !(buf[offset] == 0)
}

pub fn read_field_ext_vec<C: GenericConfig<D>, const D: usize>(
    buf: &[u8],
    mut offset: usize,
    len: usize,
) -> Vec<C::FE> {
    let mut res = Vec::with_capacity(len);
    for _ in 0..len {
        let field_ext = read_field_ext::<C, D>(buf, offset);
        res.push(field_ext);
        offset += std::mem::size_of::<u64>() * D;
    }
    res
}

pub fn read_field_vec<C: GenericConfig<D>, const D: usize>(
    buf: &[u8],
    offset: usize,
    len: usize,
) -> Vec<C::F> {
    let mut res = Vec::with_capacity(len);
    let buf = &buf[offset..];
    for i in 0..len {
        res.push(C::F::from_canonical_u64(LittleEndian::read_u64(
            &buf[i * std::mem::size_of::<u64>()..],
        )));
    }

    res
}

pub fn read_usize_vec(buf: &[u8], offset: usize, len: usize) -> Vec<usize> {
    let mut res = Vec::with_capacity(len);
    let buf = &buf[offset..];
    for i in 0..len {
        res.push(LittleEndian::read_u64(&buf[i * std::mem::size_of::<u64>()..]) as usize);
    }

    res
}

pub fn read_range_vec(buf: &[u8], offset: usize, len: usize) -> Vec<Range<usize>> {
    let mut res = Vec::with_capacity(len);
    let buf = &buf[offset..];
    for i in 0..len {
        res.push(read_range(buf, i * std::mem::size_of::<u64>() * 2));
    }

    res
}

pub fn read_bool_vec(buf: &[u8], offset: usize, len: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(len);
    let buf = &buf[offset..];
    for i in 0..len {
        res.push(read_bool(buf, i * std::mem::size_of::<u8>()));
    }

    res
}

macro_rules! base_sum_match_statement {
    ( $matched_base:expr, $buf:expr, $( $base:expr ),* ) => {
        match $matched_base {
            $(
                $base => Ok(BaseSumGate::<$base>::deserialize($buf)?),
            )*
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
        }
    }
}

pub fn read_gate<C: GenericConfig<D>, const D: usize>(
    buf: &[u8],
    mut offset: usize,
) -> IoResult<GateBox<C::F, D>> {
    let tag = buf[offset];
    offset += 1;
    match tag {
        ARITHMETIC_BASE_TAG => Ok(ArithmeticGate::deserialize(&buf[offset..])?),
        ARITHMETIC_EXT_TAG => Ok(ArithmeticExtensionGate::deserialize(&buf[offset..])?),
        ASSERT_LE_TAG => Ok(AssertLessThanGate::deserialize(&buf[offset..])?),
        BASE_SUM_TAG => {
            let base = buf[offset];
            offset += 1;

            base_sum_match_statement!(
                base,
                &buf[offset..],
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
                27,
                28,
                29,
                30,
                31,
                32,
                33,
                34,
                35,
                36,
                37,
                38,
                39,
                40,
                41,
                42,
                43,
                44,
                45,
                46,
                47,
                48,
                49,
                50,
                51,
                52,
                53,
                54,
                55,
                56,
                57,
                58,
                59,
                60,
                61,
                62,
                63,
                64
            )
        }
        CONSTANT_TAG => Ok(ConstantGate::deserialize(&buf[offset..])?),
        EXPONENTIATION_TAG => Ok(ExponentiationGate::deserialize(&buf[offset..])?),
        INTERPOLATION_TAG => Ok(HighDegreeInterpolationGate::deserialize(&buf[offset..])?),
        LOW_DEGREE_INTERPOLATION_TAG => Ok(LowDegreeInterpolationGate::deserialize(&buf[offset..])?),
        MUL_EXT_TAG => Ok(MulExtensionGate::deserialize(&buf[offset..])?),
        NOOP_TAG => Ok(NoopGate::deserialize(&buf[offset..])?),
        POSEIDON_MDS_TAG => Ok(PoseidonMdsGate::deserialize(&buf[offset..])?),
        POSEIDON_TAG => Ok(PoseidonGate::deserialize(&buf[offset..])?),
        PUBLIC_INPUT_TAG => Ok(PublicInputGate::deserialize(&buf[offset..])?),
        RANDOM_ACCESS_TAG => Ok(RandomAccessGate::deserialize(&buf[offset..])?),
        REDUCING_EXT_TAG => Ok(ReducingExtensionGate::deserialize(&buf[offset..])?),
        REDUCING_TAG => Ok(ReducingGate::deserialize(&buf[offset..])?),
        _ => Err(IoError::from(IoErrorKind::InvalidData))
    }
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
