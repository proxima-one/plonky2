use std::marker::PhantomData;
use std::ops::Range;
use std::io::{
    Result as IoResult,
    Error as IoError,
    ErrorKind as IoErrorKind, Write, Cursor, Read
};
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use plonky2_field::extension::{FieldExtension, Extendable};
use plonky2_field::types::{Field, PrimeField64, Field64};

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
use crate::plonk::circuit_data::CommonCircuitData;
use crate::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use crate::plonk::plonk_common::{FRI_ORACLES, PlonkOracle};

#[allow(type_alias_bounds)]
type HashForConfig<C: GenericConfig<D>, const D: usize> =
    <C::Hasher as Hasher<<C as GenericConfig<D>>::F>>::Hash;

pub struct ProofBuf<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> {
    buf: Buffer<R>,
    offsets: ProofBufOffsets,
    _phantom: PhantomData<C>,
}

#[derive(Debug, Clone, Copy)]
struct ProofBufOffsets {
    len: usize,
    pis_hash_offset: usize,
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

// TODO: check to ensure offsets are valid and return a IoResult
fn get_proof_buf_offsets<R: AsRef<[u8]>>(buf: &mut Buffer<R>) -> IoResult<ProofBufOffsets> {
    let len = buf.0.read_u64::<LittleEndian>()? as usize;
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

    Ok(
        ProofBufOffsets {
            len,
            pis_hash_offset: buf.0.position() as usize,
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
        }
    )
}

impl<R: AsRef<[u8]>, C: GenericConfig<D>, const D: usize> ProofBuf<C, R, D> {
    pub fn new(buf: R) -> IoResult<Self> {
        let mut buf = Buffer::new(buf);
        let offsets = get_proof_buf_offsets(&mut buf)?;
        Ok(
            ProofBuf {
                buf,
                offsets,
                _phantom: PhantomData,
            }
        )
    }

    pub fn read_pis_hash(&mut self) -> IoResult<HashForConfig<C, D>> {
        self.buf.0.set_position(self.offsets.pis_hash_offset as u64);
        self.buf.read_hash::<C::F, C::Hasher>()
    }

    pub fn read_wires_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf.0.set_position(self.offsets.wires_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_zs_pp_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf.0.set_position(self.offsets.zs_pp_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_quotient_polys_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf.0.set_position(self.offsets.quotient_polys_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_constants_openings(&mut self, num_constants: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.constants_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_constants)
    }

    pub fn read_plonk_sigmas_openings(&mut self, num_routed_wires: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.plonk_sigmas_offset as u64);
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
        self.buf.0.set_position(self.offsets.plonk_zs_next_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_challenges)
    }

    pub fn read_pps_openings(&mut self, num_partial_products: usize, num_challenges: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.pps_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(num_partial_products * num_challenges)
    }

    pub fn read_quotient_polys_openings(&mut self, quotient_degree_factor: usize, num_challenges: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.quotient_polys_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(quotient_degree_factor * num_challenges)
    }

    pub fn read_challenge_betas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.challenge_betas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_gammas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.challenge_gammas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_alphas(&mut self, num_challenges: usize) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.challenge_alphas_offset as u64);
        self.buf.read_field_vec(num_challenges)
    }

    pub fn read_challenge_zeta(&mut self) -> IoResult<C::FE> {
        self.buf.read_field_ext::<C::F, D>()
    }

    pub fn read_fri_alpha(&mut self) -> IoResult<C::FE> {
        self.buf.0.set_position(self.offsets.fri_alpha_offset as u64);
        self.buf.read_field_ext::<C::F, D>()
    }

    pub fn read_fri_pow_response(&mut self) -> IoResult<C::F> {
        self.buf.read_field()
    }

    pub fn read_fri_betas(&mut self, fri_reduction_arity_bits_len: usize) -> IoResult<Vec<C::FE>> {
        self.buf.0.set_position(self.offsets.fri_betas_offset as u64);
        self.buf.read_field_ext_vec::<C::F, D>(fri_reduction_arity_bits_len)
    }

    pub fn read_fri_query_indices(&mut self, num_fri_queries: usize) -> IoResult<Vec<usize>> {
        self.buf.0.set_position(self.offsets.fri_query_indices_offset as u64);
        self.buf.read_usize_vec(num_fri_queries)
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

impl<'a, C: GenericConfig<D>, const D: usize> ProofBuf<C, &'a mut [u8], D> {
    pub fn write_challenges(&mut self, challenges: BufferVerifierChallenges<C, D>) -> IoResult<()> {
        self.buf.0.set_position(self.offsets.challenge_betas_offset as u64);
        self.buf.write_field_vec(challenges.betas.as_slice())?;

        self.offsets.challenge_gammas_offset = self.buf.0.position() as usize;
        self.buf.write_field_vec(challenges.gammas.as_slice())?;

        self.offsets.challenge_alphas_offset = self.buf.0.position() as usize;
        self.buf.write_field_vec(challenges.alphas.as_slice())?;

        self.offsets.challenge_zeta_offset = self.buf.0.position() as usize;
        self.buf.write_field_ext::<C::F, D>(challenges.zeta)?;

        self.offsets.fri_alpha_offset = self.buf.0.position() as usize;
        self.buf.write_field_ext::<C::F, D>(challenges.fri_alpha)?;

        self.offsets.fri_pow_response_offset = self.buf.0.position() as usize;
        self.buf.write_field(challenges.fri_pow_response)?;

        self.offsets.fri_betas_offset = self.buf.0.position() as usize;
        self.buf.write_field_ext_vec::<C::F, D>(challenges.fri_betas.as_slice())?;

        self.offsets.fri_query_indices_offset = self.buf.0.position() as usize;
        self.buf.write_usize_vec(challenges.fri_query_indices.as_slice())?;

        self.offsets.len = self.buf.0.position() as usize;
        self.set_offsets()?;

        Ok(())
    }

    pub fn set_offsets(&mut self) -> IoResult<()> {
        self.buf.0.set_position(0);

        self.buf.0.write_u64::<LittleEndian>(self.offsets.len as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.wires_cap_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.zs_pp_cap_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.quotient_polys_cap_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.constants_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.plonk_sigmas_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.wires_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.plonk_zs_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.pps_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.quotient_polys_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.plonk_zs_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.challenge_betas_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.challenge_gammas_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.challenge_alphas_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.challenge_zeta_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.fri_alpha_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.fri_pow_response_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.fri_betas_offset as u64)?;
        self.buf.0.write_u64::<LittleEndian>(self.offsets.fri_query_indices_offset as u64)?;

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
    fri_instance_batches_offset: usize,
}

fn get_circuit_buf_offsets<R: AsRef<[u8]>>(buf: &mut Buffer<R>) -> IoResult<CircuitBufOffsets> {
    let len = buf.0.read_u64::<LittleEndian>()? as usize;
    let circuit_digest_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_challenges_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_gate_constraints_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let gates_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let selector_indices_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let selector_groups_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let degree_bits_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_routed_wires_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let k_is_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_partial_products_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let quotient_degree_factor_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let sigmas_cap_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_instance_batches_offset = buf.0.read_u64::<LittleEndian>()? as usize;

    Ok(
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
            fri_instance_batches_offset,
        }
    )
}

impl<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> CircuitBuf<C, R, D> {
    pub fn new(buf: R) -> IoResult<Self> {
        let mut buf = Buffer::new(buf);
        let offsets = get_circuit_buf_offsets(&mut buf)?;
        Ok(
            CircuitBuf {
                buf,
                offsets,
                _phantom: PhantomData,
            }
        )
    }

    pub fn read_circuit_digest(&mut self) -> IoResult<HashForConfig<C, D>> {
        self.buf.0.set_position(self.offsets.circuit_digest_offset as u64);
        self.buf.read_hash::<C::F, C::Hasher>()
    }

    pub fn read_num_challenges(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.num_challenges_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_gate_constraints(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.num_gate_constraints_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_selectors_info(&mut self) -> IoResult<SelectorsInfo> {
        self.buf.0.set_position(self.offsets.selector_indices_offset as u64);
        let indices_len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let selector_indices = self.buf.read_usize_vec(indices_len)?;

        let groups_len = self.buf.0.read_u64::<LittleEndian>()? as usize;
        let groups = self.buf.read_range_vec(groups_len)?;

        Ok(
            SelectorsInfo {
                selector_indices,
                groups,
            }
        )
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
        self.buf.0.set_position(self.offsets.degree_bits_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_num_routed_wires(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.num_routed_wires_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_k_is(&mut self, num_routed_wires: usize) -> IoResult<Vec<C::F>> {
        self.buf.0.set_position(self.offsets.k_is_offset as u64);
        self.buf.read_field_vec(num_routed_wires)
    }

    pub fn read_num_partial_products(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.num_partial_products_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_quotient_degree_factor(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.quotient_degree_factor_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
    }

    pub fn read_sigmas_cap(&mut self, cap_height: usize) -> IoResult<MerkleCap<C::F, C::Hasher>> {
        self.buf.0.set_position(self.offsets.sigmas_cap_offset as u64);
        self.buf.read_merkle_cap(cap_height)
    }

    pub fn read_fri_instance(&mut self, num_constants: usize, num_wires: usize, num_routed_wires: usize, num_challenges: usize, num_partial_products: usize, quotient_degree_factor: usize, degree_bits: usize, plonk_zeta: C::FE) -> IoResult<FriInstanceInfo<C::F, D>> {
        self.buf.0.set_position(self.offsets.fri_instance_batches_offset as u64);

        let fri_preprocessed_polys = FriPolynomialInfo::from_range(
            PlonkOracle::CONSTANTS_SIGMAS.index,
            0..num_constants + num_routed_wires
        );
        let fri_wire_polys = FriPolynomialInfo::from_range(
            PlonkOracle::WIRES.index,
            0..num_wires
        );
        let fri_zs_partial_products_polys = FriPolynomialInfo::from_range(
            PlonkOracle::ZS_PARTIAL_PRODUCTS.index,
            0..num_challenges * (1 + num_partial_products)
        );
        let fri_quotient_polys = FriPolynomialInfo::from_range(
            PlonkOracle::QUOTIENT.index,
            0..num_challenges * quotient_degree_factor
        );
        let all_fri_polynomials = [
            fri_preprocessed_polys,
            fri_wire_polys,
            fri_zs_partial_products_polys,
            fri_quotient_polys
        ].concat();
        let zeta_batch = FriBatchInfo {
            point: plonk_zeta,
            polynomials: all_fri_polynomials
        };

        let g = C::FE::primitive_root_of_unity(degree_bits);
        let zeta_next = g * plonk_zeta;
        let fri_zs_polys = FriPolynomialInfo::from_range(
            PlonkOracle::ZS_PARTIAL_PRODUCTS.index,
            0..num_challenges
        );
        let zeta_next_batch = FriBatchInfo {
            point: zeta_next,
            polynomials: fri_zs_polys
        };

        let batches = vec![zeta_batch, zeta_next_batch];

        Ok(FriInstanceInfo { oracles: FRI_ORACLES.to_vec(), batches })
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
    Ok(
        match tag {
            ARITHMETIC_BASE_TAG => ArithmeticGate::deserialize(buf)?,
            ARITHMETIC_EXT_TAG => ArithmeticExtensionGate::deserialize(buf)?,
            ASSERT_LE_TAG => AssertLessThanGate::deserialize(buf)?,
            // ! When serializing BaseSumGate, must prepend the limb base!
            BASE_SUM_TAG => {
                let base = buf[0];
                let buf = &buf[1..];

                base_sum_match_statement!(
                    base,
                    buf,
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
            _ => return Err(IoError::from(IoErrorKind::InvalidData))
        }
    )
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
        let tag = self.0.read_u8()?;
        let len = self.0.read_u64::<LittleEndian>()? as usize;
        let gate = read_gate::<C, D>(self.0.get_ref().as_ref(), tag)?;
        self.0.set_position(len as u64 + self.0.position());

        Ok(gate)
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

    fn write_usize_vec(
        &mut self,
        v: &[usize]
    ) -> IoResult<()> {
        for &a in v {
            self.0.write_u64::<LittleEndian>(a as u64)?;
        }

        Ok(())
    }
}