use std::io::{
    Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Seek, SeekFrom,
    Write,
};
use std::ops::Range;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::{Field64, PrimeField64};

use plonky2::fri::proof::{FriInitialTreeProof, FriQueryRound, FriQueryStep};
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::structure::{FriBatchInfo, FriOracleInfo, FriPolynomialInfo};
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::assert_le::AssertLessThanGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::gate::{Gate, GateBox};
use plonky2::gates::interpolation::HighDegreeInterpolationGate;
use plonky2::gates::low_degree_interpolation::LowDegreeInterpolationGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use plonky2::plonk::plonk_common::salt_size;

pub struct Buffer<R: AsRef<[u8]>>(pub(crate) Cursor<R>);

impl<R: AsRef<[u8]>> Buffer<R> {
    pub(crate) fn new(buffer: R) -> Self {
        Self(Cursor::new(buffer))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.get_ref().as_ref().len()
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.0.get_ref().as_ref().to_vec()
    }

    pub(crate) fn read_range(&mut self) -> IoResult<Range<usize>> {
        let start = self.0.read_u64::<LittleEndian>()? as usize;
        let end = self.0.read_u64::<LittleEndian>()? as usize;
        Ok(Range { start, end })
    }

    pub(crate) fn read_bool(&mut self) -> IoResult<bool> {
        Ok(self.0.read_u8()? != 0)
    }

    pub(crate) fn read_field<F: Field64>(&mut self) -> IoResult<F> {
        Ok(F::from_canonical_u64(self.0.read_u64::<LittleEndian>()?))
    }

    pub(crate) fn read_field_ext<F: RichField + Extendable<D>, const D: usize>(
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

    pub(crate) fn read_hash<F: RichField, H: Hasher<F>>(&mut self) -> IoResult<H::Hash> {
        let mut buf = vec![0; H::HASH_SIZE];
        self.0.read_exact(&mut buf)?;
        Ok(H::Hash::from_bytes(&buf))
    }

    pub(crate) fn read_merkle_cap<F: RichField, H: Hasher<F>>(
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

    pub(crate) fn read_field_vec<F: Field64>(&mut self, length: usize) -> IoResult<Vec<F>> {
        (0..length)
            .map(|_| self.read_field())
            .collect::<IoResult<Vec<_>>>()
    }

    pub(crate) fn read_field_ext_vec<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        length: usize,
    ) -> IoResult<Vec<F::Extension>> {
        (0..length)
            .map(|_| self.read_field_ext::<F, D>())
            .collect::<IoResult<Vec<_>>>()
    }

    pub(crate) fn read_bool_vec(&mut self, len: usize) -> IoResult<Vec<bool>> {
        let mut res = Vec::with_capacity(len);
        for _ in 0..len {
            res.push(self.read_bool()?);
        }

        Ok(res)
    }

    pub(crate) fn read_usize_vec(&mut self, len: usize) -> IoResult<Vec<usize>> {
        let mut res = Vec::with_capacity(len);
        for _ in 0..len {
            res.push(self.0.read_u64::<LittleEndian>()? as usize);
        }

        Ok(res)
    }

    pub(crate) fn read_range_vec(&mut self, len: usize) -> IoResult<Vec<Range<usize>>> {
        let mut res = Vec::with_capacity(len);
        for _ in 0..len {
            res.push(self.read_range()?);
        }

        Ok(res)
    }

    pub(crate) fn read_gate<C: GenericConfig<D>, const D: usize>(
        &mut self,
    ) -> IoResult<GateBox<C::F, D>> {
        let len = self.0.read_u64::<LittleEndian>()? as usize;
        let tag = self.0.read_u8()?;
        let position = self.0.position() as usize;
        let buf = self.0.get_ref().as_ref();
        let gate = read_gate::<C, D>(&buf[position..], tag)?;
        self.0.set_position(len as u64 + self.0.position() - 1);

        Ok(gate)
    }

    pub(crate) fn read_fri_reduction_strategy(&mut self) -> IoResult<FriReductionStrategy> {
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

    pub(crate) fn read_fri_oracle_info(&mut self) -> IoResult<FriOracleInfo> {
        let blinding = self.read_bool()?;
        Ok(FriOracleInfo { blinding })
    }

    pub(crate) fn read_fri_polynomial_info(&mut self) -> IoResult<FriPolynomialInfo> {
        let oracle_index = self.0.read_u64::<LittleEndian>()? as usize;
        let polynomial_index = self.0.read_u64::<LittleEndian>()? as usize;
        Ok(FriPolynomialInfo {
            oracle_index,
            polynomial_index,
        })
    }

    pub(crate) fn read_fri_batch_info<F: RichField + Extendable<D>, const D: usize>(
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

    pub fn read_fri_commit_phase_merkle_caps<
        F: RichField + Extendable<D>,
        H: Hasher<F>,
        const D: usize,
    >(
        &mut self,
        reduction_arity_bits_len: usize,
        cap_height: usize,
    ) -> IoResult<Vec<MerkleCap<F, H>>> {
        let mut caps = Vec::new();
        for _ in 0..reduction_arity_bits_len {
            let cap = self.read_merkle_cap(cap_height)?;
            caps.push(cap);
        }

        Ok(caps)
    }

    fn read_merkle_proof<F: RichField, H: Hasher<F>>(&mut self) -> IoResult<MerkleProof<F, H>> {
        let length = self.0.read_u8()?;
        Ok(MerkleProof {
            siblings: (0..length)
                .map(|_| self.read_hash::<F, H>())
                .collect::<IoResult<Vec<_>>>()?,
        })
    }

    fn read_fri_initial_tree_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        hiding: bool,
        num_constants: usize,
        num_routed_wires: usize,
        num_wires: usize,
        num_challenges: usize,
        num_partial_products: usize,
        quotient_degree_factor: usize,
    ) -> IoResult<FriInitialTreeProof<F, C::Hasher>> {
        let salt = salt_size(hiding);
        let mut evals_proofs = Vec::with_capacity(4);

        let constants_sigmas_v = self.read_field_vec(num_constants + num_routed_wires)?;
        let constants_sigmas_p = self.read_merkle_proof()?;
        evals_proofs.push((constants_sigmas_v, constants_sigmas_p));

        let wires_v = self.read_field_vec(num_wires + salt)?;
        let wires_p = self.read_merkle_proof()?;
        evals_proofs.push((wires_v, wires_p));

        let zs_partial_v =
            self.read_field_vec(num_challenges * (1 + num_partial_products) + salt)?;
        let zs_partial_p = self.read_merkle_proof()?;
        evals_proofs.push((zs_partial_v, zs_partial_p));

        let quotient_v = self.read_field_vec(num_challenges * quotient_degree_factor + salt)?;
        let quotient_p = self.read_merkle_proof()?;
        evals_proofs.push((quotient_v, quotient_p));

        Ok(FriInitialTreeProof { evals_proofs })
    }

    fn read_fri_query_step<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        arity: usize,
        compressed: bool,
    ) -> IoResult<FriQueryStep<F, C::Hasher, D>> {
        let evals = self.read_field_ext_vec::<F, D>(arity - if compressed { 1 } else { 0 })?;
        let merkle_proof = self.read_merkle_proof()?;
        Ok(FriQueryStep {
            evals,
            merkle_proof,
        })
    }

    pub(crate) fn read_fri_query_round<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        hiding: bool,
        num_constants: usize,
        num_routed_wires: usize,
        num_wires: usize,
        num_challenges: usize,
        num_partial_products: usize,
        quotient_degree_factor: usize,
        reduction_arity_bits: &[usize],
    ) -> IoResult<FriQueryRound<F, C::Hasher, D>> {
        let initial_trees_proof = self.read_fri_initial_tree_proof::<F, C, D>(
            hiding,
            num_constants,
            num_routed_wires,
            num_wires,
            num_challenges,
            num_partial_products,
            quotient_degree_factor,
        )?;
        let steps = reduction_arity_bits
            .iter()
            .map(|&ar| self.read_fri_query_step::<F, C, D>(1 << ar, false))
            .collect::<IoResult<_>>()?;
        Ok(FriQueryRound {
            initial_trees_proof,
            steps,
        })
    }
}

impl<'a> Buffer<&'a mut [u8]> {
    pub(crate) fn write_field<F: PrimeField64>(&mut self, x: F) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(x.to_canonical_u64())
    }

    pub(crate) fn write_field_ext<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        x: F::Extension,
    ) -> IoResult<()> {
        for &a in &x.to_basefield_array() {
            self.write_field(a)?;
        }
        Ok(())
    }

    pub(crate) fn write_hash<F: RichField, H: Hasher<F>>(&mut self, h: H::Hash) -> IoResult<()> {
        self.0.write_all(&h.to_bytes())
    }

    pub(crate) fn write_merkle_cap<F: RichField, H: Hasher<F>>(
        &mut self,
        cap: &MerkleCap<F, H>,
    ) -> IoResult<()> {
        for &a in &cap.0 {
            self.write_hash::<F, H>(a)?;
        }
        Ok(())
    }

    pub(crate) fn write_merkle_proof<F: RichField, H: Hasher<F>>(
        &mut self,
        p: &MerkleProof<F, H>,
    ) -> IoResult<()> {
        let length = p.siblings.len();
        self.0.write_u8(
            length
                .try_into()
                .expect("Merkle proof length must fit in u8."),
        )?;
        for &h in &p.siblings {
            self.write_hash::<F, H>(h)?;
        }
        Ok(())
    }

    pub(crate) fn write_field_vec<F: PrimeField64>(&mut self, v: &[F]) -> IoResult<()> {
        for &a in v {
            self.write_field(a)?;
        }
        Ok(())
    }

    pub(crate) fn write_field_ext_vec<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        v: &[F::Extension],
    ) -> IoResult<()> {
        for &a in v {
            self.write_field_ext::<F, D>(a)?;
        }
        Ok(())
    }

    pub(crate) fn write_usize_vec(&mut self, v: &[usize]) -> IoResult<()> {
        for &a in v {
            self.0.write_u64::<LittleEndian>(a as u64)?;
        }
        Ok(())
    }

    pub(crate) fn write_range_vec(&mut self, v: &[Range<usize>]) -> IoResult<()> {
        for &Range { start, end } in v {
            self.0.write_u64::<LittleEndian>(start as u64)?;
            self.0.write_u64::<LittleEndian>(end as u64)?;
        }
        Ok(())
    }

    pub(crate) fn write_gate<C: GenericConfig<D>, const D: usize>(
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

    pub(crate) fn write_gates<C: GenericConfig<D>, const D: usize>(
        &mut self,
        gates: &[GateBox<C::F, D>],
    ) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(gates.len() as u64)?;
        for gate in gates {
            self.write_gate::<C, D>(gate)?;
        }

        Ok(())
    }

    pub(crate) fn write_fri_reduction_strategy(
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

    pub(crate) fn write_fri_oracle_info(&mut self, info: &FriOracleInfo) -> IoResult<()> {
        self.0.write_u8(info.blinding as u8)
    }

    pub(crate) fn write_fri_polynomial_info(&mut self, info: &FriPolynomialInfo) -> IoResult<()> {
        self.0.write_u64::<LittleEndian>(info.oracle_index as u64)?;
        self.0
            .write_u64::<LittleEndian>(info.polynomial_index as u64)
    }

    pub(crate) fn write_fri_batch_info<F: RichField + Extendable<D>, const D: usize>(
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

    pub fn write_fri_commit_phase_merkle_caps<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        commit_phase_merkle_caps: &[MerkleCap<F, C::Hasher>],
    ) -> IoResult<()> {
        for cap in commit_phase_merkle_caps.iter() {
            self.write_merkle_cap(cap)?
        }

        Ok(())
    }

    pub(crate) fn write_fri_initial_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        fitp: &FriInitialTreeProof<F, C::Hasher>,
    ) -> IoResult<()> {
        for (v, p) in &fitp.evals_proofs {
            self.write_field_vec(v)?;
            self.write_merkle_proof(p)?;
        }
        Ok(())
    }

    pub(crate) fn write_fri_query_step<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        fqs: &FriQueryStep<F, C::Hasher, D>,
    ) -> IoResult<()> {
        self.write_field_ext_vec::<F, D>(&fqs.evals)?;
        self.write_merkle_proof(&fqs.merkle_proof)
    }

    pub(crate) fn write_fri_query_round<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        fqr: &FriQueryRound<F, C::Hasher, D>,
    ) -> IoResult<()> {
        let prepos = self.0.position();
        self.write_fri_initial_proof::<F, C, D>(&fqr.initial_trees_proof)?;
        for fqs in &fqr.steps {
            self.write_fri_query_step::<F, C, D>(fqs)?;
        }

        Ok(())
    }

    pub(crate) fn write_fri_query_rounds<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &mut self,
        fqrs: &[FriQueryRound<F, C::Hasher, D>],
    ) -> IoResult<()> {
        for fqr in fqrs {
            let len_offset = self.0.position();
            self.0
                .set_position(len_offset + std::mem::size_of::<u64>() as u64);
            self.write_fri_query_round::<F, C, D>(fqr)?;

            let len = self.0.position() - len_offset - (std::mem::size_of::<u64>() as u64);
            let tmp = self.0.position();
            self.0.set_position(len_offset);
            self.0.write_u64::<LittleEndian>(len)?;
            self.0.set_position(tmp);
        }

        Ok(())
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
