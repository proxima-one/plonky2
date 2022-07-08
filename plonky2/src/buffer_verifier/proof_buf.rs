use std::io::{Result as IoResult, SeekFrom, Seek};
use std::marker::PhantomData;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use plonky2_field::polynomial::PolynomialCoeffs;

use super::buf::Buffer;
use super::util::InnerHashForConfig;
use crate::fri::proof::FriQueryRound;
use crate::fri::structure::FriInstanceInfo;
use crate::hash::merkle_tree::MerkleCap;
use crate::plonk::config::{GenericConfig, Hasher};
use crate::plonk::proof::ProofChallenges;

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
    fri_pow_witness_offset: usize,
    fri_commit_phase_merkle_caps_offset: usize,
    fri_query_round_proofs_offset: usize,
    fri_final_poly_offset: usize,
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

pub(crate) const NUM_PROOF_BUF_OFFSETS: usize = 26;

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
    let fri_pow_witness_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_commit_phase_merkle_caps_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_query_round_proofs_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let fri_final_poly_offset = buf.0.read_u64::<LittleEndian>()? as usize;
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
        fri_pow_witness_offset,
        fri_commit_phase_merkle_caps_offset,
        fri_query_round_proofs_offset,
        fri_final_poly_offset,
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

    pub fn read_fri_pow_witness(&mut self) -> IoResult<C::F> {
        self.buf.0.set_position(self.offsets.fri_pow_witness_offset as u64);
        self.buf.read_field()
    }

    pub fn read_fri_commit_phase_merkle_caps(
        &mut self,
        reduction_arity_bits_len: usize,
        cap_height: usize
    ) -> IoResult<Vec<MerkleCap<C::F, C::Hasher>>> {
        self.buf
            .0
            .set_position(self.offsets.fri_commit_phase_merkle_caps_offset as u64);
        self.buf.read_fri_commit_phase_merkle_caps(reduction_arity_bits_len, cap_height)
    }
    
    pub fn read_fri_query_round_proof(
        &mut self,
        round: usize,
        hiding: bool,
        num_constants: usize,
        num_routed_wires: usize,
        num_wires: usize,
        num_challenges: usize,
        num_partial_products: usize,
        quotient_degree_factor: usize,
        reduction_arity_bits: &[usize],
    ) -> IoResult<FriQueryRound<C::F, C::Hasher, D>> {
        self.buf.0.set_position(self.offsets.fri_query_round_proofs_offset as u64);

        // seek to the `round`th round
        for _ in 0..round {
            let query_round_len = self.buf.0.read_u64::<LittleEndian>()?;
            self.buf.0.seek(SeekFrom::Current(query_round_len as i64))?;
        }
        self.buf.0.seek(SeekFrom::Current(std::mem::size_of::<u64>() as i64))?;

        self.buf.read_fri_query_round::<C::F, C, D>(
            hiding,
            num_constants,
            num_routed_wires,
            num_wires,
            num_challenges,
            num_partial_products,
            quotient_degree_factor,
            reduction_arity_bits,
        )
    }

    pub fn read_fri_final_poly(&mut self, fianl_poly_len: usize) -> IoResult<PolynomialCoeffs<C::FE>> {
        self.buf
            .0
            .set_position(self.offsets.fri_final_poly_offset as u64);

        let coeffs = self.buf.read_field_ext_vec::<C::F, D>(fianl_poly_len)?;
        Ok(PolynomialCoeffs { coeffs })
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

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use log::{info, Level};
    use plonky2_field::extension::Extendable;

    use super::*;
    use crate::{
        buffer_verifier::{serialization::serialize_proof_with_pis, fri_verifier::get_final_poly_len},
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

        let fri_pow_witness = proof_buf.read_fri_pow_witness()?;
        assert_eq!(fri_pow_witness, proof.proof.opening_proof.pow_witness);

        let fri_commit_phase_merkle_caps = proof_buf.read_fri_commit_phase_merkle_caps(
            common.fri_params.reduction_arity_bits.len(),
            cap_height
        )?;
        assert_eq!(
            fri_commit_phase_merkle_caps,
            proof.proof.opening_proof.commit_phase_merkle_caps
        );
        
        let num_query_rounds = common.fri_params.config.num_query_rounds;
        for round in 0..num_query_rounds {
            let fri_query_round_proof = proof_buf.read_fri_query_round_proof(
                round,
                common.fri_params.hiding,
                common.num_constants,
                common.config.num_routed_wires,
                common.config.num_wires,
                common.config.num_challenges,
                common.num_partial_products,
                common.quotient_degree_factor,
                common.fri_params.reduction_arity_bits.as_slice()
            )?;
            assert_eq!(
                fri_query_round_proof,
                proof.proof.opening_proof.query_round_proofs[round]
            );
        }

        let final_poly_len = get_final_poly_len(common.fri_params.reduction_arity_bits.as_slice(), common.fri_params.degree_bits);
        let fri_final_poly = proof_buf.read_fri_final_poly(final_poly_len)?;
        assert_eq!(fri_final_poly, proof.proof.opening_proof.final_poly);

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
