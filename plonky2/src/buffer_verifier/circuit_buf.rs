use std::io::Result as IoResult;
use std::marker::PhantomData;

use byteorder::{LittleEndian, ReadBytesExt};

use super::buf::Buffer;
use super::util::HashForConfig;
use crate::fri::reduction_strategies::FriReductionStrategy;
use crate::gates::gate::GateBox;
use crate::gates::selectors::SelectorsInfo;
use crate::hash::merkle_tree::MerkleCap;
use crate::plonk::config::GenericConfig;

pub struct CircuitBuf<C: GenericConfig<D>, R: AsRef<[u8]>, const D: usize> {
    buf: Buffer<R>,
    offsets: CircuitBufOffsets,
    _phantom: PhantomData<C>,
}

pub struct CircuitBufOffsets {
    len: usize,
    circuit_digest_offset: usize,
    num_pis_offset: usize,
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

pub(crate) const NUM_CIRCUIT_BUF_OFFSETS: usize = 23;

fn get_circuit_buf_offsets<R: AsRef<[u8]>>(buf: &mut Buffer<R>) -> IoResult<CircuitBufOffsets> {
    let len = buf.0.read_u64::<LittleEndian>()? as usize;
    let circuit_digest_offset = buf.0.read_u64::<LittleEndian>()? as usize;
    let num_pis_offset = buf.0.read_u64::<LittleEndian>()? as usize;
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
        num_pis_offset,
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

    pub fn read_num_pis(&mut self) -> IoResult<usize> {
        self.buf.0.set_position(self.offsets.num_pis_offset as u64);
        Ok(self.buf.0.read_u64::<LittleEndian>()? as usize)
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
#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use log::{info, Level};
    use plonky2_field::extension::Extendable;

    use super::*;
    use crate::{
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
            config::{Hasher, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
            prover::prove,
        },
        util::timing::TimingTree, gates::noop::NoopGate, buffer_verifier::serialization::serialize_circuit_data,
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
}
