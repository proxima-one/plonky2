use anyhow::Result;
use plonky2::{
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
        prover::prove,
    },
    util::{gate_serialization::default::DefaultGateSerializer, timing::TimingTree},
};

fn main() -> Result<()> {
    let config = CircuitConfig::standard_recursion_config();

	let cd_file = File::open(".common_circuit_data")?;
	let mut cd_bytes = Vec::new();
	cd_file.read(&mut cd_bytes)?;
	let cd = CommonCircuitData::from_bytes(cd_bytes);
	

	let proof_file = File::open(".proof")?
}