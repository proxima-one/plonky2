use maru_stark::cpu::layout::*;
use maru_stark::cpu::maru_stark::MaruSTARK;
use maru_air::memory::MemorySegment;
use maru_air::trace::{AIRTrace, ExecutionTrace, ExecutionTraceRow};
use maru_stark::config::StarkConfig;
use maru_stark::proof::StarkProofWithPublicInputs;
use maru_stark::prover::prove;
use maru_stark::recursive_verifier::{
    add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target, verify_stark_proof_circuit,
};
use maru_stark::stark::Stark;
use maru_stark::util::trace_rows_to_poly_values;
use maru_stark::verifier::verify_stark_proof;
use maru_utils::pack_insn_u64;
use plonky2::field::extension_field::Extendable;
use plonky2::field::field_types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

// write a thing that generates exeuction trace for it
// generate a proof and hope it works

// first insn: copy f_n-1
// assert [ap] = [ap-2], increment pc by 1 and ap by 1
const FIRST_INSN: u64 = pack_insn_u64([0x8000, 0x7FFE, 0x8000, 0b0_1_010_1_1000_000_01_1]);

// second insn: calculate f_n
// assert [ap] = [ap-1] + [ap-4], increment pc by 1 and ap by 1
const SECOND_INSN: u64 = pack_insn_u64([0x7FFF, 0x7FFC, 0x8000, 0b0_1_010_1_0000_000_01_1]);

// third insn: decrement counter
// assert [ap - 3] = [ap] + 1, increment pc by 2 and ap by 1
const THIRD_INSN: u64 = pack_insn_u64([0x8000, 0x8001, 0x7FFD, 0b0_1_000_1_0000_000_01_1]);

// fourth insn: if counter is not 0, return to beginning
// jmp to zero if [ap - 1] != 0, increment pc by 2 otherwise
// HACK: op0 offset is -1 to avoid OOB access in memory array
const FOURTH_INSN: u64 = pack_insn_u64([0x7FFF, 0x8001, 0x7FFF, 0b0_1_000_1_1000_100_00_0]);

pub fn fib_bytecode<F: RichField + Extendable<D>, const D: usize>() -> [F; 6] {
    let mut bytecode = [F::ZERO; 6];

    // previous state:
    // ...
    // n - k
    // f(k-1)
    // f(k)
    // n - (k + 1)
    // _    <-ap

    // next state;
    // ...
    // n - k
    // f(k-1)
    // f(k)
    // n - (k + 1)
    // f(k)
    // f(k+1)
    // n - (k + 2)
    // _ <-ap

    bytecode[0] = F::from_canonical_u64(FIRST_INSN);
    bytecode[1] = F::from_canonical_u64(SECOND_INSN);
    bytecode[2] = F::from_canonical_u64(THIRD_INSN);
    // immediate value for third insn
    bytecode[3] = F::ONE;
    bytecode[4] = F::from_canonical_u64(FOURTH_INSN);
    // immediate value for fourth insn
    bytecode[5] = -F::from_canonical_u16(4);

    bytecode
}

fn fib_exec<F: RichField + Extendable<D>, const D: usize>(mut n: u64) -> ExecutionTrace<F, D> {
    let bytecode = fib_bytecode::<F, D>().to_vec();
    let code = MemorySegment {
        public_regions: vec![(0, bytecode.len())],
        contents: bytecode.clone(),
    };

    let segments = vec![code];
    let mut memory = Vec::new();

    // populate with initial values
    memory.push(F::ZERO);
    memory.push(F::ONE);
    memory.push(F::from_canonical_u64(n - 1));
    n -= 1;

    // start pc at first insn
    // start ap at 3 (addr after the initial values)
    // start SP at 0
    let mut trace = ExecutionTrace {
        rows: Vec::new(),
        segments: segments,
    };

    let mut pc = 0;
    let mut ap = 3;
    let sp = (0, F::ZERO);

    loop {
        let insn = bytecode[pc].to_canonical_u64();
        match insn {
            FIRST_INSN => {
                memory.push(memory[ap - 2]);
                let row = ExecutionTraceRow {
                    pc: F::from_canonical_u64(pc as u64),
                    ap: (1, F::from_canonical_u64(ap as u64)),
                    sp,
                    insn: F::from_canonical_u64(insn),
                    op0: (1, F::from_canonical_u64(ap as u64)),
                    op1: (1, F::from_canonical_u64((ap - 2) as u64)),
                    dst: (1, F::from_canonical_u64(ap as u64)),
                    res: memory[ap - 2],
                };
                trace.rows.push(row);

                pc += 1;
                ap += 1;
            }
            SECOND_INSN => {
                memory.push(memory[ap - 1] + memory[ap - 4]);
                let row = ExecutionTraceRow {
                    pc: F::from_canonical_u64(pc as u64),
                    ap: (1, F::from_canonical_u64(ap as u64)),
                    sp,
                    insn: F::from_canonical_u64(insn),
                    op0: (1, F::from_canonical_u64((ap - 1) as u64)),
                    op1: (1, F::from_canonical_u64((ap - 4) as u64)),
                    dst: (1, F::from_canonical_u64(ap as u64)),
                    res: memory[ap - 1] + memory[ap - 4],
                };
                trace.rows.push(row);

                pc += 1;
                ap += 1;
            }
            THIRD_INSN => {
                memory.push(memory[ap - 3] - F::ONE);
                let row = ExecutionTraceRow {
                    pc: F::from_canonical_u64(pc as u64),
                    ap: (1, F::from_canonical_u64(ap as u64)),
                    sp,
                    insn: F::from_canonical_u64(insn),
                    op0: (1, F::from_canonical_u64(ap as u64)),
                    op1: (0, F::from_canonical_u64((pc + 1) as u64)),
                    dst: (1, F::from_canonical_u64((ap as u64) - 3)),
                    res: memory[ap] + F::ONE,
                };
                trace.rows.push(row);

                pc += 2;
                ap += 1;
                n -= 1;
            }
            FOURTH_INSN => {
                let row = ExecutionTraceRow {
                    pc: F::from_canonical_u64(pc as u64),
                    ap: (1, F::from_canonical_u64(ap as u64)),
                    sp,
                    insn: F::from_canonical_u64(insn),
                    op0: (1, F::from_canonical_u64((ap - 1) as u64)),
                    op1: (0, F::from_canonical_u64((pc + 1) as u64)),
                    dst: (1, F::from_canonical_u64((ap - 1) as u64)),
                    res: F::ZERO,
                };
                trace.rows.push(row);

                if n == 0 {
                    pc += 2;
                    break;
                }
                let new_pc_as_field = F::from_canonical_u64(pc as u64) + bytecode[pc + 1];
                pc = new_pc_as_field.to_canonical_u64() as usize;
            }
            _ => panic!("unexpected insn!"),
        }
    }

    let last_row = trace.rows.last().unwrap();

    trace.segments.push(MemorySegment {
        contents: memory,
        public_regions: vec![(0, 2), (last_row.ap.1.to_canonical_u64() as usize - 2, 2)],
    });

    trace
}

#[cfg(test)]
use anyhow::Result;

#[test]
fn test_fib() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type S = MaruSTARK<F, D>;

    let trace = fib_exec::<F, D>(16);
    let trace = AIRTrace::<F, D>::from(trace);

    let last_row = trace.rows.last().unwrap();
    // final PC should be in RES_COL. This is enforced because we constrain res <- pc when we add the dummy accesses
    let final_pc = last_row[RES_COL];
    // all dummy insns constrained such Athat ap stays the same, so ap at the end should be the same as the final ap
    // before dummy rows were added
    let final_ap = last_row[AP_COL];

    let mut public_inputs = [F::ZERO; NUM_PUBLIC_INPUTS];
    public_inputs[PC_INITIAL] = F::ZERO;
    public_inputs[PC_FINAL] = final_pc;
    // bytecode (0th segment) is 7 words long, and should start at the 3rd word of first segment
    public_inputs[AP_INITIAL] = F::from_canonical_u16(9);
    public_inputs[AP_FINAL] = final_ap;
    public_inputs[SP_INITIAL] = F::ZERO;
    public_inputs[RC_MIN] = F::ZERO;
    public_inputs[RC_MAX] = last_row[ADDR_SORTED_COLS[3]];

    let stark = trace.to_stark();
    let trace_poly_values = trace_rows_to_poly_values(trace.rows);
    let config = StarkConfig::standard_fast_config();

    let proof = prove::<F, C, S, D>(
        stark.clone(),
        &config,
        trace_poly_values,
        public_inputs,
        &mut TimingTree::default(),
    )?;

    verify_stark_proof(stark, proof, &config)
}

#[test]
fn test_fib_recursive() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type S = MaruSTARK<F, D>;
    init_logger();

    let trace = fib_exec::<F, D>(16);
    let trace = AIRTrace::<F, D>::from(trace);

    let last_row = trace.rows.last().unwrap();
    let final_pc = last_row[RES_COL];
    let final_ap = last_row[AP_COL];

    let mut public_inputs = [F::ZERO; NUM_PUBLIC_INPUTS];
    public_inputs[PC_INITIAL] = F::ZERO;
    public_inputs[PC_FINAL] = final_pc;
    // bytecode (0th segment) is 7 words long, and should start at the 3rd word of first segment
    public_inputs[AP_INITIAL] = F::from_canonical_u16(9);
    public_inputs[AP_FINAL] = final_ap;
    public_inputs[SP_INITIAL] = F::ZERO;
    public_inputs[RC_MIN] = F::ZERO;
    public_inputs[RC_MAX] = last_row[ADDR_SORTED_COLS[3]];

    let stark = MaruSTARK::from_trace(&trace);
    let trace_poly_values = trace_rows_to_poly_values(trace.rows);
    let config = StarkConfig::standard_fast_config();

    let proof = prove::<F, C, S, D>(
        stark.clone(),
        &config,
        trace_poly_values,
        public_inputs,
        &mut TimingTree::default(),
    )?;

    verify_stark_proof(stark.clone(), proof.clone(), &config)?;

    recursive_proof::<F, C, S, C, D>(stark, proof, &config, true)?;
    Ok(())
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D> + Clone,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    stark: S,
    inner_proof: StarkProofWithPublicInputs<F, InnerC, D>,
    inner_config: &StarkConfig,
    print_gate_counts: bool,
) -> Result<()>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
    [(); C::Hasher::HASH_SIZE]:,
{
    let circuit_config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
    let mut pw = PartialWitness::new();
    let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
    let pt =
        add_virtual_stark_proof_with_pis(&mut builder, stark.clone(), inner_config, degree_bits);
    set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof);

    verify_stark_proof_circuit::<F, InnerC, S, D>(&mut builder, stark, pt, inner_config);

    if print_gate_counts {
        builder.print_gate_counts(0);
    }

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;
    data.verify(proof)
}

fn init_logger() {
    let _ = env_logger::builder().format_timestamp(None).try_init();
}
