use plonky2::field::extension_field::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::layout::*;
use crate::constraint_consumer::RecursiveConstraintConsumer;

pub(crate) fn constrain_insn_recursively<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    curr_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    constrainer: &mut RecursiveConstraintConsumer<F, D>,
) {
    for i in 0..16 {
        let is_one = builder.add_const_extension(curr_row[FLAG_COLS[i]], -F::ONE);
        let is_one_or_zero = builder.mul_extension(is_one, curr_row[FLAG_COLS[i]]);
        constrainer.constraint(builder, is_one_or_zero);
    }

    let mut packed_insn_target = builder.zero_extension();
    for i in 0..16 {
        packed_insn_target = builder.mul_const_add_extension(
            F::from_canonical_u16(1 << (15 - i)),
            curr_row[FLAG_COLS[i]],
            packed_insn_target,
        );
    }
    packed_insn_target =
        builder.mul_const_extension(F::from_canonical_u64(1 << 48), packed_insn_target);
    packed_insn_target = builder.add_extension(packed_insn_target, curr_row[OP0_OFFSET_COL]);
    packed_insn_target = builder.mul_const_add_extension(
        F::from_canonical_u32(1 << 16),
        curr_row[OP1_OFFSET_COL],
        packed_insn_target,
    );
    packed_insn_target = builder.mul_const_add_extension(
        F::from_canonical_u64(1 << 32),
        curr_row[DST_OFFSET_COL],
        packed_insn_target,
    );
    let diff = builder.sub_extension(packed_insn_target, curr_row[PC_MEM_COL]);
    let is_not_dummy_insn = builder.add_const_extension(curr_row[FLAG_COLS[0]], -F::ONE);
    let filtered_diff = builder.mul_extension(is_not_dummy_insn, diff);
    constrainer.constraint(builder, filtered_diff);
}

pub(crate) fn constrain_state_transition_recursively<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    curr_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    next_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    constrainer: &mut RecursiveConstraintConsumer<F, D>,
) {
    let zero = builder.zero_extension();
    let one = builder.one_extension();

    let is_dummy_insn = curr_row[FLAG_COLS[0]];
    let is_not_dummy_insn = builder.sub_extension(one, is_dummy_insn);

    // get offsets
    let op0_offset =
        builder.add_const_extension(curr_row[OP0_OFFSET_COL], -F::from_canonical_u16(1 << 15));
    let op1_offset =
        builder.add_const_extension(curr_row[OP1_OFFSET_COL], -F::from_canonical_u16(1 << 15));
    let dst_offset =
        builder.add_const_extension(curr_row[DST_OFFSET_COL], -F::from_canonical_u16(1 << 15));

    // dst
    let dst_addressing_mode_sp = builder.sub_extension(one, curr_row[FLAG_COLS[1]]);
    let dst_addressing_mode_ap = curr_row[FLAG_COLS[1]];

    let sp_plus_offset = builder.add_extension(dst_offset, curr_row[SP_COL]);
    let dst_sp_mode_constraint = builder.sub_extension(curr_row[DST_COL], sp_plus_offset);
    let ap_plus_offset = builder.add_extension(dst_offset, curr_row[AP_COL]);
    let dst_ap_mode_constraint = builder.sub_extension(curr_row[DST_COL], ap_plus_offset);
    let mut dst_addr_constraint = builder.inner_product_extension(
        F::ONE,
        zero,
        vec![
            (dst_addressing_mode_sp, dst_sp_mode_constraint),
            (dst_addressing_mode_ap, dst_ap_mode_constraint),
        ],
    );
    dst_addr_constraint = builder.mul_extension(dst_addr_constraint, is_not_dummy_insn);
    constrainer.constraint(builder, dst_addr_constraint);

    // op1
    let op1_addressing_mode_sp = curr_row[FLAG_COLS[4]];
    let op1_addressing_mode_ap = curr_row[FLAG_COLS[3]];
    let op1_addressing_mode_op0 = curr_row[FLAG_COLS[2]];
    let mut op1_addressing_mode_pc = builder.sub_extension(one, curr_row[FLAG_COLS[2]]);
    op1_addressing_mode_pc = builder.sub_extension(op1_addressing_mode_pc, curr_row[FLAG_COLS[3]]);
    op1_addressing_mode_pc = builder.sub_extension(op1_addressing_mode_pc, curr_row[FLAG_COLS[4]]);

    let pc_plus_offset = builder.add_extension(curr_row[PC_COL], op1_offset);
    let sp_plus_offset = builder.add_extension(curr_row[SP_COL], op1_offset);
    let ap_plus_offset = builder.add_extension(curr_row[AP_COL], op1_offset);
    let op0_plus_offset = builder.add_extension(curr_row[OP0_COL], op1_offset);

    let op1_pc_mode_constraint = builder.sub_extension(curr_row[OP1_COL], pc_plus_offset);
    let op1_sp_mode_constraint = builder.sub_extension(curr_row[OP1_COL], sp_plus_offset);
    let op1_ap_mode_constraint = builder.sub_extension(curr_row[OP1_COL], ap_plus_offset);
    let op1_op0_mode_constraint = builder.sub_extension(curr_row[OP1_COL], op0_plus_offset);

    let mut op1_addr_constraint = builder.inner_product_extension(
        F::ONE,
        zero,
        vec![
            (op1_addressing_mode_pc, op1_pc_mode_constraint),
            (op1_addressing_mode_sp, op1_sp_mode_constraint),
            (op1_addressing_mode_ap, op1_ap_mode_constraint),
            (op1_addressing_mode_op0, op1_op0_mode_constraint),
        ],
    );
    op1_addr_constraint = builder.mul_extension(op1_addr_constraint, is_not_dummy_insn);
    constrainer.constraint(builder, op1_addr_constraint);

    // op0
    let op0_addressing_mode_sp = builder.sub_extension(one, curr_row[FLAG_COLS[5]]);
    let op0_addressing_mode_ap = curr_row[FLAG_COLS[5]];

    let sp_plus_offset = builder.add_extension(op0_offset, curr_row[SP_COL]);
    let op0_sp_mode_constraint = builder.sub_extension(curr_row[OP0_COL], sp_plus_offset);
    let ap_plus_offset = builder.add_extension(op0_offset, curr_row[AP_COL]);
    let op0_ap_mode_constraint = builder.sub_extension(curr_row[OP0_COL], ap_plus_offset);
    let mut op0_addr_constraint = builder.inner_product_extension(
        F::ONE,
        zero,
        vec![
            (op0_addressing_mode_sp, op0_sp_mode_constraint),
            (op0_addressing_mode_ap, op0_ap_mode_constraint),
        ],
    );
    op0_addr_constraint = builder.mul_extension(op0_addr_constraint, is_not_dummy_insn);
    constrainer.constraint(builder, op0_addr_constraint);

    // opcodes
    let is_jnz = curr_row[FLAG_COLS[10]];
    let is_not_jnz = builder.sub_extension(one, is_jnz);

    let opcode_mul = curr_row[FLAG_COLS[9]];
    let opcode_call = curr_row[FLAG_COLS[8]];
    let opcode_ret = curr_row[FLAG_COLS[7]];
    let opcode_mov = curr_row[FLAG_COLS[6]];
    let mut opcode_add = builder.sub_extension(one, curr_row[FLAG_COLS[6]]);
    opcode_add = builder.sub_extension(opcode_add, curr_row[FLAG_COLS[7]]);
    opcode_add = builder.sub_extension(opcode_add, curr_row[FLAG_COLS[8]]);
    opcode_add = builder.sub_extension(opcode_add, curr_row[FLAG_COLS[9]]);

    let mut tmp_3_constraint = builder.mul_extension(is_not_jnz, opcode_mov);
    tmp_3_constraint = builder.sub_extension(curr_row[TMP_3_COL], tmp_3_constraint);
    constrainer.constraint(builder, tmp_3_constraint);

    let mut tmp_4_constraint = builder.sub_extension(zero, curr_row[OP0_MEM_COL]);
    tmp_4_constraint =
        builder.mul_add_extension(tmp_4_constraint, curr_row[OP1_MEM_COL], curr_row[TMP_4_COL]);
    constrainer.constraint(builder, tmp_4_constraint);

    let mut opcode_add_constraint =
        builder.add_extension(curr_row[OP0_MEM_COL], curr_row[OP1_MEM_COL]);
    opcode_add_constraint = builder.sub_extension(curr_row[RES_COL], opcode_add_constraint);
    let opcode_mul_constraint = builder.sub_extension(curr_row[RES_COL], curr_row[TMP_4_COL]);
    let opcode_mov_constraint = builder.sub_extension(curr_row[RES_COL], curr_row[OP1_MEM_COL]);
    let mut res_constraint = builder.inner_product_extension(
        F::ONE,
        zero,
        vec![
            (opcode_add, opcode_add_constraint),
            (opcode_mul, opcode_mul_constraint),
            (curr_row[TMP_3_COL], opcode_mov_constraint),
        ],
    );
    res_constraint = builder.mul_extension(is_not_dummy_insn, res_constraint);
    constrainer.constraint(builder, res_constraint);

    // call
    let is_not_imm = builder.sub_extension(one, op1_addressing_mode_pc);
    let mut insn_size =
        builder.mul_const_extension(F::from_canonical_u16(2), op1_addressing_mode_pc);
    insn_size = builder.add_extension(insn_size, is_not_imm);

    let mut sp_in_dst_when_call_constraint =
        builder.sub_extension(curr_row[SP_COL], curr_row[DST_MEM_COL]);
    sp_in_dst_when_call_constraint =
        builder.mul_extension(opcode_call, sp_in_dst_when_call_constraint);
    sp_in_dst_when_call_constraint =
        builder.mul_extension(is_not_dummy_insn, sp_in_dst_when_call_constraint);
    constrainer.constraint(builder, sp_in_dst_when_call_constraint);

    let mut pc_at_op0_when_call_constraint =
        builder.sub_extension(curr_row[OP0_MEM_COL], curr_row[PC_COL]);
    pc_at_op0_when_call_constraint =
        builder.sub_extension(pc_at_op0_when_call_constraint, insn_size);
    pc_at_op0_when_call_constraint =
        builder.mul_extension(opcode_call, pc_at_op0_when_call_constraint);
    pc_at_op0_when_call_constraint =
        builder.mul_extension(is_not_dummy_insn, pc_at_op0_when_call_constraint);
    constrainer.constraint(builder, pc_at_op0_when_call_constraint);

    // pc update
    let jmp_abs = curr_row[FLAG_COLS[12]];
    let jmp_rel = curr_row[FLAG_COLS[11]];
    let mut pc_update_next_insn = builder.sub_extension(one, is_jnz);
    pc_update_next_insn = builder.sub_extension(pc_update_next_insn, curr_row[FLAG_COLS[11]]);
    pc_update_next_insn = builder.sub_extension(pc_update_next_insn, curr_row[FLAG_COLS[12]]);

    let next_is_not_dummy_insn = builder.sub_extension(one, next_row[FLAG_COLS[0]]);
    let next_insn_addr = builder.add_extension(curr_row[PC_COL], insn_size);
    let jmp_rel_addr = builder.add_extension(curr_row[PC_COL], curr_row[RES_COL]);

    let mut tmp_2_constraint = builder.mul_extension(is_not_dummy_insn, next_is_not_dummy_insn);
    tmp_2_constraint = builder.sub_extension(curr_row[TMP_2_COL], tmp_2_constraint);
    constrainer.constraint_transition(builder, tmp_2_constraint);

    let mut non_jnz_constraint = builder.mul_extension(is_not_jnz, next_row[PC_COL]);
    non_jnz_constraint = builder.inner_product_extension(
        -F::ONE,
        non_jnz_constraint,
        vec![
            (pc_update_next_insn, next_insn_addr),
            (jmp_abs, curr_row[RES_COL]),
            (jmp_rel, jmp_rel_addr),
        ],
    );
    non_jnz_constraint = builder.mul_extension(curr_row[TMP_2_COL], non_jnz_constraint);
    constrainer.constraint_transition(builder, non_jnz_constraint);

    // jnz
    let mut tmp_0_constraint = builder.mul_extension(curr_row[DST_MEM_COL], curr_row[RES_COL]);
    tmp_0_constraint = builder.mul_extension(is_jnz, tmp_0_constraint);
    tmp_0_constraint = builder.sub_extension(curr_row[TMP_0_COL], tmp_0_constraint);
    constrainer.constraint(builder, tmp_0_constraint);

    let mut dst_neq_zero_constraint =
        builder.add_extension(curr_row[PC_COL], curr_row[OP1_MEM_COL]);
    dst_neq_zero_constraint = builder.sub_extension(next_row[PC_COL], dst_neq_zero_constraint);
    dst_neq_zero_constraint = builder.mul_extension(curr_row[TMP_2_COL], dst_neq_zero_constraint);
    dst_neq_zero_constraint = builder.mul_extension(curr_row[TMP_0_COL], dst_neq_zero_constraint);
    constrainer.constraint_transition(builder, dst_neq_zero_constraint);

    let sel = builder.sub_extension(is_jnz, curr_row[TMP_0_COL]);
    let mut dst_eq_zero_constraint = builder.add_extension(curr_row[PC_COL], insn_size);
    dst_eq_zero_constraint = builder.sub_extension(next_row[PC_COL], dst_eq_zero_constraint);
    dst_eq_zero_constraint = builder.mul_extension(curr_row[TMP_2_COL], dst_eq_zero_constraint);
    dst_eq_zero_constraint = builder.mul_extension(sel, dst_eq_zero_constraint);
    constrainer.constraint_transition(builder, dst_eq_zero_constraint);

    // ap update
    let ap_inc = curr_row[FLAG_COLS[14]];
    let ap_add_res = curr_row[FLAG_COLS[13]];
    let mut ap_update_constraint =
        builder.mul_const_add_extension(F::from_canonical_u16(2), opcode_call, curr_row[AP_COL]);
    ap_update_constraint =
        builder.mul_add_extension(curr_row[RES_COL], ap_add_res, ap_update_constraint);
    ap_update_constraint = builder.add_extension(ap_inc, ap_update_constraint);
    ap_update_constraint = builder.sub_extension(next_row[AP_COL], ap_update_constraint);
    ap_update_constraint = builder.mul_extension(is_not_dummy_insn, ap_update_constraint);
    constrainer.constraint_transition(builder, ap_update_constraint);

    // sp update
    let mut sp_update_constraint = builder.sub_extension(one, opcode_ret);
    sp_update_constraint = builder.sub_extension(sp_update_constraint, opcode_call);
    sp_update_constraint = builder.mul_extension(curr_row[SP_COL], sp_update_constraint);
    let sp_update_tmp = builder.add_const_extension(curr_row[AP_COL], F::from_canonical_u16(2));
    sp_update_constraint =
        builder.mul_add_extension(opcode_call, sp_update_tmp, sp_update_constraint);
    sp_update_constraint =
        builder.mul_add_extension(opcode_ret, curr_row[DST_MEM_COL], sp_update_constraint);
    sp_update_constraint = builder.sub_extension(next_row[SP_COL], sp_update_constraint);
    sp_update_constraint = builder.mul_extension(is_not_dummy_insn, sp_update_constraint);
    constrainer.constraint_transition(builder, sp_update_constraint);

    // assertion
    let assert_dst_eq_res = curr_row[FLAG_COLS[15]];
    let mut assert_constraint = builder.sub_extension(curr_row[DST_MEM_COL], curr_row[RES_COL]);
    assert_constraint = builder.mul_extension(assert_dst_eq_res, assert_constraint);
    assert_constraint = builder.mul_extension(is_not_dummy_insn, assert_constraint);
    constrainer.constraint(builder, assert_constraint);

    // dummy access insns

    let is_dummy_access_insn = builder.mul_extension(is_dummy_insn, curr_row[FLAG_COLS[15]]);

    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[PC_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[OP0_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[OP1_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[DST_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);

    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[PC_MEM_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[OP0_MEM_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[OP1_MEM_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);
    let dummy_access_zero_constraint =
        builder.mul_extension(is_dummy_access_insn, curr_row[DST_MEM_COL]);
    constrainer.constraint(builder, dummy_access_zero_constraint);

    let mut keep_ap_same_for_dummy_access_constraint =
        builder.sub_extension(next_row[AP_COL], curr_row[AP_COL]);
    keep_ap_same_for_dummy_access_constraint = builder.mul_extension(
        is_dummy_access_insn,
        keep_ap_same_for_dummy_access_constraint,
    );
    constrainer.constraint_transition(builder, keep_ap_same_for_dummy_access_constraint);

    // transition from non-dummy to dummy

    let mut tmp_1_constraint =
        builder.mul_extension(next_row[FLAG_COLS[15]], next_row[FLAG_COLS[0]]);
    tmp_1_constraint = builder.sub_extension(curr_row[TMP_1_COL], tmp_1_constraint);
    constrainer.constraint_transition(builder, tmp_1_constraint);

    let mut transition_to_dummy_from_not_constraint =
        builder.sub_extension(next_row[RES_COL], curr_row[PC_COL]);
    transition_to_dummy_from_not_constraint =
        builder.mul_extension(curr_row[TMP_1_COL], transition_to_dummy_from_not_constraint);
    transition_to_dummy_from_not_constraint =
        builder.mul_extension(is_not_dummy_insn, transition_to_dummy_from_not_constraint);
    constrainer.constraint_transition(builder, transition_to_dummy_from_not_constraint);

    let mut transition_to_dummy_from_dummy_constraint =
        builder.sub_extension(next_row[RES_COL], curr_row[RES_COL]);
    transition_to_dummy_from_dummy_constraint = builder.mul_extension(
        curr_row[TMP_1_COL],
        transition_to_dummy_from_dummy_constraint,
    );
    transition_to_dummy_from_dummy_constraint =
        builder.mul_extension(is_dummy_insn, transition_to_dummy_from_dummy_constraint);
    constrainer.constraint_transition(builder, transition_to_dummy_from_dummy_constraint);

    // dummy padding insns
    let mut is_dummy_padding_insn = builder.sub_extension(one, curr_row[FLAG_COLS[15]]);
    is_dummy_padding_insn = builder.mul_extension(is_dummy_insn, is_dummy_padding_insn);
    for i in START_REGISTERS..NUM_COLUMNS {
        let mut non_insn_col_same_constraint = builder.sub_extension(next_row[i], curr_row[i]);
        non_insn_col_same_constraint =
            builder.mul_extension(is_dummy_padding_insn, non_insn_col_same_constraint);
        constrainer.constraint_transition(builder, non_insn_col_same_constraint);
    }
}

pub(crate) fn constrain_memory_trace_recursively<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    curr_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    next_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    constrainer: &mut RecursiveConstraintConsumer<F, D>,
) {
    // make sure sorted addresses are sequential
    let mut addr_different_targets = Vec::new();
    for i in 0..3 {
        let addr_difference = builder.sub_extension(
            curr_row[ADDR_SORTED_COLS[i + 1]],
            curr_row[ADDR_SORTED_COLS[i]],
        );
        let addr_different = builder.add_const_extension(addr_difference, -F::ONE);
        addr_different_targets.push(addr_different);
        let sorted_addrs_seq_constraint = builder.mul_extension(addr_difference, addr_different);
        constrainer.constraint(builder, sorted_addrs_seq_constraint);
    }
    let addr_difference =
        builder.sub_extension(next_row[ADDR_SORTED_COLS[0]], curr_row[ADDR_SORTED_COLS[3]]);
    let addr_different = builder.add_const_extension(addr_difference, -F::ONE);
    addr_different_targets.push(addr_different);
    let sorted_addrs_seq_constraint = builder.mul_extension(addr_difference, addr_different);
    constrainer.constraint(builder, sorted_addrs_seq_constraint);

    // make sure sorted accesses are single-valued
    for i in 0..3 {
        let value_same = builder.sub_extension(
            curr_row[MEM_SORTED_COLS[i + 1]],
            curr_row[MEM_SORTED_COLS[i]],
        );
        let single_valued_constraint = builder.mul_extension(value_same, addr_different_targets[i]);
        constrainer.constraint(builder, single_valued_constraint);
    }
    let value_same =
        builder.sub_extension(next_row[MEM_SORTED_COLS[0]], curr_row[MEM_SORTED_COLS[3]]);
    let single_valued_constraint = builder.mul_extension(value_same, addr_different_targets[3]);
    constrainer.constraint(builder, single_valued_constraint);

    // TODO: Permutation argument and public memory
}

pub(crate) fn constrain_boundary_constraints_recursively<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    curr_row: &[ExtensionTarget<D>; NUM_COLUMNS],
    public_inputs: &[ExtensionTarget<D>; NUM_PUBLIC_INPUTS],
    constrainer: &mut RecursiveConstraintConsumer<F, D>,
) {
    // intitial pc, ap, sp
    // TODO: does this circuitry appear for every row? If so, how do we only have it for the first row?
    let initial_pc_constraint = builder.sub_extension(public_inputs[PC_INITIAL], curr_row[PC_COL]);
    constrainer.constraint_first_row(builder, initial_pc_constraint);

    let initial_ap_constraint = builder.sub_extension(public_inputs[AP_INITIAL], curr_row[AP_COL]);
    constrainer.constraint_first_row(builder, initial_ap_constraint);

    let initial_sp_constraint = builder.sub_extension(public_inputs[SP_INITIAL], curr_row[SP_COL]);
    constrainer.constraint_first_row(builder, initial_sp_constraint);

    // final pc, ap, sp
    // TODO: does this circuitry appear for every row? If so, how do we only have it for the last row?
    let final_pc_constraint = builder.sub_extension(public_inputs[PC_FINAL], curr_row[RES_COL]);
    constrainer.constraint_last_row(builder, final_pc_constraint);

    let final_ap_constraint = builder.sub_extension(public_inputs[AP_FINAL], curr_row[AP_COL]);
    constrainer.constraint_last_row(builder, final_ap_constraint);
}
