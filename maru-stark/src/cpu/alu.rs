use plonky2::field::types::Field;
use plonky2::field::packed::PackedField;

use super::layout::*;
use crate::constraint_consumer::ConstraintConsumer;

pub(crate) fn constrain_insn<F, P>(
    curr_row: &[P; NUM_COLUMNS],
    _next_row: &[P; NUM_COLUMNS],
    constrainer: &mut ConstraintConsumer<P>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // ensure all flags are 0 or 1
    for i in 0..16 {
        constrainer.constraint(curr_row[FLAG_COLS[i]] * (curr_row[FLAG_COLS[i]] - F::ONE));
    }

    // check insn decode
    let packed_insn = curr_row[OP0_OFFSET_COL]
        + curr_row[OP1_OFFSET_COL] * F::from_canonical_u32(1 << 16)
        + curr_row[DST_OFFSET_COL] * F::from_canonical_u64(1 << 32)
        + (curr_row[FLAG_COLS[15]]
            + curr_row[FLAG_COLS[14]] * F::from_canonical_u16(1 << 1)
            + curr_row[FLAG_COLS[13]] * F::from_canonical_u16(1 << 2)
            + curr_row[FLAG_COLS[12]] * F::from_canonical_u16(1 << 3)
            + curr_row[FLAG_COLS[11]] * F::from_canonical_u16(1 << 4)
            + curr_row[FLAG_COLS[10]] * F::from_canonical_u16(1 << 5)
            + curr_row[FLAG_COLS[9]] * F::from_canonical_u16(1 << 6)
            + curr_row[FLAG_COLS[8]] * F::from_canonical_u16(1 << 7)
            + curr_row[FLAG_COLS[7]] * F::from_canonical_u16(1 << 8)
            + curr_row[FLAG_COLS[6]] * F::from_canonical_u16(1 << 9)
            + curr_row[FLAG_COLS[5]] * F::from_canonical_u16(1 << 10)
            + curr_row[FLAG_COLS[4]] * F::from_canonical_u16(1 << 11)
            + curr_row[FLAG_COLS[3]] * F::from_canonical_u16(1 << 12)
            + curr_row[FLAG_COLS[2]] * F::from_canonical_u16(1 << 13)
            + curr_row[FLAG_COLS[1]] * F::from_canonical_u16(1 << 14)
            + curr_row[FLAG_COLS[0]] * F::from_canonical_u16(1 << 15))
            * F::from_canonical_u64(1 << 48);
    let is_dummy_insn = curr_row[FLAG_COLS[0]];
    let is_not_dummy_insn = is_dummy_insn - F::ONE;
    constrainer.constraint(is_not_dummy_insn * (packed_insn - curr_row[PC_MEM_COL]));
}

pub(crate) fn constrain_state_transition<F: Field, P: PackedField<Scalar = F>>(
    curr_row: &[P; NUM_COLUMNS],
    next_row: &[P; NUM_COLUMNS],
    constrainer: &mut ConstraintConsumer<P>,
) {
    let is_dummy_insn = curr_row[FLAG_COLS[0]];
    let is_not_dummy_insn = -curr_row[FLAG_COLS[0]] + F::ONE;

    // get offsets
    let op0_offset = curr_row[OP0_OFFSET_COL] - F::from_canonical_u16(1 << 15);
    let op1_offset = curr_row[OP1_OFFSET_COL] - F::from_canonical_u16(1 << 15);
    let dst_offset = curr_row[DST_OFFSET_COL] - F::from_canonical_u16(1 << 15);

    // constrain dst against offset and addressing mode
    let dst_addressing_mode_sp = -curr_row[FLAG_COLS[1]] + F::ONE;
    let dst_addressing_mode_ap = curr_row[FLAG_COLS[1]];

    // degree 3
    constrainer.constraint(
        ((curr_row[DST_COL] - (curr_row[SP_COL] + dst_offset)) * dst_addressing_mode_sp
            + (curr_row[DST_COL] - (curr_row[AP_COL] + dst_offset)) * dst_addressing_mode_ap)
            * is_not_dummy_insn,
    );

    // constrain op1 against offset and addressing mode
    let op1_addressing_mode_pc =
        -curr_row[FLAG_COLS[2]] - curr_row[FLAG_COLS[3]] - curr_row[FLAG_COLS[4]] + F::ONE;
    let op1_addressing_mode_sp = curr_row[FLAG_COLS[4]];
    let op1_addressing_mode_ap = curr_row[FLAG_COLS[3]];
    let op1_addressing_mode_op0 = curr_row[FLAG_COLS[2]];

    // degree 3
    constrainer.constraint(
        (op1_addressing_mode_pc * (curr_row[OP1_COL] - (curr_row[PC_COL] + op1_offset))
            + op1_addressing_mode_sp * (curr_row[OP1_COL] - (curr_row[SP_COL] + op1_offset))
            + op1_addressing_mode_ap * (curr_row[OP1_COL] - (curr_row[AP_COL] + op1_offset))
            + op1_addressing_mode_op0 * (curr_row[OP1_MEM_COL] - (curr_row[OP0_COL] + op1_offset)))
            * is_not_dummy_insn,
    );

    // constrain op0 against offset and addressing mode
    let op0_addressing_mode_sp = -curr_row[FLAG_COLS[5]] + F::ONE;
    let op0_addressing_mode_ap = curr_row[FLAG_COLS[5]];

    // degree 3
    constrainer.constraint(
        (op0_addressing_mode_sp * (curr_row[OP0_COL] - (curr_row[SP_COL] + op0_offset))
            + op0_addressing_mode_ap * (curr_row[OP0_COL] - (curr_row[AP_COL] + op0_offset)))
            * is_not_dummy_insn,
    );

    // opcode

    let opcode_add = -curr_row[FLAG_COLS[6]]
        - curr_row[FLAG_COLS[7]]
        - curr_row[FLAG_COLS[8]]
        - curr_row[FLAG_COLS[9]]
        + F::ONE;
    let opcode_mul = curr_row[FLAG_COLS[9]];
    let opcode_call = curr_row[FLAG_COLS[8]];
    let opcode_ret = curr_row[FLAG_COLS[7]];
    let opcode_mov = curr_row[FLAG_COLS[6]];
    let pc_update_cond_relative_jump = curr_row[FLAG_COLS[10]];

    // degree 2
    constrainer
        .constraint(curr_row[TMP_3_COL] - (-pc_update_cond_relative_jump + F::ONE) * opcode_mov);

    // degree 2
    constrainer.constraint(curr_row[TMP_4_COL] - curr_row[OP0_MEM_COL] * curr_row[OP1_MEM_COL]);
    // don't care what res is for call and ret insns, so only select by add, mul, and mov
    // degree 4
    constrainer.constraint(
        (opcode_add * (curr_row[RES_COL] - (curr_row[OP0_MEM_COL] + curr_row[OP1_MEM_COL]))
            + opcode_mul * (curr_row[RES_COL] - curr_row[TMP_4_COL])
            + curr_row[TMP_3_COL] * (curr_row[RES_COL] - curr_row[OP1_MEM_COL]))
            * is_not_dummy_insn,
    );

    let insn_size = op1_addressing_mode_pc * F::from_canonical_u16(2)
        + (-op1_addressing_mode_pc + F::ONE) * F::ONE;

    // make sure sp stored in dst when doing a call insn
    constrainer
        .constraint(is_not_dummy_insn * opcode_call * (curr_row[SP_COL] - curr_row[DST_MEM_COL]));

    // make sure pc of next insn stored at op0 when doing a call insn
    constrainer.constraint(
        is_not_dummy_insn * opcode_call * (curr_row[OP0_MEM_COL] - curr_row[PC_COL] - insn_size),
    );

    // ** pc update **

    let pc_update_next_insn =
        -pc_update_cond_relative_jump - curr_row[FLAG_COLS[11]] - curr_row[FLAG_COLS[12]] + F::ONE;
    let pc_update_absolute_jump = curr_row[FLAG_COLS[12]];
    let pc_update_relative_jump = curr_row[FLAG_COLS[11]];

    // TMP_2 should be 1 if neither current nor next insn is dummy instruction, 0 otherwise
    // degree 2
    let next_is_dummy_insn = next_row[FLAG_COLS[0]];
    constrainer.constraint_transition(
        curr_row[TMP_2_COL] - is_not_dummy_insn * (-next_is_dummy_insn + F::ONE),
    );
    // constraint for all pc updates except for conditional jumps
    // ignored for dummy instructions or transition from non-dummy to dummy
    // degree 3
    constrainer.constraint_transition(
        ((-pc_update_cond_relative_jump + F::ONE) * next_row[PC_COL]
            - (pc_update_next_insn * (curr_row[PC_COL] + insn_size)
                + pc_update_absolute_jump * curr_row[RES_COL]
                + pc_update_relative_jump * (curr_row[PC_COL] + curr_row[RES_COL])))
            * curr_row[TMP_2_COL],
    );

    // ** conditional relative jumps **

    // * TMP_0 is 1 if current row is a conditional relative jump and res = dst^-1, 0 otherwise.
    // * this includes the case where dst == 0 but it's conditional relative jump: in this case we set res to 0 and TMP_1 is 0
    // degree 3
    constrainer.constraint(
        curr_row[TMP_0_COL]
            - pc_update_cond_relative_jump * curr_row[DST_MEM_COL] * curr_row[RES_COL],
    );

    // constraint for conditional jump when dst != 0
    // degree 3
    constrainer.constraint_transition(
        curr_row[TMP_0_COL]
            * curr_row[TMP_2_COL]
            * (next_row[PC_COL] - (curr_row[PC_COL] + curr_row[OP1_MEM_COL])),
    );

    // constraint for conditional jump when dst == 0 to deal with the fact that there's no inverse for dst
    // degree 3
    constrainer.constraint_transition(
        (pc_update_cond_relative_jump - curr_row[TMP_0_COL])
            * curr_row[TMP_2_COL]
            * (next_row[PC_COL] - (curr_row[PC_COL] + insn_size)),
    );

    // ap update
    // degree 3
    let ap_update_increment = curr_row[FLAG_COLS[14]];
    let ap_update_add_res = curr_row[FLAG_COLS[13]];
    constrainer.constraint_transition(
        (next_row[AP_COL]
            - (curr_row[AP_COL]
                + ap_update_increment * F::ONE
                + opcode_call * F::from_canonical_u16(2)
                + ap_update_add_res * curr_row[RES_COL]))
            * is_not_dummy_insn,
    );

    // sp update
    // degree 3
    constrainer.constraint_transition(
        (next_row[SP_COL]
            - (opcode_ret * curr_row[DST_MEM_COL]
                + opcode_call * (curr_row[AP_COL] + F::from_canonical_u16(2))
                + (-opcode_ret - opcode_call + F::ONE) * curr_row[SP_COL]))
            * is_not_dummy_insn,
    );

    // assert *dst == res when flag is set
    let assert_dst_eq_res = curr_row[FLAG_COLS[15]];
    constrainer.constraint(
        is_not_dummy_insn * assert_dst_eq_res * (curr_row[DST_MEM_COL] - curr_row[RES_COL]),
    );
    
    let is_dummy_access_insn = is_dummy_insn * curr_row[FLAG_COLS[15]];
    let is_dummy_padding_insn = is_dummy_insn * (-curr_row[FLAG_COLS[15]] + F::ONE);

    // make sure memory addresses and values are 0 for dummy access instructions
    constrainer.constraint(is_dummy_access_insn * curr_row[PC_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[OP0_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[OP1_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[DST_COL]);

    constrainer.constraint(is_dummy_access_insn * curr_row[PC_MEM_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[OP0_MEM_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[OP1_MEM_COL]);
    constrainer.constraint(is_dummy_access_insn * curr_row[DST_MEM_COL]);

    // always keep AP the same for dummy access insns
    // degree: 3
    constrainer.constraint_transition(is_dummy_access_insn * (next_row[AP_COL] - curr_row[AP_COL]));

    // if transitioning from non-dummy to dummy-access, set res to pc
    // degree: 2
    constrainer.constraint_transition(
        curr_row[TMP_1_COL] - next_row[FLAG_COLS[15]] * next_row[FLAG_COLS[0]],
    );

    // degree 3
    constrainer.constraint_transition(
        is_not_dummy_insn * curr_row[TMP_1_COL] * (next_row[RES_COL] - curr_row[PC_COL]),
    );
    // if transitioning from dummy to dummy, keep res the same
    // degree: 3
    constrainer.constraint_transition(
        (is_dummy_insn * curr_row[TMP_1_COL]) * (next_row[RES_COL] - curr_row[RES_COL]),
    );

    // for dummy padding instructions, keep all non-insn columns the same
    // degree: 3
    for i in START_REGISTERS..NUM_COLUMNS {
        constrainer.constraint_transition(is_dummy_padding_insn * (next_row[i] - curr_row[i]));
    }
}

pub(crate) fn constrain_boundary_constraints<F, P>(
    curr_row: &[P; NUM_COLUMNS],
    _next_row: &[P; NUM_COLUMNS],
    public_inputs: &[P::Scalar; NUM_PUBLIC_INPUTS],
    constrainer: &mut ConstraintConsumer<P>,
    // interaction_challenges: &Vec<F>,
) where
    F: Field,
    P: PackedField<Scalar = F>,
{
    // intitial pc, ap, sp
    constrainer.constraint_first_row(-curr_row[PC_COL] + public_inputs[PC_INITIAL]);
    constrainer.constraint_first_row(-curr_row[AP_COL] + public_inputs[AP_INITIAL]);
    constrainer.constraint_first_row(-curr_row[SP_COL] + public_inputs[SP_INITIAL]);

    // final pc, ap
    constrainer.constraint_last_row(-curr_row[RES_COL] + public_inputs[PC_FINAL]);
    constrainer.constraint_last_row(-curr_row[AP_COL] + public_inputs[AP_FINAL]);
}
