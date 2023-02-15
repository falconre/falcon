use crate::il::Expression as Expr;
use crate::il::*;
use crate::Error;
use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::ppc_reg;
use std::cmp::Ordering;

/// Struct for dealing with x86 registers
pub struct PpcRegister {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: ppc_reg,
    /// The size of this register in bits
    bits: usize,
}

impl PpcRegister {
    // pub fn bits(&self) -> usize {
    //     self.bits
    // }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn scalar(&self) -> Scalar {
        scalar(self.name, self.bits)
    }

    pub fn expression(&self) -> Expr {
        expr_scalar(self.name, self.bits)
    }
}

const PPC_REGISTERS: &[PpcRegister] = &[
    PpcRegister {
        name: "r0",
        capstone_reg: ppc_reg::PPC_REG_R0,
        bits: 32,
    },
    PpcRegister {
        name: "r1",
        capstone_reg: ppc_reg::PPC_REG_R1,
        bits: 32,
    },
    PpcRegister {
        name: "r2",
        capstone_reg: ppc_reg::PPC_REG_R2,
        bits: 32,
    },
    PpcRegister {
        name: "r3",
        capstone_reg: ppc_reg::PPC_REG_R3,
        bits: 32,
    },
    PpcRegister {
        name: "r4",
        capstone_reg: ppc_reg::PPC_REG_R4,
        bits: 32,
    },
    PpcRegister {
        name: "r5",
        capstone_reg: ppc_reg::PPC_REG_R5,
        bits: 32,
    },
    PpcRegister {
        name: "r6",
        capstone_reg: ppc_reg::PPC_REG_R6,
        bits: 32,
    },
    PpcRegister {
        name: "r7",
        capstone_reg: ppc_reg::PPC_REG_R7,
        bits: 32,
    },
    PpcRegister {
        name: "r8",
        capstone_reg: ppc_reg::PPC_REG_R8,
        bits: 32,
    },
    PpcRegister {
        name: "r9",
        capstone_reg: ppc_reg::PPC_REG_R9,
        bits: 32,
    },
    PpcRegister {
        name: "r10",
        capstone_reg: ppc_reg::PPC_REG_R10,
        bits: 32,
    },
    PpcRegister {
        name: "r11",
        capstone_reg: ppc_reg::PPC_REG_R11,
        bits: 32,
    },
    PpcRegister {
        name: "r12",
        capstone_reg: ppc_reg::PPC_REG_R12,
        bits: 32,
    },
    PpcRegister {
        name: "r13",
        capstone_reg: ppc_reg::PPC_REG_R13,
        bits: 32,
    },
    PpcRegister {
        name: "r14",
        capstone_reg: ppc_reg::PPC_REG_R14,
        bits: 32,
    },
    PpcRegister {
        name: "r15",
        capstone_reg: ppc_reg::PPC_REG_R15,
        bits: 32,
    },
    PpcRegister {
        name: "r16",
        capstone_reg: ppc_reg::PPC_REG_R16,
        bits: 32,
    },
    PpcRegister {
        name: "r17",
        capstone_reg: ppc_reg::PPC_REG_R17,
        bits: 32,
    },
    PpcRegister {
        name: "r18",
        capstone_reg: ppc_reg::PPC_REG_R18,
        bits: 32,
    },
    PpcRegister {
        name: "r19",
        capstone_reg: ppc_reg::PPC_REG_R19,
        bits: 32,
    },
    PpcRegister {
        name: "r20",
        capstone_reg: ppc_reg::PPC_REG_R20,
        bits: 32,
    },
    PpcRegister {
        name: "r21",
        capstone_reg: ppc_reg::PPC_REG_R21,
        bits: 32,
    },
    PpcRegister {
        name: "r22",
        capstone_reg: ppc_reg::PPC_REG_R22,
        bits: 32,
    },
    PpcRegister {
        name: "r23",
        capstone_reg: ppc_reg::PPC_REG_R23,
        bits: 32,
    },
    PpcRegister {
        name: "r24",
        capstone_reg: ppc_reg::PPC_REG_R24,
        bits: 32,
    },
    PpcRegister {
        name: "r25",
        capstone_reg: ppc_reg::PPC_REG_R25,
        bits: 32,
    },
    PpcRegister {
        name: "r26",
        capstone_reg: ppc_reg::PPC_REG_R26,
        bits: 32,
    },
    PpcRegister {
        name: "r27",
        capstone_reg: ppc_reg::PPC_REG_R27,
        bits: 32,
    },
    PpcRegister {
        name: "r28",
        capstone_reg: ppc_reg::PPC_REG_R28,
        bits: 32,
    },
    PpcRegister {
        name: "r29",
        capstone_reg: ppc_reg::PPC_REG_R29,
        bits: 32,
    },
    PpcRegister {
        name: "r30",
        capstone_reg: ppc_reg::PPC_REG_R30,
        bits: 32,
    },
    PpcRegister {
        name: "r31",
        capstone_reg: ppc_reg::PPC_REG_R31,
        bits: 32,
    },
    PpcRegister {
        name: "cr0",
        capstone_reg: ppc_reg::PPC_REG_CR0,
        bits: 32,
    },
    PpcRegister {
        name: "cr1",
        capstone_reg: ppc_reg::PPC_REG_CR1,
        bits: 32,
    },
    PpcRegister {
        name: "cr2",
        capstone_reg: ppc_reg::PPC_REG_CR2,
        bits: 32,
    },
    PpcRegister {
        name: "cr3",
        capstone_reg: ppc_reg::PPC_REG_CR3,
        bits: 32,
    },
    PpcRegister {
        name: "cr4",
        capstone_reg: ppc_reg::PPC_REG_CR4,
        bits: 32,
    },
    PpcRegister {
        name: "cr5",
        capstone_reg: ppc_reg::PPC_REG_CR5,
        bits: 32,
    },
    PpcRegister {
        name: "cr6",
        capstone_reg: ppc_reg::PPC_REG_CR6,
        bits: 32,
    },
    PpcRegister {
        name: "cr7",
        capstone_reg: ppc_reg::PPC_REG_CR7,
        bits: 32,
    },
    PpcRegister {
        name: "ctr",
        capstone_reg: ppc_reg::PPC_REG_CTR,
        bits: 32,
    },
];

/// Takes a capstone register enum and returns a `MIPSRegister`
pub fn get_register(capstone_id: ppc_reg) -> Result<&'static PpcRegister, Error> {
    for register in PPC_REGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(register);
        }
    }
    Err("Could not find register".into())
}

/// Returns the details section of a mips capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_ppc, Error> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::PPC(x) => Ok(x),
        _ => Err("Could not get instruction details".into()),
    }
}

pub fn set_condition_register_signed(
    block: &mut Block,
    condition_register: Scalar,
    lhs: Expression,
    rhs: Expression,
) -> Result<(), Error> {
    let lt = Expression::ite(
        Expression::cmplts(lhs.clone(), rhs.clone())?,
        expr_const(0b0100, 4),
        expr_const(0b0000, 4),
    )?;
    let gt = Expression::ite(
        Expression::cmplts(rhs.clone(), lhs.clone())?,
        expr_const(0b0010, 4),
        expr_const(0b0000, 4),
    )?;
    let eq = Expression::ite(
        Expression::cmplts(rhs, lhs)?,
        expr_const(0b0001, 4),
        expr_const(0b0000, 4),
    )?;
    block.assign(scalar(format!("{}-lt", condition_register.name()), 1), lt);
    block.assign(scalar(format!("{}-gt", condition_register.name()), 1), gt);
    block.assign(scalar(format!("{}-eq", condition_register.name()), 1), eq);

    Ok(())
}

pub fn set_condition_register_unsigned(
    block: &mut Block,
    condition_register: Scalar,
    lhs: Expression,
    rhs: Expression,
) -> Result<(), Error> {
    let lt = Expression::ite(
        Expression::cmpltu(lhs.clone(), rhs.clone())?,
        expr_const(0b0100, 4),
        expr_const(0b0000, 4),
    )?;
    let gt = Expression::ite(
        Expression::cmpltu(rhs.clone(), lhs.clone())?,
        expr_const(0b0010, 4),
        expr_const(0b0000, 4),
    )?;
    let eq = Expression::ite(
        Expression::cmpltu(rhs, lhs)?,
        expr_const(0b0001, 4),
        expr_const(0b0000, 4),
    )?;
    block.assign(scalar(format!("{}-lt", condition_register.name()), 1), lt);
    block.assign(scalar(format!("{}-gt", condition_register.name()), 1), gt);
    block.assign(scalar(format!("{}-eq", condition_register.name()), 1), eq);

    Ok(())
}

pub fn set_condition_register_summary_overflow(
    block: &mut Block,
    condition_register: Scalar,
    summary_overflow: Expression,
) {
    block.assign(
        scalar(format!("{}-so", condition_register.name()), 1),
        summary_overflow,
    );
}

pub fn condition_register_bit_to_flag(condition_register_bit: usize) -> Result<Scalar, Error> {
    Ok(match condition_register_bit {
        0 => scalar("cr0-lt", 1),
        1 => scalar("cr0-gt", 1),
        2 => scalar("cr0-eq", 1),
        3 => scalar("cr0-so", 1),
        4 => scalar("cr1-lt", 1),
        5 => scalar("cr1-gt", 1),
        6 => scalar("cr1-eq", 1),
        7 => scalar("cr1-so", 1),
        8 => scalar("cr2-lt", 1),
        9 => scalar("cr2-gt", 1),
        10 => scalar("cr2-eq", 1),
        11 => scalar("cr2-so", 1),
        12 => scalar("cr3-lt", 1),
        13 => scalar("cr3-gt", 1),
        14 => scalar("cr3-eq", 1),
        15 => scalar("cr3-so", 1),
        16 => scalar("cr4-lt", 1),
        17 => scalar("cr4-gt", 1),
        18 => scalar("cr4-eq", 1),
        19 => scalar("cr4-so", 1),
        20 => scalar("cr5-lt", 1),
        21 => scalar("cr5-gt", 1),
        22 => scalar("cr5-eq", 1),
        23 => scalar("cr5-so", 1),
        24 => scalar("cr6-lt", 1),
        25 => scalar("cr6-gt", 1),
        26 => scalar("cr6-eq", 1),
        27 => scalar("cr6-so", 1),
        28 => scalar("cr7-lt", 1),
        29 => scalar("cr7-gt", 1),
        30 => scalar("cr7-eq", 1),
        31 => scalar("cr7-so", 1),
        _ => return Err(Error::Custom("Invalid condition register bit".to_string())),
    })
}

pub fn rlwinm_(
    control_flow_graph: &mut ControlFlowGraph,
    ra: Scalar,
    rs: Expression,
    sh: u64,
    mb: u64,
    me: u64,
) -> Result<(), Error> {
    /*
    - If the MB value is less than the ME value + 1, then the mask bits between
      and including the starting point and the end point are set to ones. All
      other bits are set to zeros.
    - If the MB value is the same as the ME value + 1, then all 32 mask bits are
      set to ones.
    - If the MB value is greater than the ME value + 1, then all of the mask
      bits between and including the ME value +1 and the MB value -1 are set to
      zeros. All other bits are set to ones.
    */

    let mask = match mb.cmp(&(me + 1)) {
        Ordering::Less => {
            let mb = 32 - mb;
            let me = 32 - me;
            let mask = (1 << (mb - me)) - 1;
            mask << me
        }
        Ordering::Equal => 0xffff_ffff,
        Ordering::Greater => {
            let mb = 32 - mb;
            let me = 32 - me;
            let mask = (1 << (me - mb)) - 1;
            let mask = mask << mb;
            mask ^ 0xffff_ffff
        }
    };

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let value = Expr::rotl(rs, expr_const(sh, 32))?;
        let value = Expr::and(value, expr_const(mask, 32))?;
        block.assign(ra, value);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn add(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::add(lhs, rhs)?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn addi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::add(lhs, rhs)?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn addis(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const((detail.operands[2].imm() as u64) << 16, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::add(lhs, rhs)?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn addze(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::add(
            lhs.clone(),
            Expression::zext(lhs.bits(), expr_scalar("carry", 1))?,
        )?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn bl(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = expr_const(detail.operands[0].imm() as u32 as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("lr", 32), expr_const(instruction.address + 4, 32));
        block.branch(dst);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn bclr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let bo = detail.operands[0].imm() as usize;
    let bi = detail.operands[1].imm() as usize;

    let ctr = scalar("ctr", 32);
    let branch_target = expr_scalar("lr", 32);

    match bo & 0x1f {
        0b00000 | 0b00001 | 0b00010 | 0b00011 => {
            // Decrement the CTR, then branch if condition is false
            let head_index = {
                let block = control_flow_graph.new_block()?;
                block.assign(
                    ctr.clone(),
                    Expression::sub(ctr.clone().into(), expr_const(1, ctr.bits()))?,
                );
                block.index()
            };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let false_condition: Expression = condition_register_bit_to_flag(bi)?.into();
            let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b00100 | 0b00101 | 0b00110 | 0b00111 => {
            // Branch if the condition is false
            let head_index = { control_flow_graph.new_block()?.index() };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let false_condition: Expression = condition_register_bit_to_flag(bi)?.into();
            let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b01000 | 0b01001 | 0b01010 | 0b01011 => {
            // Decrement the CTR, then branch if condition is true
            let head_index = {
                let block = control_flow_graph.new_block()?;
                block.assign(
                    ctr.clone(),
                    Expression::sub(ctr.clone().into(), expr_const(1, ctr.bits()))?,
                );
                block.index()
            };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let true_condition: Expression = condition_register_bit_to_flag(bi)?.into();
            let false_condition = Expression::cmpeq(true_condition.clone(), expr_const(0, 1))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b01100 | 0b01101 | 0b01110 | 0b01111 => {
            // Branch if the condition is true
            let head_index = { control_flow_graph.new_block()?.index() };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let true_condition: Expression = condition_register_bit_to_flag(bi)?.into();
            let false_condition = Expression::cmpeq(true_condition.clone(), expr_const(0, 1))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b10000 | 0b10001 | 0b11000 | 0b11001 => {
            // Decrement the CTF, then branch if CTR != 0
            let head_index = {
                let block = control_flow_graph.new_block()?;
                block.assign(
                    ctr.clone(),
                    Expression::sub(ctr.clone().into(), expr_const(1, ctr.bits()))?,
                );
                block.index()
            };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let true_condition = Expression::cmpneq(ctr.clone().into(), expr_const(0, ctr.bits()))?;
            let false_condition = Expression::cmpeq(ctr.clone().into(), expr_const(0, ctr.bits()))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b10010 | 0b10011 | 0b11010 | 0b11011 => {
            // Decrement the CTR, then branch if CTR == 0
            let head_index = {
                let block = control_flow_graph.new_block()?;
                block.assign(
                    ctr.clone(),
                    Expression::sub(ctr.clone().into(), expr_const(1, ctr.bits()))?,
                );
                block.index()
            };

            let true_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            let false_index = { control_flow_graph.new_block()?.index() };

            let true_condition = Expression::cmpeq(ctr.clone().into(), expr_const(0, ctr.bits()))?;
            let false_condition =
                Expression::cmpneq(ctr.clone().into(), expr_const(0, ctr.bits()))?;

            control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;

            control_flow_graph.conditional_edge(head_index, false_index, false_condition)?;

            control_flow_graph.set_entry(head_index)?;
            control_flow_graph.set_exit(false_index)?;
        }
        0b10100 | 0b10101 | 0b10110 | 0b10111 | 0b11100 | 0b11101 | 0b11110 | 0b11111 => {
            // Always branch
            let block_index = {
                let block = control_flow_graph.new_block()?;
                block.branch(branch_target);
                block.index()
            };

            control_flow_graph.set_entry(block_index)?;
            control_flow_graph.set_exit(block_index)?;
        }
        _ => return Err(Error::Custom(format!("Invalid bo for bclr: {}", bo))),
    }

    Ok(())
}

pub fn bctr(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<(), Error> {
    // get operands
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.branch(expr_scalar("ctr", 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn cmpwi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let cr = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        set_condition_register_signed(block, cr, lhs, rhs)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn cmplwi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let cr = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        set_condition_register_unsigned(block, cr, lhs, rhs)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lbz(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = detail.operands[1].mem().disp;
    let offset = expr_const(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ea = Expr::add(offset, base)?;

        let temp = Scalar::temp(instruction.address, 8);
        block.load(temp.clone(), ea);
        block.assign(dst.clone(), Expression::zext(dst.bits(), temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn li(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let src = expr_const(detail.operands[1].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lwz(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = detail.operands[1].mem().disp;
    let offset = expr_const(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ea = Expr::add(offset, base)?;

        block.load(dst, ea);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lwzu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.scalar();
    let offset = detail.operands[1].mem().disp;
    let offset = expr_const(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ea = Expr::add(offset, base.clone().into())?;

        block.load(dst, ea.clone());
        block.assign(base, ea);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lis(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let src = expr_const(detail.operands[1].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::or(
            Expression::and(src.clone(), expr_const(0x0000_ffff, 32))?,
            Expression::shl(src, expr_const(16, 32))?,
        )?;

        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let src = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mflr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, expr_scalar("lr", 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mtctr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let src = expr_const(detail.operands[1].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mtlr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let src = get_register(detail.operands[0].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("lr", 32), src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn nop(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<(), Error> {
    let block_index = {
        let block = control_flow_graph.new_block()?;
        block.nop();
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn rlwinm(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let ra = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let sh = detail.operands[2].imm() as u64;
    let mb = detail.operands[3].imm() as u64;
    let me = detail.operands[4].imm() as u64;

    rlwinm_(control_flow_graph, ra, rs, sh, mb, me)
}

pub fn slwi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let ra = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let sh = detail.operands[2].imm() as u64;

    rlwinm_(control_flow_graph, ra, rs, sh, 0, 31 - sh)
}

pub fn srawi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, Expression::sra(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn stw(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let src = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = detail.operands[1].mem().disp;
    let offset = expr_const(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ea = Expr::add(offset, base)?;

        block.store(ea, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn stmw(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = detail.operands[1].mem().disp;
    let mut offset = const_(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let mut start_register: Option<usize> = None;
        for (i, reg) in PPC_REGISTERS.iter().enumerate() {
            if reg.capstone_reg == detail.operands[0].reg() {
                start_register = Some(i);
                break;
            }
        }

        let mut i = match start_register {
            Some(i) => i,
            None => {
                return Err(Error::Custom(
                    "Failed to find start register for stmwu".to_string(),
                ))
            }
        };

        while PPC_REGISTERS[i].capstone_reg != ppc_reg::PPC_REG_CR0 {
            let register = PPC_REGISTERS[i].expression();
            let ea = Expr::add(offset.clone().into(), base.clone())?;
            block.store(ea, register);
            offset = offset.add(&const_(4, offset.bits()))?;
            i += 1;
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn stwu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let src = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.scalar();
    let offset = detail.operands[1].mem().disp;
    let offset = expr_const(offset as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ea = Expr::add(offset, base.clone().into())?;

        block.store(ea.clone(), src);
        block.assign(base, ea);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn subf(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = Expression::add(
            Expression::add(Expression::xor(lhs, expr_const(0xffff_ffff, 32))?, rhs)?,
            expr_const(1, 32),
        )?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}
