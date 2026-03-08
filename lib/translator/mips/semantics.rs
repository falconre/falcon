use crate::il::Expression as Expr;
use crate::il::*;
use crate::Error;
use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::mips_reg;

/// Struct for dealing with x86 registers
pub struct MipsRegister {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: mips_reg,
    /// The size of this register in bits
    bits: usize,
}

impl MipsRegister {
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
        if self.name == "$zero" {
            expr_const(0, 32)
        } else {
            expr_scalar(self.name, self.bits)
        }
    }
}

const MIPS_REGISTERS: &[MipsRegister] = &[
    MipsRegister {
        name: "$zero",
        capstone_reg: mips_reg::MIPS_REG_0,
        bits: 32,
    },
    MipsRegister {
        name: "$at",
        capstone_reg: mips_reg::MIPS_REG_1,
        bits: 32,
    },
    MipsRegister {
        name: "$v0",
        capstone_reg: mips_reg::MIPS_REG_2,
        bits: 32,
    },
    MipsRegister {
        name: "$v1",
        capstone_reg: mips_reg::MIPS_REG_3,
        bits: 32,
    },
    MipsRegister {
        name: "$a0",
        capstone_reg: mips_reg::MIPS_REG_4,
        bits: 32,
    },
    MipsRegister {
        name: "$a1",
        capstone_reg: mips_reg::MIPS_REG_5,
        bits: 32,
    },
    MipsRegister {
        name: "$a2",
        capstone_reg: mips_reg::MIPS_REG_6,
        bits: 32,
    },
    MipsRegister {
        name: "$a3",
        capstone_reg: mips_reg::MIPS_REG_7,
        bits: 32,
    },
    MipsRegister {
        name: "$t0",
        capstone_reg: mips_reg::MIPS_REG_8,
        bits: 32,
    },
    MipsRegister {
        name: "$t1",
        capstone_reg: mips_reg::MIPS_REG_9,
        bits: 32,
    },
    MipsRegister {
        name: "$t2",
        capstone_reg: mips_reg::MIPS_REG_10,
        bits: 32,
    },
    MipsRegister {
        name: "$t3",
        capstone_reg: mips_reg::MIPS_REG_11,
        bits: 32,
    },
    MipsRegister {
        name: "$t4",
        capstone_reg: mips_reg::MIPS_REG_12,
        bits: 32,
    },
    MipsRegister {
        name: "$t5",
        capstone_reg: mips_reg::MIPS_REG_13,
        bits: 32,
    },
    MipsRegister {
        name: "$t6",
        capstone_reg: mips_reg::MIPS_REG_14,
        bits: 32,
    },
    MipsRegister {
        name: "$t7",
        capstone_reg: mips_reg::MIPS_REG_15,
        bits: 32,
    },
    MipsRegister {
        name: "$s0",
        capstone_reg: mips_reg::MIPS_REG_16,
        bits: 32,
    },
    MipsRegister {
        name: "$s1",
        capstone_reg: mips_reg::MIPS_REG_17,
        bits: 32,
    },
    MipsRegister {
        name: "$s2",
        capstone_reg: mips_reg::MIPS_REG_18,
        bits: 32,
    },
    MipsRegister {
        name: "$s3",
        capstone_reg: mips_reg::MIPS_REG_19,
        bits: 32,
    },
    MipsRegister {
        name: "$s4",
        capstone_reg: mips_reg::MIPS_REG_20,
        bits: 32,
    },
    MipsRegister {
        name: "$s5",
        capstone_reg: mips_reg::MIPS_REG_21,
        bits: 32,
    },
    MipsRegister {
        name: "$s6",
        capstone_reg: mips_reg::MIPS_REG_22,
        bits: 32,
    },
    MipsRegister {
        name: "$s7",
        capstone_reg: mips_reg::MIPS_REG_23,
        bits: 32,
    },
    MipsRegister {
        name: "$t8",
        capstone_reg: mips_reg::MIPS_REG_24,
        bits: 32,
    },
    MipsRegister {
        name: "$t9",
        capstone_reg: mips_reg::MIPS_REG_25,
        bits: 32,
    },
    MipsRegister {
        name: "$k0",
        capstone_reg: mips_reg::MIPS_REG_26,
        bits: 32,
    },
    MipsRegister {
        name: "$k1",
        capstone_reg: mips_reg::MIPS_REG_27,
        bits: 32,
    },
    MipsRegister {
        name: "$gp",
        capstone_reg: mips_reg::MIPS_REG_28,
        bits: 32,
    },
    MipsRegister {
        name: "$sp",
        capstone_reg: mips_reg::MIPS_REG_29,
        bits: 32,
    },
    MipsRegister {
        name: "$fp",
        capstone_reg: mips_reg::MIPS_REG_30,
        bits: 32,
    },
    MipsRegister {
        name: "$ra",
        capstone_reg: mips_reg::MIPS_REG_31,
        bits: 32,
    },
];

/// Takes a capstone register enum and returns a `MipsRegister`
pub fn get_register(capstone_id: mips_reg) -> Result<&'static MipsRegister, Error> {
    for register in MIPS_REGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(register);
        }
    }
    Err("Could not find register".into())
}

/// Returns the details section of a mips capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_mips, Error> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::MIPS(x) => Ok(x),
        _ => Err("Could not get instruction details".into()),
    }
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

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let raise_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(Intrinsic::new(
            "IntegerOverflow",
            "IntegerOverflow",
            Vec::new(),
            None,
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        ));

        block.index()
    };

    let operation_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::add(lhs.clone(), rhs.clone())?);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    let condition = Expr::cmpneq(
        Expr::trun(
            1,
            Expr::shr(Expr::add(lhs.clone(), rhs)?, expr_const(31, 32))?,
        )?,
        Expr::trun(1, Expr::shr(lhs, expr_const(31, 32))?)?,
    )?;

    control_flow_graph.conditional_edge(head_index, raise_index, condition.clone())?;

    control_flow_graph.conditional_edge(
        head_index,
        operation_index,
        Expr::cmpeq(condition, expr_const(0, 1))?,
    )?;

    control_flow_graph.unconditional_edge(raise_index, terminating_index)?;
    control_flow_graph.unconditional_edge(operation_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn addi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?;
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let lhs = if lhs.name() == "$zero" {
        expr_const(0, 32)
    } else {
        lhs.expression()
    };

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let raise_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(Intrinsic::new(
            "IntegerOverflow",
            "IntegerOverflow",
            Vec::new(),
            None,
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        ));

        block.index()
    };

    let operation_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::add(lhs.clone(), rhs.clone())?);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    let condition = Expr::cmpneq(
        Expr::trun(
            1,
            Expr::shr(Expr::add(lhs.clone(), rhs)?, expr_const(31, 32))?,
        )?,
        Expr::trun(1, Expr::shr(lhs, expr_const(31, 32))?)?,
    )?;

    control_flow_graph.conditional_edge(head_index, raise_index, condition.clone())?;

    control_flow_graph.conditional_edge(
        head_index,
        operation_index,
        Expr::cmpeq(condition, expr_const(0, 1))?,
    )?;

    control_flow_graph.unconditional_edge(raise_index, terminating_index)?;
    control_flow_graph.unconditional_edge(operation_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn addiu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?;
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let lhs = if lhs.name() == "$zero" {
        expr_const(0, 32)
    } else {
        lhs.expression()
    };

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::add(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn addu(
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

        block.assign(dst, Expr::add(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn and(
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

        block.assign(dst, Expr::and(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn andi(
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

        block.assign(dst, Expr::and(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn b(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<(), Error> {
    let block_index = control_flow_graph.new_block()?.index();

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn bal(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let operand = details(instruction)?.operands[0];

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.branch(expr_const(operand.imm() as u64, 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn bgezal(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let lhs = get_register(detail.operands[0].reg())?.expression();
    let zero = expr_const(0, 32);
    let target = expr_const(detail.operands[1].imm() as u64, 32);

    let head_index = {
        let block = control_flow_graph.new_block()?;
        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.branch(target);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    let false_condition = Expr::cmplts(lhs, zero)?;

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmpeq(false_condition.clone(), expr_const(0, 1))?,
    )?;

    control_flow_graph.conditional_edge(head_index, terminating_index, false_condition)?;

    control_flow_graph.unconditional_edge(true_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn bltzal(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let lhs = get_register(detail.operands[0].reg())?.expression();
    let zero = expr_const(0, 32);
    let target = expr_const(detail.operands[1].imm() as u64, 32);

    let head_index = {
        let block = control_flow_graph.new_block()?;
        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.branch(target);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    let true_condition = Expr::cmplts(lhs, zero)?;
    let false_condition = Expr::cmpeq(true_condition.clone(), expr_const(0, 1))?;

    control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;
    control_flow_graph.conditional_edge(head_index, terminating_index, false_condition)?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn break_(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        let intrinsic = Intrinsic::new(
            "break",
            "break",
            Vec::new(),
            Some(Vec::new()),
            Some(Vec::new()),
            instruction.bytes.get(0..4).unwrap().to_vec(),
        );

        block.intrinsic(intrinsic);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn clo(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();

    let (head_index, count) = {
        let count = control_flow_graph.temp(32);
        let block = control_flow_graph.new_block()?;

        block.assign(count.clone(), expr_const(0, 32));

        (block.index(), count)
    };

    let check_index = { control_flow_graph.new_block()?.index() };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            count.clone(),
            Expr::add(count.clone().into(), expr_const(1, 32))?,
        );

        block.index()
    };

    let terminating_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, count.clone().into());

        block.index()
    };

    control_flow_graph.unconditional_edge(head_index, check_index)?;
    let condition = Expr::trun(
        1,
        Expr::shr(rs, Expr::sub(expr_const(31, 32), count.clone().into())?)?,
    )?;
    control_flow_graph.conditional_edge(check_index, inc_index, condition.clone())?;
    control_flow_graph.conditional_edge(
        check_index,
        terminating_index,
        Expr::cmpeq(condition, expr_const(0, 1))?,
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        terminating_index,
        Expr::cmpeq(count.clone().into(), expr_const(32, 32))?,
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        check_index,
        Expr::cmpneq(count.into(), expr_const(32, 32))?,
    )?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn clz(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();

    let (head_index, count) = {
        let count = control_flow_graph.temp(32);
        let block = control_flow_graph.new_block()?;

        block.assign(count.clone(), expr_const(0, 32));

        (block.index(), count)
    };

    let check_index = { control_flow_graph.new_block()?.index() };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            count.clone(),
            Expr::add(count.clone().into(), expr_const(1, 32))?,
        );

        block.index()
    };

    let terminating_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, count.clone().into());

        block.index()
    };

    control_flow_graph.unconditional_edge(head_index, check_index)?;
    let condition = Expr::trun(
        1,
        Expr::shr(rs, Expr::sub(expr_const(31, 32), count.clone().into())?)?,
    )?;
    control_flow_graph.conditional_edge(
        check_index,
        inc_index,
        Expr::cmpeq(condition.clone(), expr_const(0, 1))?,
    )?;
    control_flow_graph.conditional_edge(check_index, terminating_index, condition)?;
    control_flow_graph.conditional_edge(
        inc_index,
        terminating_index,
        Expr::cmpeq(count.clone().into(), expr_const(32, 32))?,
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        check_index,
        Expr::cmpneq(count.into(), expr_const(32, 32))?,
    )?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn div(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let lhs = get_register(detail.operands[0].reg())?.expression();
    let rhs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$lo", 32), Expr::divs(lhs.clone(), rhs.clone())?);
        block.assign(scalar("$hi", 32), Expr::mods(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn divu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let lhs = get_register(detail.operands[0].reg())?.expression();
    let rhs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$lo", 32), Expr::divu(lhs.clone(), rhs.clone())?);
        block.assign(scalar("$hi", 32), Expr::modu(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn j(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<(), Error> {
    let block_index = control_flow_graph.new_block()?.index();

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn jr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let target = get_register(detail.operands[0].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.branch(target);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn jal(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.branch(expr_const(detail.operands[0].imm() as u64, 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn jalr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let target = get_register(detail.operands[0].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.branch(target);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lb(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let temp = Scalar::temp(instruction.address, 8);
        block.load(temp.clone(), Expr::add(base, offset)?);
        block.assign(dst, Expr::sext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lbu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let temp = Scalar::temp(instruction.address, 8);
        block.load(temp.clone(), Expr::add(base, offset)?);
        block.assign(dst, Expr::zext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lh(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let temp = Scalar::temp(instruction.address, 16);
        block.load(temp.clone(), Expr::add(base, offset)?);
        block.assign(dst, Expr::sext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lhu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let temp = Scalar::temp(instruction.address, 16);
        block.load(temp.clone(), Expr::add(base, offset)?);
        block.assign(dst, Expr::zext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

// This is identical to lw
pub fn ll(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.load(dst, Expr::add(base, offset)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lui(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.scalar();
    let imm = expr_const((detail.operands[1].imm() as u64) << 16, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt, imm);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lw(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.load(dst, Expr::add(base, offset)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lwl(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let address = Expr::add(base, offset)?;

        // get the number of bits to clear
        let bytes_to_clear = Expr::sub(
            expr_const(4, 32),
            Expr::and(expr_const(3, 32), address.clone())?,
        )?;
        let bits_to_clear = Expr::shl(bytes_to_clear, expr_const(3, 32))?;

        // get the number of bytes to shift the result
        let bytes_to_shift = Expr::and(expr_const(3, 32), address.clone())?;
        let bits_to_shift = Expr::shl(bytes_to_shift, expr_const(3, 32))?;

        let tmp = Scalar::temp(instruction.address, 32);
        block.load(tmp.clone(), address);

        // clear the dst register by shifting left then right
        let dst_expr = Expr::shl(dst.clone().into(), bits_to_clear.clone())?;
        let dst_expr = Expr::shr(dst_expr, bits_to_clear)?;

        // zero out the right bits in the loaded word
        let tmp = Expr::shl(Expr::shr(tmp.into(), bits_to_shift.clone())?, bits_to_shift)?;

        // or together
        let dst_expr = Expr::or(dst_expr, tmp)?;

        block.assign(dst, dst_expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn lwr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let address = Expr::sub(Expr::add(base, offset)?, expr_const(3, 32))?;

        // create a bit mask for dst and the loaded result
        let mask_bytes = Expr::and(address.clone(), expr_const(3, 32))?;
        let mask_bits = Expr::shl(mask_bytes, expr_const(3, 32))?;
        let mask_bit = Expr::shl(expr_const(1, 32), mask_bits)?;
        let mask = Expr::sub(mask_bit, expr_const(1, 32))?;

        // load our word from memory
        let tmp = Scalar::temp(instruction.address, 32);
        block.load(tmp.clone(), address);

        // we want to and this word with our mask to remove the high bits
        let temp = Expr::and(tmp.into(), mask.clone())?;

        // and out the bits we're about to set in dst
        let dst_expr = Expr::and(
            dst.clone().into(),
            Expr::sub(expr_const(0xffff_ffff, 32), mask)?,
        )?;

        let dst_expr = Expr::or(dst_expr, temp)?;

        block.assign(dst, dst_expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn madd(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp0 = Scalar::temp(instruction.address, 64);
        let tmp1 = Scalar::temp(instruction.address + 1, 64);
        block.assign(
            tmp0.clone(),
            Expr::mul(Expr::sext(64, rs)?, Expr::sext(64, rt)?)?,
        );
        block.assign(
            tmp1.clone(),
            Expr::shl(Expr::zext(64, expr_scalar("$hi", 32))?, expr_const(32, 64))?,
        );
        block.assign(
            tmp1.clone(),
            Expr::or(tmp1.clone().into(), Expr::zext(64, expr_scalar("$lo", 32))?)?,
        );
        block.assign(tmp0.clone(), Expr::add(tmp0.clone().into(), tmp1.into())?);
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp0.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp0.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn maddu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp0 = Scalar::temp(instruction.address, 64);
        let tmp1 = Scalar::temp(instruction.address + 1, 64);
        block.assign(
            tmp0.clone(),
            Expr::mul(Expr::zext(64, rs)?, Expr::zext(64, rt)?)?,
        );
        block.assign(
            tmp1.clone(),
            Expr::shl(Expr::zext(64, expr_scalar("$hi", 32))?, expr_const(32, 64))?,
        );
        block.assign(
            tmp1.clone(),
            Expr::or(tmp1.clone().into(), Expr::zext(64, expr_scalar("$lo", 32))?)?,
        );
        block.assign(tmp0.clone(), Expr::add(tmp0.clone().into(), tmp1.into())?);
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp0.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp0.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mfhi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, expr_scalar("$hi", 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mflo(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, expr_scalar("$lo", 32));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn move_(
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

pub fn movn(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let op_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, rs);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        op_index,
        Expr::cmpneq(rt.clone(), expr_const(0, 32))?,
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpeq(rt, expr_const(0, 32))?,
    )?;

    control_flow_graph.unconditional_edge(op_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn movz(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let op_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, rs);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        op_index,
        Expr::cmpeq(rt.clone(), expr_const(0, 32))?,
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpneq(rt, expr_const(0, 32))?,
    )?;

    control_flow_graph.unconditional_edge(op_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn msub(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp0 = Scalar::temp(instruction.address, 64);
        let tmp1 = Scalar::temp(instruction.address + 1, 64);
        block.assign(
            tmp0.clone(),
            Expr::mul(Expr::sext(64, rs)?, Expr::sext(64, rt)?)?,
        );
        block.assign(
            tmp1.clone(),
            Expr::shl(Expr::zext(64, expr_scalar("$hi", 32))?, expr_const(32, 64))?,
        );
        block.assign(
            tmp1.clone(),
            Expr::or(tmp1.clone().into(), Expr::zext(64, expr_scalar("$lo", 32))?)?,
        );
        block.assign(tmp0.clone(), Expr::sub(tmp0.clone().into(), tmp1.into())?);
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp0.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp0.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn msubu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp0 = Scalar::temp(instruction.address, 64);
        let tmp1 = Scalar::temp(instruction.address + 1, 64);
        block.assign(
            tmp0.clone(),
            Expr::mul(Expr::zext(64, rs)?, Expr::zext(64, rt)?)?,
        );
        block.assign(
            tmp1.clone(),
            Expr::shl(Expr::zext(64, expr_scalar("$hi", 32))?, expr_const(32, 64))?,
        );
        block.assign(
            tmp1.clone(),
            Expr::or(tmp1.clone().into(), Expr::zext(64, expr_scalar("$lo", 32))?)?,
        );
        block.assign(tmp0.clone(), Expr::sub(tmp0.clone().into(), tmp1.into())?);
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp0.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp0.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mthi(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$hi", 32), rs);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mtlo(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("$lo", 32), rs);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mul(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            rd,
            Expr::trun(32, Expr::mul(Expr::sext(64, rs)?, Expr::sext(64, rt)?)?)?,
        );

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn mult(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp = Scalar::temp(instruction.address, 64);
        block.assign(
            tmp.clone(),
            Expr::mul(Expr::sext(64, rs)?, Expr::sext(64, rt)?)?,
        );
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn multu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let tmp = Scalar::temp(instruction.address, 64);
        block.assign(
            tmp.clone(),
            Expr::mul(Expr::zext(64, rs)?, Expr::zext(64, rt)?)?,
        );
        block.assign(
            scalar("$hi", 32),
            Expr::trun(32, Expr::shr(tmp.clone().into(), expr_const(32, 64))?)?,
        );
        block.assign(scalar("$lo", 32), Expr::trun(32, tmp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn negu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::sub(expr_const(0, 32), rs)?);

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

pub fn nor(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            rd,
            Expr::xor(Expr::or(rs, rt)?, expr_const(0xffff_ffff, 32))?,
        );

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn or(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::or(rs, rt)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn ori(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let imm = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt, Expr::or(rs, imm)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn rdhwr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    let rt = get_register(detail.operands[0].reg())?.expression();
    let rd = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;
        let intrinsic = Intrinsic::new(
            "rdhwr",
            format!("{} {}", instruction.mnemonic, instruction.op_str),
            vec![rt.clone(), rd],
            Some(vec![rt]),
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        );
        block.intrinsic(intrinsic);
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sb(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.store(Expr::add(base, offset)?, Expr::trun(8, rt)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

// This is identical to sw
pub fn sc(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let addr_expr = Expr::add(base, offset)?;

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.store(addr_expr, rt);
        // a 1 is written to rt on success
        block.assign(
            get_register(detail.operands[0].reg())?.scalar(),
            expr_const(1, 32),
        );

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sh(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.store(Expr::add(base, offset)?, Expr::trun(16, rt)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sll(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let sa = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::shl(rt, sa)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sllv(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let rs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::shl(rt, rs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn slt(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd.clone(), expr_const(1, 32));

        block.index()
    };

    let false_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, expr_const(0, 32));

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmplts(rs.clone(), rt.clone())?,
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        false_index,
        Expr::cmpeq(Expr::cmplts(rs, rt)?, expr_const(0, 1))?,
    )?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;
    control_flow_graph.unconditional_edge(false_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn slti(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let imm = expr_const(detail.operands[2].imm() as u64, 32);

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt.clone(), expr_const(1, 32));

        block.index()
    };

    let false_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt, expr_const(0, 32));

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmplts(rs.clone(), imm.clone())?,
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        false_index,
        Expr::cmpeq(Expr::cmplts(rs, imm)?, expr_const(0, 1))?,
    )?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;
    control_flow_graph.unconditional_edge(false_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn sltiu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let imm = expr_const(detail.operands[2].imm() as u64, 32);

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt.clone(), expr_const(1, 32));

        block.index()
    };

    let false_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rt, expr_const(0, 32));

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmpltu(rs.clone(), imm.clone())?,
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        false_index,
        Expr::cmpeq(Expr::cmpltu(rs, imm)?, expr_const(0, 1))?,
    )?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;
    control_flow_graph.unconditional_edge(false_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn sltu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let true_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd.clone(), expr_const(1, 32));

        block.index()
    };

    let false_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, expr_const(0, 32));

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmpltu(rs.clone(), rt.clone())?,
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        false_index,
        Expr::cmpeq(Expr::cmpltu(rs, rt)?, expr_const(0, 1))?,
    )?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;
    control_flow_graph.unconditional_edge(false_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn sra(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let sa = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::ashr(rt, sa)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn srav(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let rs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::ashr(rt, rs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn srl(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let sa = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::shr(rt, sa)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn srlv(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rt = get_register(detail.operands[1].reg())?.expression();
    let rs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::shr(rt, rs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sub(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let raise_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(Intrinsic::new(
            "IntegerOverflow",
            "IntegerOverflow",
            Vec::new(),
            None,
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        ));

        block.index()
    };

    let operation_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::sub(rs.clone(), rt.clone())?);

        block.index()
    };

    let terminating_index = { control_flow_graph.new_block()?.index() };

    control_flow_graph.conditional_edge(
        head_index,
        raise_index,
        Expr::cmpltu(rs.clone(), Expr::sub(rt.clone(), rs.clone())?)?,
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        operation_index,
        Expr::cmpeq(
            Expr::cmpltu(rs.clone(), Expr::sub(rt, rs)?)?,
            expr_const(0, 1),
        )?,
    )?;

    control_flow_graph.unconditional_edge(raise_index, terminating_index)?;
    control_flow_graph.unconditional_edge(operation_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}

pub fn subu(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::sub(rs, rt)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn sw(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let addr_expr = Expr::add(base, offset)?;

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.store(addr_expr, rt);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    /*
    This code is a more accurate translation of `sw`, and raises an
    `AddressError` if the address isn't properly aligned. Unfortunately, it's
    super irritating, so for now we will leave it here, commented out.

    This also should be implemented for `lw`, but isn't implemented there.

    let head_index = {
        control_flow_graph.new_block()?.index()
    };

    let exception_index = {
        let block = control_flow_graph.new_block()?;

        block.raise(expr_scalar("AddressError", 1));

        block.index()
    };

    let op_index = {
        let block = control_flow_graph.new_block()?;

        block.store(array("mem", MEM_SIZE), addr_expr.clone(), rt);

        block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        exception_index,
        Expr::cmpneq(Expr::trun(2, addr_expr.clone())?, expr_const(0, 2))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        op_index,
        Expr::cmpeq(Expr::trun(2, addr_expr.clone())?, expr_const(0, 2))?
    )?;
    control_flow_graph.unconditional_edge(exception_index, terminating_index)?;
    control_flow_graph.unconditional_edge(op_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;
    */

    Ok(())
}

pub fn swl(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let address = Expr::add(base, offset)?;

        // load the value currently in memory
        let tmp = Scalar::temp(instruction.address, 32);
        block.load(
            tmp.clone(),
            Expr::and(expr_const(0xffff_fffc, 32), address.clone())?,
        );

        // create a mask for our value
        let mask_bytes = Expr::and(address.clone(), expr_const(3, 32))?;
        // we want the opposite of the number of bytes we are storing
        let mask_bytes = Expr::sub(expr_const(4, 32), mask_bytes)?;
        let mask_bits = Expr::shl(mask_bytes, expr_const(3, 32))?;

        let mask = Expr::sub(Expr::shl(expr_const(1, 32), mask_bits)?, expr_const(1, 32))?;

        // and the loaded value with our mask
        // this operation inverts the mask
        let tmp = Expr::and(Expr::sub(expr_const(0xffff_ffff, 32), mask)?, tmp.into())?;

        // figure out how many bits we should shift our value right
        let shift_bytes = Expr::and(address.clone(), expr_const(3, 32))?;
        let shift_bits = Expr::shl(shift_bytes, expr_const(3, 32))?;

        // shift the value right
        let rt = Expr::shr(rt, shift_bits)?;

        // or them together
        let expr = Expr::or(tmp, rt)?;

        // store it back in memory
        block.store(Expr::and(expr_const(0xffff_fffc, 32), address)?, expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn swr(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.expression();
    let base = get_register(detail.operands[1].mem().base)?.expression();
    let offset = expr_const(detail.operands[1].mem().disp as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let address = Expr::sub(Expr::add(base, offset)?, expr_const(3, 32))?;

        // create a bit mask for dst and the loaded result
        let mask_bytes = Expr::and(address.clone(), expr_const(3, 32))?;
        let mask_bits = Expr::shl(mask_bytes, expr_const(3, 32))?;
        let mask_bit = Expr::shl(expr_const(1, 32), mask_bits)?;
        let mask = Expr::sub(mask_bit, expr_const(1, 32))?;

        // load our word from memory
        let tmp = Scalar::temp(instruction.address, 32);
        block.load(tmp.clone(), address.clone());

        // zero out the words we're about to set in dst
        let dst_expr = Expr::and(
            tmp.into(),
            Expr::sub(expr_const(0xffff_ffff, 32), mask.clone())?,
        )?;

        // zero out the bits we're not setting in rt
        let rt = Expr::and(rt, mask)?;

        // or the two together
        let dst_expr = Expr::or(dst_expr, rt)?;

        // store it back in memory
        block.store(address, dst_expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn syscall(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        let intrinsic = Intrinsic::new(
            "syscall",
            "syscall",
            Vec::new(),
            Some(Vec::new()),
            Some(Vec::new()),
            instruction.bytes.get(0..4).unwrap().to_vec(),
        );

        block.intrinsic(intrinsic);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn teq(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rs = get_register(detail.operands[0].reg())?.expression();
    let rt = get_register(detail.operands[1].reg())?.expression();

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    let tail_index = { control_flow_graph.new_block()?.index() };

    let trap_index = {
        let block = control_flow_graph.new_block()?;

        let intrinsic = Intrinsic::new(
            "trap",
            "trap",
            Vec::new(),
            Some(Vec::new()),
            Some(Vec::new()),
            instruction.bytes.get(0..4).unwrap().to_vec(),
        );
        block.intrinsic(intrinsic);

        block.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        trap_index,
        Expr::cmpeq(rs.clone(), rt.clone())?,
    )?;

    control_flow_graph.conditional_edge(head_index, tail_index, Expr::cmpneq(rs, rt)?)?;

    control_flow_graph.unconditional_edge(trap_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}

pub fn xor(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let rt = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::xor(rs, rt)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn xori(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let detail = details(instruction)?;

    // get operands
    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();
    let imm = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(rd, Expr::xor(rs, imm)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}
