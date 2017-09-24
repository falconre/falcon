use capstone_rust::capstone;
use capstone_rust::capstone_sys::mips_reg;
use error::*;
use il::*;
use il::Expression as Expr;


const MEM_SIZE: u64 = (1 << 32);


/// Struct for dealing with x86 registers
pub struct MIPSRegister {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: mips_reg,
    /// The size of this register in bits
    bits: usize,
}


impl MIPSRegister {
    // pub fn bits(&self) -> usize {
    //     self.bits
    // }


    pub fn scalar(&self) -> Scalar {
        scalar(self.name, self.bits)
    }


    pub fn expression(&self) -> Expr {
        expr_scalar(self.name, self.bits)
    }
}



const MIPSREGISTERS : &'static [MIPSRegister] = &[
    MIPSRegister { name: "$zero", capstone_reg: mips_reg::MIPS_REG_0, bits: 32 },
    MIPSRegister { name: "$at", capstone_reg: mips_reg::MIPS_REG_1, bits: 32 },
    MIPSRegister { name: "$v0", capstone_reg: mips_reg::MIPS_REG_2, bits: 32 },
    MIPSRegister { name: "$v1", capstone_reg: mips_reg::MIPS_REG_3, bits: 32 },
    MIPSRegister { name: "$a0", capstone_reg: mips_reg::MIPS_REG_4, bits: 32 },
    MIPSRegister { name: "$a1", capstone_reg: mips_reg::MIPS_REG_5, bits: 32 },
    MIPSRegister { name: "$a2", capstone_reg: mips_reg::MIPS_REG_6, bits: 32 },
    MIPSRegister { name: "$a3", capstone_reg: mips_reg::MIPS_REG_7, bits: 32 },
    MIPSRegister { name: "$t0", capstone_reg: mips_reg::MIPS_REG_8, bits: 32 },
    MIPSRegister { name: "$t1", capstone_reg: mips_reg::MIPS_REG_9, bits: 32 },
    MIPSRegister { name: "$t2", capstone_reg: mips_reg::MIPS_REG_10, bits: 32 },
    MIPSRegister { name: "$t3", capstone_reg: mips_reg::MIPS_REG_11, bits: 32 },
    MIPSRegister { name: "$t4", capstone_reg: mips_reg::MIPS_REG_12, bits: 32 },
    MIPSRegister { name: "$t5", capstone_reg: mips_reg::MIPS_REG_13, bits: 32 },
    MIPSRegister { name: "$t6", capstone_reg: mips_reg::MIPS_REG_14, bits: 32 },
    MIPSRegister { name: "$t7", capstone_reg: mips_reg::MIPS_REG_15, bits: 32 },
    MIPSRegister { name: "$s0", capstone_reg: mips_reg::MIPS_REG_16, bits: 32 },
    MIPSRegister { name: "$s1", capstone_reg: mips_reg::MIPS_REG_17, bits: 32 },
    MIPSRegister { name: "$s2", capstone_reg: mips_reg::MIPS_REG_18, bits: 32 },
    MIPSRegister { name: "$s3", capstone_reg: mips_reg::MIPS_REG_19, bits: 32 },
    MIPSRegister { name: "$s4", capstone_reg: mips_reg::MIPS_REG_20, bits: 32 },
    MIPSRegister { name: "$s5", capstone_reg: mips_reg::MIPS_REG_21, bits: 32 },
    MIPSRegister { name: "$s6", capstone_reg: mips_reg::MIPS_REG_22, bits: 32 },
    MIPSRegister { name: "$s7", capstone_reg: mips_reg::MIPS_REG_23, bits: 32 },
    MIPSRegister { name: "$t8", capstone_reg: mips_reg::MIPS_REG_24, bits: 32 },
    MIPSRegister { name: "$t9", capstone_reg: mips_reg::MIPS_REG_25, bits: 32 },
    MIPSRegister { name: "$k0", capstone_reg: mips_reg::MIPS_REG_26, bits: 32 },
    MIPSRegister { name: "$k1", capstone_reg: mips_reg::MIPS_REG_27, bits: 32 },
    MIPSRegister { name: "$gp", capstone_reg: mips_reg::MIPS_REG_28, bits: 32 },
    MIPSRegister { name: "$sp", capstone_reg: mips_reg::MIPS_REG_29, bits: 32 },
    MIPSRegister { name: "$fp", capstone_reg: mips_reg::MIPS_REG_30, bits: 32 },
    MIPSRegister { name: "$ra", capstone_reg: mips_reg::MIPS_REG_31, bits: 32 },
];



/// Takes a capstone register enum and returns a `MIPSRegister`
pub fn get_register(capstone_id: mips_reg) -> Result<&'static MIPSRegister> {
    for register in MIPSREGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(&register);
        }
    }
    Err("Could not find register".into())
}



/// Returns the details section of a mips capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_mips> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::MIPS(x) => Ok(x),
        _ => Err("Could not get instruction details".into())
    }
}



pub fn add(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = get_register(detail.operands[2].reg())?.expression();

    let head_index = {
        control_flow_graph.new_block()?.index()
    };

    let raise_index = {
        let mut block = control_flow_graph.new_block()?;

        block.raise(expr_scalar("IntegerOverflow", 1));

        block.index()
    };

    let operation_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst.clone(), Expr::add(lhs.clone(), rhs.clone())?);

        block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        raise_index,
        Expr::cmpltu(Expr::add(lhs.clone(), rhs.clone())?, lhs.clone())?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        operation_index,
        Expr::cmpltu(lhs.clone(), Expr::add(lhs.clone(), rhs.clone())?)?
    )?;

    control_flow_graph.unconditional_edge(raise_index, terminating_index)?;
    control_flow_graph.unconditional_edge(operation_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn addi(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let head_index = {
        control_flow_graph.new_block()?.index()
    };

    let raise_index = {
        let mut block = control_flow_graph.new_block()?;

        block.raise(expr_scalar("IntegerOverflow", 1));

        block.index()
    };

    let operation_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst.clone(), Expr::add(lhs.clone(), rhs.clone())?);

        block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        raise_index,
        Expr::cmpltu(Expr::add(lhs.clone(), rhs.clone())?, lhs.clone())?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        operation_index,
        Expr::cmpltu(lhs.clone(), Expr::add(lhs.clone(), rhs.clone())?)?
    )?;

    control_flow_graph.unconditional_edge(raise_index, terminating_index)?;
    control_flow_graph.unconditional_edge(operation_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn addiu(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::add(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn addu(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::add(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn and(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = get_register(detail.operands[2].reg())?.expression();

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::and(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn andi(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let lhs = get_register(detail.operands[1].reg())?.expression();
    let rhs = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(dst, Expr::and(lhs, rhs)?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn b(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = control_flow_graph.new_block()?.index();

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn bal(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let operand = details(&instruction)?.operands[0];

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.brc(expr_const(operand.imm() as u64, 32), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn bgezal(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    let lhs = get_register(detail.operands[0].reg())?.expression();
    let zero = expr_const(0, 32);
    let target = expr_const(detail.operands[1].imm() as u64, 32);

    let head_index = {
        control_flow_graph.new_block()?.index()
    };

    let true_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.brc(target, expr_const(1, 1));

        block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    let false_condition = Expr::cmplts(zero, lhs)?;

    control_flow_graph.conditional_edge(
        head_index,
        true_index,
        Expr::cmpeq(false_condition.clone(), expr_const(0, 1))?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        false_condition
    )?;

    control_flow_graph.unconditional_edge(true_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn bltzal(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    let lhs = get_register(detail.operands[0].reg())?.expression();
    let zero = expr_const(0, 32);
    let target = expr_const(detail.operands[1].imm() as u64, 32);

    let head_index = {
        control_flow_graph.new_block()?.index()
    };

    let true_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("$ra", 32), expr_const(instruction.address + 8, 32));
        block.brc(target, expr_const(1, 1));

        block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    let true_condition = Expr::cmplts(lhs, zero)?;
    let false_condition = Expr::cmpeq(true_condition.clone(), expr_const(0, 1))?;

    control_flow_graph.conditional_edge(head_index, true_index, true_condition)?;
    control_flow_graph.conditional_edge(head_index, terminating_index, false_condition)?;
    control_flow_graph.unconditional_edge(true_index, terminating_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn break_(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.raise(expr_scalar("break", 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn clo(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();

    let (head_index, count) = {
        let count = control_flow_graph.temp(32);
        let mut block = control_flow_graph.new_block()?;

        block.assign(count.clone(), expr_const(0, 32));

        (block.index(), count)
    };

    let check_index = {
        control_flow_graph.new_block()?.index()
    };

    let inc_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(count.clone(), Expr::add(count.clone().into(), expr_const(1, 32))?);

        block.index()
    };

    let terminating_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(rd, count.clone().into());

        block.index()
    };

    control_flow_graph.unconditional_edge(head_index, check_index)?;
    let condition = Expr::trun(
        1,
        Expr::shr(rs, Expr::sub(expr_const(31, 32), count.clone().into())?)?
    )?;
    control_flow_graph.conditional_edge(check_index, inc_index, condition.clone())?;
    control_flow_graph.conditional_edge(
        check_index,
        terminating_index,
        Expr::cmpeq(condition.clone(), expr_const(0, 1))?
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        terminating_index,
        Expr::cmpeq(count.clone().into(), expr_const(32, 32))?
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        check_index,
        Expr::cmpneq(count.into(), expr_const(32, 32))?
    )?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn clz(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    let rd = get_register(detail.operands[0].reg())?.scalar();
    let rs = get_register(detail.operands[1].reg())?.expression();

    let (head_index, count) = {
        let count = control_flow_graph.temp(32);
        let mut block = control_flow_graph.new_block()?;

        block.assign(count.clone(), expr_const(0, 32));

        (block.index(), count)
    };

    let check_index = {
        control_flow_graph.new_block()?.index()
    };

    let inc_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(count.clone(), Expr::add(count.clone().into(), expr_const(1, 32))?);

        block.index()
    };

    let terminating_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(rd, count.clone().into());

        block.index()
    };

    control_flow_graph.unconditional_edge(head_index, check_index)?;
    let condition = Expr::trun(
        1,
        Expr::shr(rs, Expr::sub(expr_const(31, 32), count.clone().into())?)?
    )?;
    control_flow_graph.conditional_edge(
        check_index,
        inc_index,
        Expr::cmpeq(condition.clone(), expr_const(0, 1))?
    )?;
    control_flow_graph.conditional_edge(
        check_index,
        terminating_index,
        condition
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        terminating_index,
        Expr::cmpeq(count.clone().into(), expr_const(32, 32))?
    )?;
    control_flow_graph.conditional_edge(
        inc_index,
        check_index,
        Expr::cmpneq(count.into(), expr_const(32, 32))?
    )?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn div(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let lhs = get_register(detail.operands[0].reg())?.expression();
    let rhs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("$lo", 32), Expr::divs(lhs.clone(), rhs.clone())?);
        block.assign(scalar("$hi", 32), Expr::mods(lhs.clone(), rhs.clone())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn divu(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let lhs = get_register(detail.operands[0].reg())?.expression();
    let rhs = get_register(detail.operands[1].reg())?.expression();

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("$lo", 32), Expr::divu(lhs.clone(), rhs.clone())?);
        block.assign(scalar("$hi", 32), Expr::modu(lhs.clone(), rhs.clone())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lb(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].reg())?.expression();
    let offset = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let temp = block.temp(8);
        block.load(temp.clone(), Expr::add(base, offset)?, array("mem", MEM_SIZE));
        block.assign(dst, Expr::sext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lbu(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].reg())?.expression();
    let offset = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let temp = block.temp(8);
        block.load(temp.clone(), Expr::add(base, offset)?, array("mem", MEM_SIZE));
        block.assign(dst, Expr::zext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lh(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].reg())?.expression();
    let offset = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let temp = block.temp(16);
        block.load(temp.clone(), Expr::add(base, offset)?, array("mem", MEM_SIZE));
        block.assign(dst, Expr::sext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lhu(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].reg())?.expression();
    let offset = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let temp = block.temp(16);
        block.load(temp.clone(), Expr::add(base, offset)?, array("mem", MEM_SIZE));
        block.assign(dst, Expr::zext(32, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lui(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let rt = get_register(detail.operands[0].reg())?.scalar();
    let imm = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(rt, Expr::shl(imm, expr_const(16, 32))?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}




pub fn lw(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = details(instruction)?;

    // get operands
    let dst = get_register(detail.operands[0].reg())?.scalar();
    let base = get_register(detail.operands[1].reg())?.expression();
    let offset = expr_const(detail.operands[2].imm() as u64, 32);

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.load(dst, Expr::add(base, offset)?, array("mem", MEM_SIZE));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}