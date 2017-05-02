use capstone_rust::capstone;
use capstone_rust::capstone::{cs_x86_op};
use capstone_rust::capstone_sys::{x86_op_type, x86_reg};
use error::*;
use il::*;
use il::Expression as Expr;


/// Struct for dealing with x86 registers
pub struct X86Register {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: x86_reg,
    /// The full register. For example, eax is the full register for al.
    full_reg: x86_reg,
    /// The offset of this register. For example, ah is offset 8 bit into eax.
    offset: usize,
    /// The size of this register in bits
    size: usize,
}


impl X86Register {
    /// Returns true if this is a full-width register (i.e. eax, ebx, etc)
    pub fn is_full(&self) -> bool {
        if self.capstone_reg == self.full_reg {
            true
        }
        else {
            false
        }
    }

    /// Returns the full-width register for this register
    pub fn get_full(&self) -> Result<&'static X86Register> {
        get_register(self.full_reg)
    }

    /// Returns an expression which evaluates to the value of the register.
    ///
    /// This handles things like al/ah/ax/eax
    pub fn get(&self) -> Result<Expression> {
        if self.is_full() {
            return Ok(expr_var(self.name, self.size));
        }
        else if self.offset == 0 {
            return Expr::trun(self.size, self.get_full()?.get()?);
        }
        else {
            let full_reg = self.get_full()?;
            let expr = Expr::shr(full_reg.get()?, expr_const(self.offset as u64, full_reg.size))?;
            return Expr::trun(self.size, expr);
        }
    }

    /// Sets the value of this register.
    ///
    /// This handles things like al/ah/ax/eax
    pub fn set(&self, block: &mut Block, value: Expression) -> Result<()> {
        if self.is_full() {
            block.assign(var(self.name, self.size), value);
            return Ok(())
        }
        else if self.offset == 0 {
            let full_reg = self.get_full()?;
            let mask = !0 << self.size;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.size))?;
            let expr = Expr::or(expr, Expr::zext(full_reg.size, value)?)?;
            return full_reg.set(block, expr);
        }
        else {
            let full_reg = self.get_full()?;
            let mask = ((1 << self.size) - 1) << self.offset;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.size))?;
            let value = Expr::zext(full_reg.size, value)?;
            let expr = Expr::or(expr, Expr::shl(value, expr_const(self.offset as u64, full_reg.size))?)?;
            return full_reg.set(block, expr);
        }
    }
}



const X86REGISTERS : &'static [X86Register] = &[
    X86Register { name: "ah", capstone_reg: x86_reg::X86_REG_AH, full_reg: x86_reg::X86_REG_EAX, offset: 8, size: 8 },
    X86Register { name: "al", capstone_reg: x86_reg::X86_REG_AL, full_reg: x86_reg::X86_REG_EAX, offset: 0, size: 8 },
    X86Register { name: "ax", capstone_reg: x86_reg::X86_REG_AX, full_reg: x86_reg::X86_REG_EAX, offset: 0, size: 16 },
    X86Register { name: "eax", capstone_reg: x86_reg::X86_REG_EAX, full_reg: x86_reg::X86_REG_EAX, offset: 0, size: 32 },
    X86Register { name: "bh", capstone_reg: x86_reg::X86_REG_BH, full_reg: x86_reg::X86_REG_EBX, offset: 8, size: 8 },
    X86Register { name: "bl", capstone_reg: x86_reg::X86_REG_BL, full_reg: x86_reg::X86_REG_EBX, offset: 0, size: 8 },
    X86Register { name: "bx", capstone_reg: x86_reg::X86_REG_BX, full_reg: x86_reg::X86_REG_EBX, offset: 0, size: 16 },
    X86Register { name: "ebx", capstone_reg: x86_reg::X86_REG_EBX, full_reg: x86_reg::X86_REG_EBX, offset: 0, size: 32 },
    X86Register { name: "ch", capstone_reg: x86_reg::X86_REG_CH, full_reg: x86_reg::X86_REG_ECX, offset: 8, size: 8 },
    X86Register { name: "cl", capstone_reg: x86_reg::X86_REG_CL, full_reg: x86_reg::X86_REG_ECX, offset: 0, size: 8 },
    X86Register { name: "cx", capstone_reg: x86_reg::X86_REG_CX, full_reg: x86_reg::X86_REG_ECX, offset: 0, size: 16 },
    X86Register { name: "ecx", capstone_reg: x86_reg::X86_REG_ECX, full_reg: x86_reg::X86_REG_ECX, offset: 0, size: 32 },
    X86Register { name: "dh", capstone_reg: x86_reg::X86_REG_DH, full_reg: x86_reg::X86_REG_EDX, offset: 8, size: 8 },
    X86Register { name: "dl", capstone_reg: x86_reg::X86_REG_DL, full_reg: x86_reg::X86_REG_EDX, offset: 0, size: 8 },
    X86Register { name: "dx", capstone_reg: x86_reg::X86_REG_DX, full_reg: x86_reg::X86_REG_EDX, offset: 0, size: 16 },
    X86Register { name: "edx", capstone_reg: x86_reg::X86_REG_EDX, full_reg: x86_reg::X86_REG_EDX, offset: 0, size: 32 },
    X86Register { name: "si", capstone_reg: x86_reg::X86_REG_SI, full_reg: x86_reg::X86_REG_ESI, offset: 0, size: 16 },
    X86Register { name: "esi", capstone_reg: x86_reg::X86_REG_ESI, full_reg: x86_reg::X86_REG_ESI, offset: 0, size: 32 },
    X86Register { name: "di", capstone_reg: x86_reg::X86_REG_DI, full_reg: x86_reg::X86_REG_EDI, offset: 0, size: 16 },
    X86Register { name: "edi", capstone_reg: x86_reg::X86_REG_EDI, full_reg: x86_reg::X86_REG_EDI, offset: 0, size: 32 },
    X86Register { name: "sp", capstone_reg: x86_reg::X86_REG_SP, full_reg: x86_reg::X86_REG_ESP, offset: 0, size: 16 },
    X86Register { name: "esp", capstone_reg: x86_reg::X86_REG_ESP, full_reg: x86_reg::X86_REG_ESP, offset: 0, size: 32 },
    X86Register { name: "bp", capstone_reg: x86_reg::X86_REG_BP, full_reg: x86_reg::X86_REG_EBP, offset: 0, size: 16 },
    X86Register { name: "ebp", capstone_reg: x86_reg::X86_REG_EBP, full_reg: x86_reg::X86_REG_EBP, offset: 0, size: 32 },
];


/// Takes a capstone register enum and returns an X86Register
pub fn get_register(capstone_id: x86_reg) -> Result<&'static X86Register> {
    for register in X86REGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(&register);
        }
    }
    return Err("Could not find register".into());
}



/// Returns the details section of an x86 capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_x86> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::X86(x) => Ok(x),
        _ => Err("Could not get instruction details".into())
    }
}


/// Gets the value of an operand as an IL expression
pub fn operand_value(block: &Block, operand: &cs_x86_op) -> Result<Expression> {
    match operand.type_ {
        x86_op_type::X86_OP_INVALID => Err("Invalid operand".into()),
        x86_op_type::X86_OP_REG => {
            // Get the register value
            return get_register(*operand.reg())?.get();
        }
        x86_op_type::X86_OP_MEM => {
            let mem = operand.mem();
            let base_capstone_reg = capstone::x86_reg::from(mem.base);
            let index_capstone_reg = capstone::x86_reg::from(mem.index);

            let base = match base_capstone_reg {
                x86_reg::X86_REG_INVALID => None,
                reg => Some(get_register(reg)?.get()?)
            };

            let index = match index_capstone_reg {
                x86_reg::X86_REG_INVALID => None,
                reg => Some(get_register(reg)?.get()?)
            };

            let scale = Expr::constant(Constant::new(mem.scale as i64 as u64, 32));

            let si = match index {
                Some(index) => Some(Expr::mulu(index, scale).unwrap()),
                None => None
            };

            let op : Expression = if base.is_some() {
                if si.is_some() {
                    Expr::add(base.unwrap(), si.unwrap()).unwrap()
                }
                else {
                    base.unwrap()
                }
            } 
            else if si.is_some() {
                si.unwrap()
            }
            else {
                return Ok(Expr::constant(Constant::new(mem.disp as u64, 32)));
            };

            if mem.disp > 0 {
                let constant = Expr::constant(Constant::new(mem.disp as u64, 32));
                let add = Expr::add(op, constant)?;
                return Ok(add);
            }
            else {
                return Ok(op);
            }
        },
        x86_op_type::X86_OP_IMM => {
            return Ok(expr_const(operand.imm() as u64, operand.size as usize * 8));
        }
        x86_op_type::X86_OP_FP => Err("Unhandled operand".into()),
    }
}


/// Gets the value of an operand as an IL expression, performing any required loads as needed.
pub fn operand_load(block: &mut Block, operand: &cs_x86_op) -> Result<Expression> {
    let op = try!(operand_value(block, operand));

    if operand.type_ == x86_op_type::X86_OP_MEM {
        let temp = block.temp(operand.size as usize * 8);
        block.load(temp.clone(), op);
        return Ok(temp.into());
    }
    return Ok(op);
}


/// Stores a value in an operand, performing any stores as necessary.
pub fn operand_store(mut block: &mut Block, operand: &cs_x86_op, value: Expression) -> Result<()> {
    match operand.type_ {
        x86_op_type::X86_OP_INVALID => return Err("operand_store called on invalid operand".into()),
        x86_op_type::X86_OP_IMM => return Err("operand_store called on immediate operand".into()),
        x86_op_type::X86_OP_REG => {
            let dst_register = get_register(*operand.reg())?;
            return dst_register.set(&mut block, value);
        },
        x86_op_type::X86_OP_MEM => {
            let address = operand_value(&mut block, operand)?;
            block.store(address, value);
            return Ok(());
        },
        x86_op_type::X86_OP_FP => {
            return Err("operand_store called on fp operand".into());
        }
    }
}


/// Convenience function to pop a value off the stack
pub fn pop_value(block: &mut Block) -> Result<Expression> {
    let temp = block.temp(32);

    block.load(temp.clone(), expr_var("esp", 32));
    block.assign(var("esp", 32), Expr::add(expr_var("esp", 32), expr_const(4, 32))?);

    return Ok(temp.into());
}


/// Convenience function to push a value onto the stack
pub fn push_value(block: &mut Block, value: Expression) -> Result<()> {
    block.assign(var("esp", 32), Expr::sub(expr_var("esp", 32), expr_const(4, 32))?);
    block.store(expr_var("esp", 32), value);
    Ok(())
}


/// Convenience function set set the zf based on result
pub fn set_zf(block: &mut Block, result: Expression) -> Result<()> {
    block.assign(var("ZF", 1), Expr::cmpeq(result.clone(), expr_const(0, result.bits()))?);
    Ok(())
}


/// Convenience function to set the sf based on result
pub fn set_sf(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::shr(result.clone(), expr_const((result.bits() - 1) as u64, result.bits()))?;
    let expr = Expr::trun(1, expr)?;
    block.assign(var("SF", 1), expr);
    Ok(())
}


/// Convenience function to set the of based on result and both operands
pub fn set_of(block: &mut Block, result: Expression, lhs: Expression, rhs: Expression) -> Result<()> {
    let expr0 = Expr::xor(lhs.clone().into(), rhs.clone().into())?;
    let expr1 = Expr::xor(lhs.clone().into(), result.clone().into())?;
    let expr = Expr::and(expr0, expr1)?;
    let expr = Expr::shr(expr.clone(), expr_const((expr.bits() - 1) as u64, expr.bits()))?;
    block.assign(var("OF", 1), Expr::trun(1, expr)?);
    Ok(())
}


/// Convenience function to set the cf based on result and lhs operand
pub fn set_cf(block: &mut Block, result: Expression, lhs: Expression) -> Result<()> {
    let expr = Expr::cmpltu(lhs.clone().into(), result.clone().into())?;
    block.assign(var("CF", 1), expr);
    Ok(())
}


/// Returns a condition which is true if a conditional jump should be taken
pub fn jcc_condition(instruction: &capstone::Instr) -> Result<Expression> {
    let expr = if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_JA => {
                let cf = Expr::cmpeq(expr_var("CF", 1), expr_const(0, 1))?;
                let zf = Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?;
                Expr::and(cf, zf)?
            },
            capstone::x86_insn::X86_INS_JAE => Expr::cmpeq(expr_var("CF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JB => Expr::cmpeq(expr_var("CF", 1), expr_const(1, 1))?,
            capstone::x86_insn::X86_INS_JBE => {
                let cf = Expr::cmpeq(expr_var("CF", 1), expr_const(1, 1))?;
                let zf = Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?;
                Expr::or(cf, zf)?
            },
            capstone::x86_insn::X86_INS_JCXZ => {
                let cx = get_register(x86_reg::X86_REG_CX)?.get()?;
                Expr::cmpeq(cx, expr_const(0, 16))?
            },
            capstone::x86_insn::X86_INS_JECXZ => {
                let cx = get_register(x86_reg::X86_REG_ECX)?.get()?;
                Expr::cmpeq(cx, expr_const(0, 32))?
            },
            capstone::x86_insn::X86_INS_JE => Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JG => {
                let sfof = Expr::cmpeq(expr_var("SF", 1), expr_var("OF", 1))?;
                let zf = Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?;
                Expr::and(sfof, zf)?
            },
            capstone::x86_insn::X86_INS_JGE => Expr::cmpeq(expr_var("SF", 1), expr_var("OF", 1))?,
            capstone::x86_insn::X86_INS_JL => Expr::cmpneq(expr_var("SF", 1), expr_var("OF", 1))?,
            capstone::x86_insn::X86_INS_JLE => {
                let sfof = Expr::cmpneq(expr_var("SF", 1), expr_var("OF", 1))?;
                let zf = Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?;
                Expr::and(sfof, zf)?
            },
            capstone::x86_insn::X86_INS_JNE => Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JNO => Expr::cmpeq(expr_var("OF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JNP => Expr::cmpeq(expr_var("PF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JNS => Expr::cmpeq(expr_var("SF", 1), expr_const(0, 1))?,
            capstone::x86_insn::X86_INS_JO  => Expr::cmpeq(expr_var("OF", 1), expr_const(1, 1))?,
            capstone::x86_insn::X86_INS_JP  => Expr::cmpeq(expr_var("PF", 1), expr_const(1, 1))?,
            capstone::x86_insn::X86_INS_JS  => Expr::cmpeq(expr_var("SF", 1), expr_const(1, 1))?,
            _ => bail!("unhandled jcc")
        }
    }
    else {
        bail!("not an x86 instruction")
    };

    Ok(expr)
}


/// Returns a condition which is true if a loop should be taken
pub fn loop_condition(instruction: &capstone::Instr) -> Result<Expression> {
    let ecx = var("ecx", 32);

    let expr = if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_LOOP => Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits()))?,
            capstone::x86_insn::X86_INS_LOOPE => {
                let expr = Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits()))?;
                let expr = Expr::and(expr, Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?);
                return expr;
            }
            capstone::x86_insn::X86_INS_LOOPNE => {
                let expr = Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits()))?;
                let expr = Expr::and(expr, Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?);
                return expr;
            }
            _ => bail!("unhandled loop")
        }
    }
    else {
        bail!("not an x86 instruction")
    };

    Ok(expr)
}


/// Wraps the given instruction graph with the rep prefix inplace
pub fn rep_prefix(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    if control_flow_graph.entry().is_none() || control_flow_graph.exit().is_none() {
        bail!("control_flow_graph entry/exit was none");
    }

    let head_index = control_flow_graph.new_block()?.index();

    let loop_index = {
        let mut loop_block = control_flow_graph.new_block()?;
        loop_block.assign(var("ecx", 32), Expr::sub(expr_var("ecx", 32), expr_const(1, 32))?);
        loop_block.index()
    };

    let terminating_index = control_flow_graph.new_block()?.index();

    let entry = control_flow_graph.entry().clone().unwrap();
    let exit = control_flow_graph.exit().clone().unwrap();

    // head -> entry
    // head -> terminating
    control_flow_graph.conditional_edge(
        head_index,
        entry,
        Expr::cmpneq(expr_var("ecx", 32), expr_const(0, 32))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpeq(expr_var("ecx", 32), expr_const(0, 32))?
    )?;

    // exit -> loop
    control_flow_graph.unconditional_edge(exit, loop_index)?;

    if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_CMPSB |
            capstone::x86_insn::X86_INS_CMPSW |
            capstone::x86_insn::X86_INS_CMPSD |
            capstone::x86_insn::X86_INS_SCASB |
            capstone::x86_insn::X86_INS_SCASW |
            capstone::x86_insn::X86_INS_SCASD => {
                // loop -> head
                control_flow_graph.conditional_edge(
                    loop_index,
                    head_index,
                    Expr::cmpneq(expr_var("ZF", 1), expr_const(0, 1))?
                )?;
                // loop -> terminating
                control_flow_graph.conditional_edge(
                    loop_index,
                    terminating_index,
                    Expr::cmpneq(expr_var("ZF", 1), expr_const(1, 1))?
                )?;
            },
            capstone::x86_insn::X86_INS_STOSB |
            capstone::x86_insn::X86_INS_STOSW |
            capstone::x86_insn::X86_INS_STOSD => {
                // loop -> head
                control_flow_graph.unconditional_edge(loop_index, head_index)?;
            },
            _ => bail!("unsupported instruction for rep prefix")
        }
    }

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



/// Wraps the given instruction graph with the repe prefix inplace
pub fn repe_prefix(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    if control_flow_graph.entry().is_none() || control_flow_graph.exit().is_none() {
        bail!("control_flow_graph entry/exit was none");
    }
    
    let head_index = control_flow_graph.new_block()?.index();

    let loop_index = {
        let mut loop_block = control_flow_graph.new_block()?;
        loop_block.assign(var("ecx", 32), Expr::sub(expr_var("ecx", 32), expr_const(1, 32))?);
        loop_block.index()
    };

    let terminating_index = control_flow_graph.new_block()?.index();

    let entry = control_flow_graph.entry().clone().unwrap();
    let exit = control_flow_graph.exit().clone().unwrap();

    // head -> entry
    // head -> terminating
    control_flow_graph.conditional_edge(
        head_index,
        entry,
        Expr::cmpneq(expr_var("ecx", 32), expr_const(0, 32))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpeq(expr_var("ecx", 32), expr_const(0, 32))?
    )?;

    // exit -> loop
    control_flow_graph.unconditional_edge(exit, loop_index)?;

    if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_CMPSB |
            capstone::x86_insn::X86_INS_CMPSW |
            capstone::x86_insn::X86_INS_CMPSD |
            capstone::x86_insn::X86_INS_SCASB |
            capstone::x86_insn::X86_INS_SCASW |
            capstone::x86_insn::X86_INS_SCASD => {
                // loop -> head
                control_flow_graph.conditional_edge(
                    loop_index,
                    head_index,
                    Expr::cmpneq(expr_var("ZF", 1), expr_const(1, 1))?
                )?;
                // loop -> terminating
                control_flow_graph.conditional_edge(
                    loop_index,
                    terminating_index,
                    Expr::cmpneq(expr_var("ZF", 1), expr_const(0, 1))?
                )?;
            },
            capstone::x86_insn::X86_INS_STOSB |
            capstone::x86_insn::X86_INS_STOSW |
            capstone::x86_insn::X86_INS_STOSD => {
                // loop -> head
                control_flow_graph.unconditional_edge(loop_index, head_index)?;
            },
            _ => bail!("unsupported instruction for repne prefix")
        }
    }

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn adc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let result: Variable = block.temp(lhs.bits());

        // perform addition
        let addition = Expr::add(lhs.clone(), rhs.clone())?;
        let zext_cf = Expr::zext(lhs.bits(), Expr::variable(Variable::new("CF", 1)))?;
        block.assign(result.clone(), Expr::add(addition, zext_cf)?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone().into(), lhs.clone())?;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn add(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let result = block.temp(lhs.bits());

        // perform addition
        block.assign(result.clone(), Expr::add(lhs.clone(), rhs.clone())?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone().into(), lhs.clone())?;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn and(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if rhs.bits() != lhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs)?;
        }

        let result = block.temp(lhs.bits());

        // perform addition
        block.assign(result.clone(), Expr::and(lhs.clone(), rhs.clone())?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        block.assign(Variable::new("CF", 1), expr_const(0, 1));
        block.assign(Variable::new("OF", 1), expr_const(0, 1));

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


/*
    BSF scans the bits in the second word or doubleword operand starting with
    bit 0. The ZF flag is cleared if the bits are all 0; otherwise, the ZF flag
    is set and the destination register is loaded with the bit index of the
    first set bit.
*/
pub fn bsf(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));


    // create our head block
    let (head_index, dst, rhs, counter) = {
        let (head_index, dst, rhs) = {
            let mut head_block = control_flow_graph.new_block()?;

            // get started
            let dst = operand_load(&mut head_block, &detail.operands[0])?;
            let rhs = operand_load(&mut head_block, &detail.operands[1])?;

            (head_block.index(), dst, rhs)
        };

        let counter = {
            control_flow_graph.temp(rhs.bits())
        };

        let mut head_block = control_flow_graph.block_mut(head_index)?;
        
        // This is the loop preamble, and we'll always execute it
        head_block.assign(var("ZF", 1), expr_const(0, 1));
        head_block.assign(counter.clone(), expr_const(0, rhs.bits()));

        (head_index, dst, rhs, counter)
    };

    // if rhs == 0 then ZF = 1 and we are done.
    let zero_index = {
        let mut zero_block = control_flow_graph.new_block()?;
        zero_block.assign(var("ZF", 1), expr_const(1, 1));

        zero_block.index()
    };

    // The loop body checks if the bits for our counter is set.
    let (bitfield, loop_index) = {
        let bitfield = control_flow_graph.temp(rhs.bits());

        let mut loop_block = control_flow_graph.new_block()?;
        loop_block.assign(bitfield.clone(), 
            Expr::and(
                Expr::shr(rhs.clone(), counter.clone().into())?,
                expr_const(1, rhs.bits())
            )?
        );

        (bitfield, loop_block.index())
    };

    // While our bitfield == 0, we increment counter and keep looping
    let iterate_index = {
        let mut iterate_block = control_flow_graph.new_block()?;

        iterate_block.assign(counter.clone(), Expr::add(counter.clone().into(), expr_const(1, counter.bits()))?);

        iterate_block.index()
    };

    // In our terminating block, we set the result to counter
    let terminating_index = {
        let mut terminating_block = control_flow_graph.new_block()?;

        operand_store(&mut terminating_block, &detail.operands[0], counter.into())?;

        terminating_block.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        zero_index,
        Expr::cmpeq(rhs.clone(), expr_const(0, rhs.bits()))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        loop_index,
        Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?
    )?;

    control_flow_graph.unconditional_edge(zero_index, terminating_index)?;

    control_flow_graph.conditional_edge(
        loop_index,
        iterate_index,
        Expr::cmpeq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
    )?;
    control_flow_graph.conditional_edge(
        loop_index,
        terminating_index,
        Expr::cmpneq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
    )?;
    control_flow_graph.unconditional_edge(iterate_index, loop_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}


/*
    BSR scans the bits in the second word or doubleword operand from the most
    significant bit to the least significant bit. The ZF flag is cleared if the
    bits are all 0; otherwise, ZF is set and the destination register is loaded
    with the bit index of the first set bit found when scanning in the reverse
    direction.
*/
pub fn bsr(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let (head_index, dst, rhs, counter) = {
        let (head_index, dst, rhs) = {
            let mut head_block = control_flow_graph.new_block()?;

            // get started
            let dst = operand_load(&mut head_block, &detail.operands[0])?;
            let rhs = operand_load(&mut head_block, &detail.operands[1])?;

            (head_block.index(), dst, rhs)
        };

        let counter = {
            control_flow_graph.temp(rhs.bits())
        };

        let mut head_block = control_flow_graph.block_mut(head_index)?;
        
        // This is the loop preamble, and we'll always execute it
        head_block.assign(var("ZF", 1), expr_const(0, 1));
        head_block.assign(counter.clone(), expr_const((rhs.bits() - 1) as u64, rhs.bits()));

        (head_index, dst, rhs, counter)
    };


    // if rhs == 0 then ZF = 1 and we are done.
    let zero_index = {
        let mut zero_block = control_flow_graph.new_block()?;
        zero_block.assign(var("ZF", 1), expr_const(1, 1));

        zero_block.index()
    };

    // The loop body checks if the bits for our counter is set
    let (bitfield, loop_index) = {
        let bitfield = control_flow_graph.temp(rhs.bits());

        let mut loop_block = control_flow_graph.new_block()?;
        loop_block.assign(bitfield.clone(), 
            Expr::and(
                Expr::shr(rhs.clone(), counter.clone().into())?,
                expr_const(1, rhs.bits())
            )?
        );

        (bitfield, loop_block.index())
    };    

    // While our bitfield == 0, we decrement counter and keep looping
    let iterate_index = {
        let mut iterate_block = control_flow_graph.new_block()?;

        iterate_block.assign(counter.clone(), Expr::sub(counter.clone().into(), expr_const(1, counter.bits()))?);

        iterate_block.index()
    };

    // In our terminating block, we set the result to counter
    let terminating_index = {
        let mut terminating_block = control_flow_graph.new_block()?;

        operand_store(&mut terminating_block, &detail.operands[0], counter.into())?;

        terminating_block.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        zero_index,
        Expr::cmpeq(rhs.clone(), expr_const(0, rhs.bits()))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        loop_index,
        Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?
    )?;

    control_flow_graph.unconditional_edge(zero_index, terminating_index)?;

    control_flow_graph.conditional_edge(
        loop_index,
        iterate_index,
        Expr::cmpeq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
    )?;
    control_flow_graph.conditional_edge(
        loop_index,
        terminating_index,
        Expr::cmpneq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
    )?;
    control_flow_graph.unconditional_edge(iterate_index, loop_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}


/*
    BT saves the value of the bit indicated by the base (first operand) and the
    bit offset (second operand) into the carry flag.

    CF ← BIT[LeftSRC, RightSRC];

    0F A3 BT r/m16,r16 3/12 Save bit in carry flag
    0F A3 BT r/m32,r32 3/12 Save bit in carry flag
    0F BA /4 ib BT r/m16,imm8 3/6 Save bit in carry flag
    0F BA /4 ib BT r/m32,imm8 3/6 Save bit in carry flag
*/
pub fn bt(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create our head block
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get started
        let base = operand_load(&mut block, &detail.operands[0])?;
        let mut offset = operand_load(&mut block, &detail.operands[1])?;

        // let's ensure we have equal sorts
        if offset.bits() != base.bits() {
            let temp = block.temp(base.bits());
            block.assign(temp.clone(), Expr::zext(base.bits(), offset.clone().into())?);
            offset = temp.into();
        }

        let temp = block.temp(base.bits());
        block.assign(temp.clone(), Expr::shr(base.into(), offset.into())?);
        block.assign(var("CF", 1), Expr::trun(1, temp.into())?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


/*
    BTC saves the value of the bit indicated by the base (first operand) and the
    bit offset (second operand) into the carry flag and then complements the
    bit.

    CF ← BIT[LeftSRC, RightSRC];
    BIT[LeftSRC, RightSRC] ← NOT BIT[LeftSRC, RightSRC];

    0F BB BTC r/m16,r16 6/13 Save bit in carry flag and complement
    0F BB BTC r/m32,r32 6/13 Save bit in carry flag and complement
    0F BA /7 ib BTC r/m16,imm8 6/8 Save bit in carry flag and complement
    0F BA /7 ib BTC r/m32,imm8 6/8 Save bit in carry flag and complement
*/
pub fn btc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create our head block
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get started
        let base = operand_load(&mut block, &detail.operands[0])?;
        let mut offset = operand_load(&mut block, &detail.operands[1])?;

        // let's ensure we have equal sorts
        if offset.bits() != base.bits() {
            let temp = block.temp(base.bits());
            block.assign(temp.clone(), Expr::zext(base.bits(), offset.clone().into())?);
            offset = temp.into();
        }

        // this handles the assign to CF
        let temp = block.temp(base.bits());
        block.assign(temp.clone(), Expr::shr(base.into(), offset.clone().into())?);
        block.assign(var("CF", 1), Expr::trun(1, temp.clone().into())?);

        let expr = Expr::xor(temp.clone().into(), expr_const(1, temp.clone().bits()))?;
        let expr = Expr::shl(expr, offset.into())?;
        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


/*
    BTR saves the value of the bit indicated by the base (first operand) and the
    bit offset (second operand) into the carry flag and then stores 0 in the
    bit.

    CF ← BIT[LeftSRC, RightSRC];
    BIT[LeftSRC, RightSRC] ← 0;

    0F B3 BTR r/m16,r16 6/13 Save bit in carry flag and reset
    0F B3 BTR r/m32,r32 6/13 Save bit in carry flag and reset
    0F BA /6 ib BTR r/m16,imm8 6/8 Save bit in carry flag and reset
    0F BA /6 ib BTR r/m32,imm8 6/8 Save bit in carry flag and reset
*/
pub fn btr(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create our head block
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get started
        let base = operand_load(&mut block, &detail.operands[0])?;
        let mut offset = operand_load(&mut block, &detail.operands[1])?;

        // let's ensure we have equal sorts
        if offset.bits() != base.bits() {
            let temp = block.temp(base.bits());
            block.assign(temp.clone(), Expr::zext(base.bits(), offset.clone().into())?);
            offset = temp.into();
        }

        // this handles the assign to CF
        let temp = block.temp(base.bits());
        block.assign(temp.clone(), Expr::shr(base.clone().into(), offset.clone().into())?);
        block.assign(var("CF", 1), Expr::trun(1, temp.clone().into())?);

        let expr = Expr::shl(expr_const(1, base.bits()), offset.into())?;
        let expr = Expr::xor(expr, expr_const(0xffffffffffffffff, base.bits()))?;
        let expr = Expr::and(base.into(), expr)?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


/*
    BTS saves the value of the bit indicated by the base (first operand) and the
    bit offset (second operand) into the carry flag and then stores 1 in the
    bit.

    CF ← BIT[LeftSRC, RightSRC];
    BIT[LeftSRC, RightSRC] ← 1;

    0F AB BTS r/m16,r16 6/13 Save bit in carry flag and set
    0F AB BTS r/m32,r32 6/13 Save bit in carry flag and set
    0F BA /5 ib BTS r/m16,imm8 6/8 Save bit in carry flag and set
    0F BA /5 ib BTS r/m32,imm8 6/8 Save bit in carry flag and set
*/
pub fn bts(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create our head block
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get started
        let base = operand_load(&mut block, &detail.operands[0])?;
        let mut offset = operand_load(&mut block, &detail.operands[1])?;

        // let's ensure we have equal sorts
        if offset.bits() != base.bits() {
            let temp = block.temp(base.bits());
            block.assign(temp.clone(), Expr::zext(base.bits(), offset.clone().into())?);
            offset = temp.into();
        }

        // this handles the assign to CF
        let temp = block.temp(base.bits());
        block.assign(temp.clone(), Expr::shr(base.clone().into(), offset.clone().into())?);
        block.assign(var("CF", 1), Expr::trun(1, temp.clone().into())?);

        let expr = Expr::shl(expr_const(1, base.bits()), offset.into())?;
        let expr = Expr::or(base.into(), expr)?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn call(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get started
        let dst = operand_load(&mut block, &detail.operands[0])?;

        push_value(&mut block, expr_var("eip", 32))?;

        block.brc(dst, expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cbw(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;
        let src = operand_load(&mut block, &detail.operands[1])?;

        let expr = Expr::sext(dst.bits(), src.into())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cdq(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // isolate the sign bits of ax
        let expr = Expr::shr(expr_var("eax", 32), expr_const(31, 32))?;
        let expr = Expr::trun(1, expr)?;
        let expr = Expr::sext(32, expr)?;

        block.assign(var("edx", 32), expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn clc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("CF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cld(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("DF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cli(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("IF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cmc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let expr = Expr::xor(expr_var("CF", 1), expr_const(1, 1))?;
        block.assign(var("CF", 1), expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cmp(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[0])?;

        if rhs.bits() != lhs.bits() {
            let temp = block.temp(lhs.bits());
            block.assign(temp.clone(), Expr::sext(lhs.bits(), rhs.into())?);
            rhs = temp.into();
        }

        let result = block.temp(lhs.bits());
        block.assign(result.clone(), Expr::sub(lhs.clone().into(), rhs.clone().into())?);

        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone().into(), lhs.clone())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cwd(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // isolate the sign bits of ax
        let expr = Expr::shr(expr_var("ax", 16), expr_const(15, 16))?;
        let expr = Expr::trun(1, expr)?;
        let expr = Expr::sext(16, expr)?;

        block.assign(var("dx", 16), expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cwde(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;
        let src = operand_load(&mut block, &detail.operands[1])?;

        let expr = Expr::sext(dst.bits(), src.into())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn dec(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;

        let expr = Expr::sub(dst.clone().into(), expr_const(1, dst.bits()))?;

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), dst.clone(), expr_const(1, dst.bits()))?;
        set_cf(&mut block, expr.clone(), dst.clone())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn div(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let divisor = operand_load(&mut block, &detail.operands[0])?;
        let divisor = Expr::zext(divisor.bits() * 2, divisor)?;

        let dividend: Expr = match divisor.bits() {
            16 => get_register(x86_reg::X86_REG_AX)?.get()?,
            32 => {
                let expr_dx = Expr::zext(32, get_register(x86_reg::X86_REG_DX)?.get()?)?;
                let expr_dx = Expr::shl(expr_dx, expr_const(16, 32))?;
                let expr = Expr::or(expr_dx, Expr::zext(32, get_register(x86_reg::X86_REG_AX)?.get()?)?)?;
                expr
            },
            64 => {
                let expr_edx = Expr::zext(64, get_register(x86_reg::X86_REG_EDX)?.get()?)?;
                let expr_edx = Expr::shl(expr_edx, expr_const(32, 64))?;
                let expr = Expr::or(expr_edx, Expr::zext(64, get_register(x86_reg::X86_REG_EAX)?.get()?)?)?;
                expr
            },
            _ => return Err("invalid bit-width in x86 div".into())
        };

        let quotient  = block.temp(divisor.bits());
        let remainder = block.temp(divisor.bits());

        block.assign(quotient.clone(), Expr::divu(dividend.clone(), divisor.clone())?);
        block.assign(remainder.clone(), Expr::modu(dividend, divisor.clone())?);

        match divisor.bits() {
            16 => {
                let al = get_register(x86_reg::X86_REG_AL)?;
                let ah = get_register(x86_reg::X86_REG_AH)?;
                al.set(&mut block, Expr::trun(8, quotient.into())?)?;
                ah.set(&mut block, Expr::trun(8, remainder.into())?)?;
            },
            32 => {
                let ax = get_register(x86_reg::X86_REG_AX)?;
                let dx = get_register(x86_reg::X86_REG_DX)?;
                ax.set(&mut block, Expr::trun(16, quotient.into())?)?;
                dx.set(&mut block, Expr::trun(16, remainder.into())?)?;
            },
            64 => {
                let eax = get_register(x86_reg::X86_REG_EAX)?;
                let edx = get_register(x86_reg::X86_REG_EDX)?;
                eax.set(&mut block, Expr::trun(32, quotient.into())?)?;
                edx.set(&mut block, Expr::trun(32, remainder.into())?)?;
            },
            _ => return Err("invalid bit-width in x86 div".into())
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


// This is essentially the exact same as div with the signs of the arith ops
// reversed.
pub fn idiv(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let divisor = operand_load(&mut block, &detail.operands[0])?;
        let divisor = Expr::zext(divisor.bits() * 2, divisor)?;

        let dividend: Expr = match divisor.bits() {
            16 => get_register(x86_reg::X86_REG_AX)?.get()?,
            32 => {
                let expr_dx = Expr::zext(32, get_register(x86_reg::X86_REG_DX)?.get()?)?;
                let expr_dx = Expr::shl(expr_dx, expr_const(16, 32))?;
                let expr = Expr::or(expr_dx, Expr::zext(32, get_register(x86_reg::X86_REG_AX)?.get()?)?)?;
                expr
            },
            64 => {
                let expr_edx = Expr::zext(64, get_register(x86_reg::X86_REG_EDX)?.get()?)?;
                let expr_edx = Expr::shl(expr_edx, expr_const(32, 64))?;
                let expr = Expr::or(expr_edx, Expr::zext(64, get_register(x86_reg::X86_REG_EAX)?.get()?)?)?;
                expr
            },
            _ => return Err("invalid bit-width in x86 div".into())
        };

        let quotient  = block.temp(divisor.bits());
        let remainder = block.temp(divisor.bits());

        block.assign(quotient.clone(), Expr::divs(dividend.clone(), divisor.clone())?);
        block.assign(remainder.clone(), Expr::mods(dividend, divisor.clone())?);

        match divisor.bits() {
            16 => {
                let al = get_register(x86_reg::X86_REG_AL)?;
                let ah = get_register(x86_reg::X86_REG_AH)?;
                al.set(&mut block, Expr::trun(8, quotient.into())?)?;
                ah.set(&mut block, Expr::trun(8, remainder.into())?)?;
            },
            32 => {
                let ax = get_register(x86_reg::X86_REG_AX)?;
                let dx = get_register(x86_reg::X86_REG_DX)?;
                ax.set(&mut block, Expr::trun(16, quotient.into())?)?;
                dx.set(&mut block, Expr::trun(16, remainder.into())?)?;
            },
            64 => {
                let eax = get_register(x86_reg::X86_REG_EAX)?;
                let edx = get_register(x86_reg::X86_REG_EDX)?;
                eax.set(&mut block, Expr::trun(32, quotient.into())?)?;
                edx.set(&mut block, Expr::trun(32, remainder.into())?)?;
            },
            _ => return Err("invalid bit-width in x86 div".into())
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}


// If we have one operand, we go in AX, DX:AX, EDX:EAX
// If we have two operands, sign-extend rhs if required, go in 0 operand
// If we have three operands, sign-extend rhs if required, go in 0 operand
pub fn imul(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // Get multiplicand
        let multiplicand = match detail.operands.len() {
            1 => match detail.operands[0].size {
                // AL
                1 => get_register(x86_reg::X86_REG_AL)?.get()?,
                // AX
                2 => get_register(x86_reg::X86_REG_AX)?.get()?,
                // EAX
                4 => get_register(x86_reg::X86_REG_EAX)?.get()?,
                _ => bail!("invalid operand size for imul")
            },
            2 => operand_load(&mut block, &detail.operands[0])?,
            3 => operand_load(&mut block, &detail.operands[1])?,
            _ => bail!("invalid number of operands for imul")
        };

        // Get multiplier
        let multiplier = match detail.operands.len() {
            1 => operand_load(&mut block, &detail.operands[0])?,
            2 => {
                let multiplier = operand_load(&mut block, &detail.operands[1])?;
                if multiplier.bits() < multiplicand.bits() {
                    Expr::sext(multiplicand.bits(), multiplier)?
                }
                else {
                    multiplier
                }
            },
            3 => {
                let multiplier = operand_load(&mut block, &detail.operands[2])?;
                if multiplier.bits() < multiplicand.bits() {
                    Expr::sext(multiplicand.bits(), multiplier)?
                }
                else {
                    multiplier
                }
            }
            _ => bail!("invalid number of operands for imul")
        };

        // Perform multiplication
        let bit_width = multiplicand.bits() * 2;

        let result = block.temp(bit_width);
        block.assign(result.clone(), Expr::muls(
            Expr::zext(bit_width, multiplicand)?,
            Expr::zext(bit_width, multiplier)?
        )?);

        // Set the result
        match detail.operands.len() {
            1 => {
                match detail.operands[0].size {
                    1 => get_register(x86_reg::X86_REG_AX)?.set(&mut block, result.clone().into())?,
                    2 => {
                        let dx = get_register(x86_reg::X86_REG_DX)?;
                        let ax = get_register(x86_reg::X86_REG_AX)?;
                        let expr = Expr::shr(result.clone().into(), expr_const(16, 32))?;
                        dx.set(&mut block, Expr::trun(16, expr)?)?;
                        ax.set(&mut block, Expr::trun(16, result.clone().into())?)?;
                    },
                    4 => {
                        let edx = get_register(x86_reg::X86_REG_EDX)?;
                        let eax = get_register(x86_reg::X86_REG_EAX)?;
                        let expr = Expr::shr(result.clone().into(), expr_const(32, 64))?;
                        edx.set(&mut block, Expr::trun(32, expr)?)?;
                        eax.set(&mut block, Expr::trun(32, result.clone().into())?)?;
                    },
                    _ => bail!("Invalid operand size for imul")
                }
            },
            2 => {
                let expr = Expr::trun(bit_width / 2, result.clone().into())?;
                operand_store(&mut block, &detail.operands[0], expr)?;
            }
            3 => {
                let expr = Expr::trun(bit_width / 2, result.clone().into())?;
                operand_store(&mut block, &detail.operands[0], expr)?;
            }
            _ => bail!("invalid number of operands for imul")
        }


        // Set flags
        block.assign(var("OF", 1),
            Expr::cmpneq(
                Expr::trun(
                    bit_width / 2,
                    Expr::shr(
                        result.clone().into(),
                        expr_const((bit_width / 2) as u64, bit_width)
                    )?
                )?,
                expr_const(0, bit_width / 2)
            )?
        );
        block.assign(var("CF", 1), expr_var("OF", 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn inc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;

        let expr = Expr::add(dst.clone().into(), expr_const(1, dst.bits()))?;

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), dst.clone(), expr_const(1, dst.bits()))?;
        set_cf(&mut block, expr.clone(), dst.clone())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn jcc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // we only need to emit a brc here if the destination cannot be determined
        // at translation time
        if detail.operands[0].type_ != x86_op_type::X86_OP_IMM {
            let dst = operand_load(&mut block, &detail.operands[0])?;
            let expr = jcc_condition(&instruction)?;
            block.brc(dst, expr);
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn jmp(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // we only need to emit a brc here if the destination cannot be determined
        // at translation time
        if detail.operands[0].type_ != x86_op_type::X86_OP_IMM {
            let dst = operand_load(&mut block, &detail.operands[0])?;
            let expr = jcc_condition(&instruction)?;
            block.brc(dst, expr_const(1, 1));
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lea(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_value(&mut block, &detail.operands[1])?;

        operand_store(&mut block, &detail.operands[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn leave(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("esp", 32), expr_var("ebp", 32));
        let ebp = pop_value(&mut block)?;
        block.assign(var("ebp", 32), ebp);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn loop_(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;

        let ecx = var("ecx", 32);

        block.assign(ecx.clone(), Expr::sub(ecx.clone().into(), expr_const(1, ecx.bits()))?);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn mov(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;

        operand_store(&mut block, &detail.operands[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn movsx(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;
        let value = Expr::sext((detail.operands[0].size as usize) * 8, src)?;

        operand_store(&mut block, &detail.operands[0], value)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn movzx(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;
        let value = Expr::zext((detail.operands[0].size as usize) * 8, src)?;

        operand_store(&mut block, &detail.operands[0], value)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn mul(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let rhs = operand_load(&mut block, &detail.operands[0])?;

        let lhs = match rhs.bits() {
            8 => get_register(x86_reg::X86_REG_AL)?.get()?,
            16 => get_register(x86_reg::X86_REG_AX)?.get()?,
            32 => get_register(x86_reg::X86_REG_EAX)?.get()?,
            _ => bail!("invalid bit-width for mul")
        };

        let bit_width = rhs.bits() * 2;
        let result = block.temp(bit_width);
        let expr = Expr::mulu(Expr::zext(bit_width, lhs)?, Expr::zext(bit_width, rhs.clone())?)?;
        block.assign(result.clone(), expr);

        match rhs.bits() {
            8 => {
                let ax = get_register(x86_reg::X86_REG_AX)?;
                ax.set(&mut block, result.into())?;
                let expr = Expr::cmpeq(get_register(x86_reg::X86_REG_AH)?.get()?, expr_const(0, 8))?;
                block.assign(var("ZF", 1), expr);
                block.assign(var("CF", 1), expr_var("ZF", 1));
            },
            16 => {
                let dx = get_register(x86_reg::X86_REG_DX)?;
                let ax = get_register(x86_reg::X86_REG_AX)?;
                dx.set(&mut block, Expr::trun(16, Expr::shr(result.clone().into(), expr_const(16, 32))?)?)?;
                ax.set(&mut block, Expr::trun(16, result.into())?)?;
                block.assign(var("ZF", 1), Expr::cmpeq(dx.get()?, expr_const(0, 16))?);
                block.assign(var("CF", 1), expr_var("ZF", 1));
            },
            32 => {
                let edx = get_register(x86_reg::X86_REG_EDX)?;
                let eax = get_register(x86_reg::X86_REG_EAX)?;
                edx.set(&mut block, Expr::trun(32, Expr::shr(result.clone().into(), expr_const(32, 64))?)?)?;
                eax.set(&mut block, Expr::trun(32, result.into())?)?;
                block.assign(var("ZF", 1), Expr::cmpeq(edx.get()?, expr_const(0, 32))?);
                block.assign(var("CF", 1), expr_var("ZF", 1));
            },
            _ => bail!("invalid bit-width for mul")
        }

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn neg(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;

        let result = block.temp(dst.bits());

        block.assign(var("CF", 1), Expr::cmpneq(dst.clone().into(), expr_const(0, dst.bits()))?);
        block.assign(result.clone(), Expr::sub(expr_const(0, dst.bits()), dst.clone().into())?);

        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), expr_const(0, dst.bits()), dst.clone().into())?;

        operand_store(&mut block, &detail.operands[0], result.clone().into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn nop(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn not(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let dst = operand_load(&mut block, &detail.operands[0])?;

        let expr = Expr::xor(dst.clone(), expr_const(!0, dst.bits()))?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn or(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        let result = block.temp(lhs.bits());

        if lhs.bits() != rhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs)?;
        }

        // perform addition
        block.assign(result.clone(), Expr::or(lhs.clone(), rhs.clone())?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        block.assign(Variable::new("CF", 1), expr_const(0, 1));
        block.assign(Variable::new("OF", 1), expr_const(0, 1));

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn pop(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;
        
        let value = pop_value(&mut block)?;

        operand_store(&mut block, &detail.operands[0], value)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn push(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let value = operand_load(&mut block, &detail.operands[0])?;

        push_value(&mut block, value)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn ret(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let value = pop_value(&mut block)?;

        if detail.operands.len() == 1 {
            let imm = operand_load(&mut block, &detail.operands[0])?;
            get_register(x86_reg::X86_REG_ESP)?.set(&mut block, imm)?;
        }

        block.assign(var("eip", 32), value);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn sbb(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs)?;
        }

        let rhs = Expr::add(rhs.clone(), Expr::zext(rhs.bits(), expr_var("CF", 1))?)?;
        let expr = Expr::sub(lhs.clone(), rhs.clone())?;

        let result = block.temp(lhs.bits());
        block.assign(result.clone(), expr);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone().into(), lhs.clone())?;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn setcc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let expr = if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
            match instruction_id {
                capstone::x86_insn::X86_INS_SETAE => Expr::cmpeq(expr_var("CF", 1), expr_const(0, 1))?,
                capstone::x86_insn::X86_INS_SETA => Expr::and(
                        Expr::cmpeq(expr_var("CF", 1), expr_const(0, 1))?,
                        Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?
                    )?,
                capstone::x86_insn::X86_INS_SETBE => Expr::or(
                        Expr::cmpeq(expr_var("CF", 1), expr_const(1, 1))?,
                        Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?
                    )?,
                capstone::x86_insn::X86_INS_SETB => Expr::cmpeq(expr_var("CF", 1), expr_const(1, 1))?,
                capstone::x86_insn::X86_INS_SETE => Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?,
                capstone::x86_insn::X86_INS_SETGE => Expr::cmpeq(expr_var("SF", 1), expr_var("OF", 1))?,
                capstone::x86_insn::X86_INS_SETG => Expr::or(
                        Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?,
                        Expr::cmpeq(expr_var("SF", 1), expr_var("OF", 1))?
                    )?,
                capstone::x86_insn::X86_INS_SETLE => Expr::and(
                        Expr::cmpeq(expr_var("ZF", 1), expr_const(1, 1))?,
                        Expr::cmpneq(expr_var("SF", 1), expr_var("OF", 1))?
                    )?,
                capstone::x86_insn::X86_INS_SETL => Expr::cmpneq(expr_var("SF", 1), expr_var("OF", 1))?,
                capstone::x86_insn::X86_INS_SETNE => Expr::cmpeq(expr_var("ZF", 1), expr_const(0, 1))?,
                capstone::x86_insn::X86_INS_SETNO => Expr::cmpeq(expr_var("OF", 1), expr_const(0, 1))?,
                capstone::x86_insn::X86_INS_SETNP => Expr::cmpeq(expr_var("PF", 1), expr_const(0, 1))?,
                capstone::x86_insn::X86_INS_SETNS => Expr::cmpeq(expr_var("SF", 1), expr_const(0, 1))?,
                capstone::x86_insn::X86_INS_SETO => Expr::cmpeq(expr_var("OF", 1), expr_const(1, 1))?,
                capstone::x86_insn::X86_INS_SETP => Expr::cmpeq(expr_var("PF", 1), expr_const(1, 1))?,
                capstone::x86_insn::X86_INS_SETS => Expr::cmpeq(expr_var("SF", 1), expr_const(1, 1))?,
                _ => bail!("unhandled setcc")
            }
        }
        else {
            bail!("unhandled jcc")
        };

        operand_store(&mut block, &detail.operands[0], Expr::zext(8, expr)?)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn stc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("CF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn std(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("DF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn sti(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(var("IF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn stosd(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.store(expr_var("edi", 32), expr_var("eax", 32));

        block.index()
    };

    let inc_index = {
        let mut inc_block = control_flow_graph.new_block()?;;

        inc_block.assign(var("edi", 32), Expr::add(expr_var("edi", 32), expr_const(4, 32))?);

        inc_block.index()
    };

    let dec_index = {
        let mut dec_block = control_flow_graph.new_block()?;;

        dec_block.assign(var("edi", 32), Expr::sub(expr_var("edi", 32), expr_const(4, 32))?);

        dec_block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        block_index,
        inc_index,
        Expr::cmpeq(expr_var("DF", 1), expr_const(0, 1))?
    )?;
    control_flow_graph.conditional_edge(
        block_index,
        dec_index,
        Expr::cmpeq(expr_var("DF", 1), expr_const(1, 1))?
    )?;
    control_flow_graph.unconditional_edge(inc_index, terminating_index)?;
    control_flow_graph.unconditional_edge(dec_index, terminating_index)?;

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(terminating_index)?;

    Ok(())
}



pub fn sub(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs)?;
        }

        let result = block.temp(lhs.bits());
        block.assign(result.clone(), Expr::sub(lhs.clone(), rhs.clone())?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        set_of(&mut block, result.clone().into(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone().into(), lhs.clone())?;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn test(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let expr = Expr::and(lhs.clone(), rhs.clone())?;

        // calculate flags
        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr)?;
        block.assign(var("CF", 1), expr_const(0, 1));
        block.assign(var("OF", 1), expr_const(0, 1));;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn xchg(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let tmp = block.temp(lhs.bits());
        block.assign(tmp.clone(), lhs.clone());

        operand_store(&mut block, &detail.operands[0], rhs)?;
        operand_store(&mut block, &detail.operands[1], tmp.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn xor(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs)?;
        }

        let result = block.temp(lhs.bits());
        block.assign(result.clone(), Expr::xor(lhs.clone(), rhs.clone())?);

        // calculate flags
        set_zf(&mut block, result.clone().into())?;
        set_sf(&mut block, result.clone().into())?;
        block.assign(var("CF", 1), expr_const(0, 1));
        block.assign(var("OF", 1), expr_const(0, 1));;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}
