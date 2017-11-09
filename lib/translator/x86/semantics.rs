use falcon_capstone::capstone;
use falcon_capstone::capstone::cs_x86_op;
use falcon_capstone::capstone_sys::{x86_op_type, x86_reg};
use error::*;
use il::*;
use il::Expression as Expr;


const MEM_SIZE: u64 = (1 << 48);


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
    bits: usize,
}


impl X86Register {
    pub fn bits(&self) -> usize {
        self.bits
    }

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
            Ok(expr_scalar(self.name, self.bits))
        }
        else if self.offset == 0 {
            Expr::trun(self.bits, self.get_full()?.get()?)
        }
        else {
            let full_reg = self.get_full()?;
            let expr = Expr::shr(full_reg.get()?, expr_const(self.offset as u64, full_reg.bits))?;
            Expr::trun(self.bits, expr)
        }
    }

    /// Sets the value of this register.
    ///
    /// This handles things like al/ah/ax/eax
    pub fn set(&self, block: &mut Block, value: Expression) -> Result<()> {
        if self.is_full() {
            block.assign(scalar(self.name, self.bits), value);
            Ok(())
        }
        else if self.offset == 0 {
            let full_reg = self.get_full()?;
            let mask = !0 << self.bits;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.bits))?;
            let expr = Expr::or(expr, Expr::zext(full_reg.bits, value)?)?;
            full_reg.set(block, expr)
        }
        else {
            let full_reg = self.get_full()?;
            let mask = ((1 << self.bits) - 1) << self.offset;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.bits))?;
            let value = Expr::zext(full_reg.bits, value)?;
            let expr = Expr::or(expr, Expr::shl(value, expr_const(self.offset as u64, full_reg.bits))?)?;
            full_reg.set(block, expr)
        }
    }
}



const X86REGISTERS : &'static [X86Register] = &[
    X86Register { name: "ah", capstone_reg: x86_reg::X86_REG_AH, full_reg: x86_reg::X86_REG_EAX, offset: 8, bits: 8 },
    X86Register { name: "al", capstone_reg: x86_reg::X86_REG_AL, full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 8 },
    X86Register { name: "ax", capstone_reg: x86_reg::X86_REG_AX, full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 16 },
    X86Register { name: "eax", capstone_reg: x86_reg::X86_REG_EAX, full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 32 },
    X86Register { name: "bh", capstone_reg: x86_reg::X86_REG_BH, full_reg: x86_reg::X86_REG_EBX, offset: 8, bits: 8 },
    X86Register { name: "bl", capstone_reg: x86_reg::X86_REG_BL, full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 8 },
    X86Register { name: "bx", capstone_reg: x86_reg::X86_REG_BX, full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 16 },
    X86Register { name: "ebx", capstone_reg: x86_reg::X86_REG_EBX, full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 32 },
    X86Register { name: "ch", capstone_reg: x86_reg::X86_REG_CH, full_reg: x86_reg::X86_REG_ECX, offset: 8, bits: 8 },
    X86Register { name: "cl", capstone_reg: x86_reg::X86_REG_CL, full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 8 },
    X86Register { name: "cx", capstone_reg: x86_reg::X86_REG_CX, full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 16 },
    X86Register { name: "ecx", capstone_reg: x86_reg::X86_REG_ECX, full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 32 },
    X86Register { name: "dh", capstone_reg: x86_reg::X86_REG_DH, full_reg: x86_reg::X86_REG_EDX, offset: 8, bits: 8 },
    X86Register { name: "dl", capstone_reg: x86_reg::X86_REG_DL, full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 8 },
    X86Register { name: "dx", capstone_reg: x86_reg::X86_REG_DX, full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 16 },
    X86Register { name: "edx", capstone_reg: x86_reg::X86_REG_EDX, full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 32 },
    X86Register { name: "si", capstone_reg: x86_reg::X86_REG_SI, full_reg: x86_reg::X86_REG_ESI, offset: 0, bits: 16 },
    X86Register { name: "esi", capstone_reg: x86_reg::X86_REG_ESI, full_reg: x86_reg::X86_REG_ESI, offset: 0, bits: 32 },
    X86Register { name: "di", capstone_reg: x86_reg::X86_REG_DI, full_reg: x86_reg::X86_REG_EDI, offset: 0, bits: 16 },
    X86Register { name: "edi", capstone_reg: x86_reg::X86_REG_EDI, full_reg: x86_reg::X86_REG_EDI, offset: 0, bits: 32 },
    X86Register { name: "sp", capstone_reg: x86_reg::X86_REG_SP, full_reg: x86_reg::X86_REG_ESP, offset: 0, bits: 16 },
    X86Register { name: "esp", capstone_reg: x86_reg::X86_REG_ESP, full_reg: x86_reg::X86_REG_ESP, offset: 0, bits: 32 },
    X86Register { name: "bp", capstone_reg: x86_reg::X86_REG_BP, full_reg: x86_reg::X86_REG_EBP, offset: 0, bits: 16 },
    X86Register { name: "ebp", capstone_reg: x86_reg::X86_REG_EBP, full_reg: x86_reg::X86_REG_EBP, offset: 0, bits: 32 },
    X86Register { name: "fs", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_FS, offset: 0, bits: 16 },
    X86Register { name: "gs", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_GS, offset: 0, bits: 16 },
    X86Register { name: "ds", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_DS, offset: 0, bits: 16 },
    X86Register { name: "es", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_ES, offset: 0, bits: 16 },
    X86Register { name: "cs", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_CS, offset: 0, bits: 16 },
    X86Register { name: "ss", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_SS, offset: 0, bits: 16 },
];


/// Takes a capstone register enum and returns an `X86Register`
pub fn get_register(capstone_id: x86_reg) -> Result<&'static X86Register> {
    for register in X86REGISTERS.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(&register);
        }
    }
    Err("Could not find register".into())
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
pub fn operand_value(operand: &cs_x86_op) -> Result<Expression> {
    match operand.type_ {
        x86_op_type::X86_OP_INVALID => Err("Invalid operand".into()),
        x86_op_type::X86_OP_REG => {
            // Get the register value
            get_register(operand.reg())?.get()
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
                Some(index) => Some(Expr::mul(index, scale).unwrap()),
                None => None
            };

            // Handle base and scale/index
            let op : Option<Expression> = if base.is_some() {
                if si.is_some() {
                    Some(Expr::add(base.unwrap(), si.unwrap()).unwrap())
                }
                else {
                    base
                }
            }
            else if si.is_some() {
                si
            }
            else {
                None
            };

            // handle disp
            let op = if op.is_some() {
                if mem.disp > 0 {
                    Expr::add(op.unwrap(), expr_const(mem.disp as u64, 32))?
                }
                else if mem.disp < 0 {
                    Expr::sub(op.unwrap(), expr_const(mem.disp.abs() as u64, 32))?
                }
                else {
                    op.unwrap()
                }
            }
            else {
                expr_const(mem.disp as u64, 32)
            };

            match x86_reg::from(mem.segment) {
                x86_reg::X86_REG_INVALID =>
                    Ok(op),
                x86_reg::X86_REG_CS => 
                    Ok(Expr::add(expr_scalar("cs_base", 32), op)?),
                x86_reg::X86_REG_DS => 
                    Ok(Expr::add(expr_scalar("ds_base", 32), op)?),
                x86_reg::X86_REG_ES => 
                    Ok(Expr::add(expr_scalar("es_base", 32), op)?),
                x86_reg::X86_REG_FS => 
                    Ok(Expr::add(expr_scalar("fs_base", 32), op)?),
                x86_reg::X86_REG_GS => 
                    Ok(Expr::add(expr_scalar("gs_base", 32), op)?),
                x86_reg::X86_REG_SS => 
                    Ok(Expr::add(expr_scalar("ss_base", 32), op)?),
                _ => bail!("invalid segment register")
            }
        },
        x86_op_type::X86_OP_IMM => {
            Ok(expr_const(operand.imm() as u64, operand.size as usize * 8))
        }
        x86_op_type::X86_OP_FP => Err("Unhandled operand".into()),
    }
}


/// Gets the value of an operand as an IL expression, performing any required loads as needed.
pub fn operand_load(block: &mut Block, operand: &cs_x86_op) -> Result<Expression> {
    let op = try!(operand_value(operand));

    if operand.type_ == x86_op_type::X86_OP_MEM {
        let temp = block.temp(operand.size as usize * 8);
        block.load(temp.clone(), op, array("mem", MEM_SIZE));
        return Ok(temp.into());
    }
    Ok(op)
}


/// Stores a value in an operand, performing any stores as necessary.
pub fn operand_store(mut block: &mut Block, operand: &cs_x86_op, value: Expression) -> Result<()> {
    match operand.type_ {
        x86_op_type::X86_OP_INVALID => Err("operand_store called on invalid operand".into()),
        x86_op_type::X86_OP_IMM => Err("operand_store called on immediate operand".into()),
        x86_op_type::X86_OP_REG => {
            let dst_register = get_register(operand.reg())?;
            dst_register.set(&mut block, value)
        },
        x86_op_type::X86_OP_MEM => {
            let address = operand_value(operand)?;
            block.store(array("mem", MEM_SIZE), address, value);
            Ok(())
        },
        x86_op_type::X86_OP_FP => {
            Err("operand_store called on fp operand".into())
        }
    }
}


/// Convenience function to pop a value off the stack
pub fn pop_value(block: &mut Block, bits: usize) -> Result<Expression> {
    let temp = block.temp(bits);

    block.load(temp.clone(), expr_scalar("esp", 32), array("mem", MEM_SIZE));
    block.assign(scalar("esp", 32), Expr::add(expr_scalar("esp", 32), expr_const(bits as u64 / 8, 32))?);

    Ok(temp.into())
}


/// Convenience function to push a value onto the stack
pub fn push_value(block: &mut Block, value: Expression) -> Result<()> {
    block.assign(scalar("esp", 32), Expr::sub(expr_scalar("esp", 32), expr_const(4, 32))?);
    block.store(array("mem", MEM_SIZE), expr_scalar("esp", 32), value);
    Ok(())
}


/// Convenience function set set the zf based on result
pub fn set_zf(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::cmpeq(result.clone(), expr_const(0, result.bits()))?;
    block.assign(scalar("ZF", 1), expr);
    Ok(())
}


/// Convenience function to set the sf based on result
pub fn set_sf(block: &mut Block, result: Expression) -> Result<()> {
    let expr = Expr::shr(result.clone(), expr_const((result.bits() - 1) as u64, result.bits()))?;
    let expr = Expr::trun(1, expr)?;
    block.assign(scalar("SF", 1), expr);
    Ok(())
}


/// Convenience function to set the of based on result and both operands
pub fn set_of(block: &mut Block, result: Expression, lhs: Expression, rhs: Expression) -> Result<()> {
    let expr0 = Expr::xor(lhs.clone().into(), rhs.clone().into())?;
    let expr1 = Expr::xor(lhs.clone().into(), result.clone().into())?;
    let expr = Expr::and(expr0, expr1)?;
    let expr = Expr::shr(expr.clone(), expr_const((expr.bits() - 1) as u64, expr.bits()))?;
    block.assign(scalar("OF", 1), Expr::trun(1, expr)?);
    Ok(())
}


/// Convenience function to set the cf based on result and lhs operand
pub fn set_cf(block: &mut Block, result: Expression, lhs: Expression) -> Result<()> {
    let expr = Expr::cmpltu(lhs.clone().into(), result.clone().into())?;
    block.assign(scalar("CF", 1), expr);
    Ok(())
}


/// Returns a condition which is true if a conditional instruction should be
/// executed. Used for setcc, jcc and cmovcc.
pub fn cc_condition(instruction: &capstone::Instr) -> Result<Expression> {
    if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_CMOVA |
            capstone::x86_insn::X86_INS_JA |
            capstone::x86_insn::X86_INS_SETA => {
                let cf = Expr::cmpeq(expr_scalar("CF", 1), expr_const(0, 1))?;
                let zf = Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1))?;
                Expr::and(cf, zf)
            },
            capstone::x86_insn::X86_INS_CMOVAE |
            capstone::x86_insn::X86_INS_JAE |
            capstone::x86_insn::X86_INS_SETAE =>
                Expr::cmpeq(expr_scalar("CF", 1), expr_const(0, 1)),
            capstone::x86_insn::X86_INS_CMOVB |
            capstone::x86_insn::X86_INS_JB |
            capstone::x86_insn::X86_INS_SETB =>
                Expr::cmpeq(expr_scalar("CF", 1), expr_const(1, 1)),
            capstone::x86_insn::X86_INS_CMOVBE |
            capstone::x86_insn::X86_INS_JBE |
            capstone::x86_insn::X86_INS_SETBE => {
                let cf = Expr::cmpeq(expr_scalar("CF", 1), expr_const(1, 1))?;
                let zf = Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1))?;
                Expr::or(cf, zf)
            },
            capstone::x86_insn::X86_INS_JCXZ => {
                let cx = get_register(x86_reg::X86_REG_CX)?.get()?;
                Expr::cmpeq(cx, expr_const(0, 16))
            },
            capstone::x86_insn::X86_INS_JECXZ => {
                let cx = get_register(x86_reg::X86_REG_ECX)?.get()?;
                Expr::cmpeq(cx, expr_const(0, 32))
            },
            capstone::x86_insn::X86_INS_CMOVE |
            capstone::x86_insn::X86_INS_JE |
            capstone::x86_insn::X86_INS_SETE =>
                Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1)),
            capstone::x86_insn::X86_INS_CMOVG |
            capstone::x86_insn::X86_INS_JG |
            capstone::x86_insn::X86_INS_SETG => {
                let sfof = Expr::cmpeq(expr_scalar("SF", 1), expr_scalar("OF", 1))?;
                let zf = Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1))?;
                Expr::and(sfof, zf)
            },
            capstone::x86_insn::X86_INS_CMOVGE |
            capstone::x86_insn::X86_INS_JGE |
            capstone::x86_insn::X86_INS_SETGE =>
                Expr::cmpeq(expr_scalar("SF", 1), expr_scalar("OF", 1)),
            capstone::x86_insn::X86_INS_CMOVL |
            capstone::x86_insn::X86_INS_JL |
            capstone::x86_insn::X86_INS_SETL =>
                Expr::cmpneq(expr_scalar("SF", 1), expr_scalar("OF", 1)),
            capstone::x86_insn::X86_INS_CMOVLE |
            capstone::x86_insn::X86_INS_JLE |
            capstone::x86_insn::X86_INS_SETLE => {
                let sfof = Expr::cmpneq(expr_scalar("SF", 1), expr_scalar("OF", 1))?;
                let zf = Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1))?;
                Expr::and(sfof, zf)
            },
            capstone::x86_insn::X86_INS_CMOVNE |
            capstone::x86_insn::X86_INS_JNE |
            capstone::x86_insn::X86_INS_SETNE =>
                Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1)),
            capstone::x86_insn::X86_INS_CMOVNO |
            capstone::x86_insn::X86_INS_JNO |
            capstone::x86_insn::X86_INS_SETNO =>
                Expr::cmpeq(expr_scalar("OF", 1), expr_const(0, 1)),
            capstone::x86_insn::X86_INS_CMOVNP |
            capstone::x86_insn::X86_INS_JNP |
            capstone::x86_insn::X86_INS_SETNP =>
                Expr::cmpeq(expr_scalar("PF", 1), expr_const(0, 1)),
            capstone::x86_insn::X86_INS_CMOVNS |
            capstone::x86_insn::X86_INS_JNS |
            capstone::x86_insn::X86_INS_SETNS =>
                Expr::cmpeq(expr_scalar("SF", 1), expr_const(0, 1)),
            capstone::x86_insn::X86_INS_CMOVO |
            capstone::x86_insn::X86_INS_JO |
            capstone::x86_insn::X86_INS_SETO  =>
                Expr::cmpeq(expr_scalar("OF", 1), expr_const(1, 1)),
            capstone::x86_insn::X86_INS_CMOVP |
            capstone::x86_insn::X86_INS_JP |
            capstone::x86_insn::X86_INS_SETP  =>
                Expr::cmpeq(expr_scalar("PF", 1), expr_const(1, 1)),
            capstone::x86_insn::X86_INS_CMOVS |
            capstone::x86_insn::X86_INS_JS |
            capstone::x86_insn::X86_INS_SETS  =>
                Expr::cmpeq(expr_scalar("SF", 1), expr_const(1, 1)),
            _ => bail!("unhandled jcc")
        }
    }
    else {
        bail!("not an x86 instruction")
    }
}


/// Returns a condition which is true if a loop should be taken
pub fn loop_condition(instruction: &capstone::Instr) -> Result<Expression> {
    let ecx = scalar("ecx", 32);

    if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
        match instruction_id {
            capstone::x86_insn::X86_INS_LOOP =>
                Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits())),
            capstone::x86_insn::X86_INS_LOOPE => {
                let expr = Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits()))?;
                Expr::and(expr, Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1))?)
            }
            capstone::x86_insn::X86_INS_LOOPNE => {
                let expr = Expr::cmpneq(ecx.clone().into(), expr_const(0, ecx.bits()))?;
                Expr::and(expr, Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1))?)
            }
            _ => bail!("unhandled loop")
        }
    }
    else {
        bail!("not an x86 instruction")
    }
}


/// Wraps the given instruction graph with the rep prefix inplace
pub fn rep_prefix(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr
) -> Result<()> {

    if control_flow_graph.entry().is_none() || control_flow_graph.exit().is_none() {
        bail!("control_flow_graph entry/exit was none");
    }

    let head_index = control_flow_graph.new_block()?.index();

    let loop_index = {
        let loop_block = control_flow_graph.new_block()?;
        loop_block.assign(
            scalar("ecx", 32),
            Expr::sub(expr_scalar("ecx", 32), expr_const(1, 32))?
        );
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
        Expr::cmpneq(expr_scalar("ecx", 32), expr_const(0, 32))?
    )?;
    control_flow_graph.conditional_edge(
        head_index,
        terminating_index,
        Expr::cmpeq(expr_scalar("ecx", 32), expr_const(0, 32))?
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
                    Expr::cmpneq(expr_scalar("ZF", 1), expr_const(0, 1))?
                )?;
                // loop -> terminating
                control_flow_graph.conditional_edge(
                    loop_index,
                    terminating_index,
                    Expr::cmpneq(expr_scalar("ZF", 1), expr_const(1, 1))?
                )?;
            },
            capstone::x86_insn::X86_INS_STOSB |
            capstone::x86_insn::X86_INS_STOSW |
            capstone::x86_insn::X86_INS_STOSD |
            capstone::x86_insn::X86_INS_MOVSB |
            capstone::x86_insn::X86_INS_MOVSW |
            capstone::x86_insn::X86_INS_MOVSD => {
                // loop -> head
                control_flow_graph.unconditional_edge(loop_index, head_index)?;
            },
            _ => bail!("unsupported instruction for rep prefix, 0x{:x}", instruction.address)
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

        let result = block.temp(lhs.bits());

        // perform addition
        let addition = Expr::add(lhs.clone(), rhs.clone())?;
        let zext_cf = Expr::zext(lhs.bits(), expr_scalar("CF", 1))?;
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
        block.assign(scalar("CF", 1), expr_const(0, 1));
        block.assign(scalar("OF", 1), expr_const(0, 1));

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn bswap(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let src = operand_load(&mut block, &detail.operands[0])?;

        if src.bits() != 32 {
            bail!("Invalid bit-width for bswap arg {} at 0x{:x}", src, instruction.address);
        }

        let expr = Expr::or(
            Expr::or(
                Expr::and(Expr::shl(src.clone(), expr_const(24, 32))?, expr_const(0xff00_0000, 32))?,
                Expr::and(Expr::shl(src.clone(), expr_const(8, 32))?, expr_const(0x00ff_0000, 32))?
            )?,
            Expr::or(
                Expr::and(Expr::shr(src.clone(), expr_const(8, 32))?, expr_const(0x0000_ff00, 32))?,
                Expr::and(Expr::shr(src, expr_const(24, 32))?, expr_const(0x0000_00ff, 32))?
            )?
        )?;

        operand_store(&mut block, &detail.operands[0], expr)?;

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
    let (head_index, rhs, counter) = {
        let (head_index, rhs) = {
            let mut head_block = control_flow_graph.new_block()?;

            // get started
            let rhs = operand_load(&mut head_block, &detail.operands[1])?;

            (head_block.index(), rhs)
        };

        let counter = {
            control_flow_graph.temp(rhs.bits())
        };

        let head_block = control_flow_graph.block_mut(head_index)
                                               .ok_or("Could not find block")?;

        // This is the loop preamble, and we'll always execute it
        head_block.assign(scalar("ZF", 1), expr_const(0, 1));
        head_block.assign(counter.clone(), expr_const(0, rhs.bits()));

        (head_index, rhs, counter)
    };

    // if rhs == 0 then ZF = 1 and we are done.
    let zero_index = {
        let zero_block = control_flow_graph.new_block()?;
        zero_block.assign(scalar("ZF", 1), expr_const(1, 1));

        zero_block.index()
    };

    // The loop body checks if the bits for our counter is set.
    let (bitfield, loop_index) = {
        let bitfield = control_flow_graph.temp(rhs.bits());

        let loop_block = control_flow_graph.new_block()?;
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
        let iterate_block = control_flow_graph.new_block()?;

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

    let (head_index, rhs, counter) = {
        let (head_index, rhs) = {
            let mut head_block = control_flow_graph.new_block()?;

            // get started
            let rhs = operand_load(&mut head_block, &detail.operands[1])?;

            (head_block.index(), rhs)
        };

        let counter = {
            control_flow_graph.temp(rhs.bits())
        };

        let head_block = control_flow_graph.block_mut(head_index)
                                               .ok_or("Could not find block")?;

        // This is the loop preamble, and we'll always execute it
        head_block.assign(scalar("ZF", 1), expr_const(0, 1));
        head_block.assign(counter.clone(), expr_const((rhs.bits() - 1) as u64, rhs.bits()));

        (head_index, rhs, counter)
    };


    // if rhs == 0 then ZF = 1 and we are done.
    let zero_index = {
        let zero_block = control_flow_graph.new_block()?;
        zero_block.assign(scalar("ZF", 1), expr_const(1, 1));

        zero_block.index()
    };

    // The loop body checks if the bits for our counter is set
    let (bitfield, loop_index) = {
        let bitfield = control_flow_graph.temp(rhs.bits());

        let loop_block = control_flow_graph.new_block()?;
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
        let iterate_block = control_flow_graph.new_block()?;

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
        block.assign(scalar("CF", 1), Expr::trun(1, temp.into())?);

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
        block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

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
        block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

        let expr = Expr::shl(expr_const(1, base.bits()), offset.into())?;
        let expr = Expr::xor(expr, expr_const(0xffff_ffff_ffff_ffff, base.bits()))?;
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
        block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

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

        let ret_addr = instruction.address + instruction.size as u64;

        push_value(&mut block, expr_const(ret_addr, 32))?;

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



pub fn cdq(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // isolate the sign bits of ax
        let expr = Expr::shr(expr_scalar("eax", 32), expr_const(31, 32))?;
        let expr = Expr::trun(1, expr)?;
        let expr = Expr::sext(32, expr)?;

        block.assign(scalar("edx", 32), expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn clc(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("CF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cld(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("DF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cli(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("IF", 1), expr_const(0, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cmc(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        let expr = Expr::xor(expr_scalar("CF", 1), expr_const(1, 1))?;
        block.assign(scalar("CF", 1), expr);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cmovcc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let head_index = {
        let block = control_flow_graph.new_block()?;

        block.index()
    };

    let tail_index = {
        let block = control_flow_graph.new_block()?;

        block.index()
    };

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;

        operand_store(&mut block, &detail.operands[0], src)?;

        block.index()
    };

    let condition = cc_condition(&instruction)?;

    control_flow_graph.conditional_edge(head_index, block_index, condition.clone())?;
    control_flow_graph.conditional_edge(
        head_index,
        tail_index,
        Expr::cmpeq(condition, expr_const(0, 1))?
    )?;
    control_flow_graph.unconditional_edge(block_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}



pub fn cmp(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if rhs.bits() != lhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs.into())?;
        }

        let expr = Expr::sub(lhs.clone(), rhs.clone())?;

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, expr.clone(), lhs.clone())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn cmpsb(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));


    let head_index = {
        let mut block = control_flow_graph.new_block()?;

        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if rhs.bits() != lhs.bits() {
            rhs = Expr::sext(lhs.bits(), rhs.into())?;
        }

        let expr = Expr::sub(lhs.clone(), rhs.clone())?;

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, expr.clone(), lhs.clone())?;

        block.index()
    };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::add(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.assign(
            scalar("edi", 32),
            Expr::add(expr_scalar("edi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let dec_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::sub(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.assign(
            scalar("edi", 32),
            Expr::sub(expr_scalar("edi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let tail_index = {
        control_flow_graph.new_block()?.index()
    };


    control_flow_graph.conditional_edge(
        head_index,
        inc_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        dec_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
    )?;

    control_flow_graph.unconditional_edge(inc_index, tail_index)?;
    control_flow_graph.unconditional_edge(dec_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}



pub fn cmpxchg(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let (head_index, dest, lhs, rhs) = {
        let mut block = control_flow_graph.new_block()?;

        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let dest = match rhs.bits() {
            8 => get_register(x86_reg::X86_REG_AL)?,
            16 => get_register(x86_reg::X86_REG_AX)?,
            32 => get_register(x86_reg::X86_REG_EAX)?,
            _ => bail!("can't figure out dest for xmpxchg, rhs.bits()={}", rhs.bits())
        };

        (block.index(), dest, lhs, rhs)
    };

    let taken_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("ZF", 1), expr_const(1, 1));
        operand_store(&mut block, &detail.operands[0], rhs.clone())?;

        block.index()
    };

    let not_taken_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("ZF", 1), expr_const(0, 1));
        dest.set(&mut block, lhs.clone())?;

        block.index()
    };

    let tail_index = {
        let mut block = control_flow_graph.new_block()?;

        let result = Expr::sub(lhs.clone(), rhs.clone())?;
        set_sf(&mut block, result.clone())?;
        set_of(&mut block, result.clone(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, result.clone(), lhs.clone())?;

        block.index()
    };

    let condition = Expr::cmpeq(dest.get()?, lhs.clone())?;

    control_flow_graph.conditional_edge(head_index, taken_index, condition.clone())?;
    control_flow_graph.conditional_edge(
        head_index,
        not_taken_index,
        Expr::cmpeq(condition.clone(), expr_const(0, 1))?
    )?;
    control_flow_graph.unconditional_edge(taken_index, tail_index)?;
    control_flow_graph.unconditional_edge(not_taken_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}



pub fn cwd(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // isolate the sign bits of ax
        let expr = Expr::shr(expr_scalar("ax", 16), expr_const(15, 16))?;
        let expr = Expr::trun(1, expr)?;
        let expr = Expr::sext(16, expr)?;

        block.assign(scalar("dx", 16), expr);

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
                Expr::or(expr_dx, Expr::zext(32, get_register(x86_reg::X86_REG_AX)?.get()?)?)?
            },
            64 => {
                let expr_edx = Expr::zext(64, get_register(x86_reg::X86_REG_EDX)?.get()?)?;
                let expr_edx = Expr::shl(expr_edx, expr_const(32, 64))?;
                Expr::or(expr_edx, Expr::zext(64, get_register(x86_reg::X86_REG_EAX)?.get()?)?)?
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
                Expr::or(expr_dx, Expr::zext(32, get_register(x86_reg::X86_REG_AX)?.get()?)?)?
            },
            64 => {
                let expr_edx = Expr::zext(64, get_register(x86_reg::X86_REG_EDX)?.get()?)?;
                let expr_edx = Expr::shl(expr_edx, expr_const(32, 64))?;
                Expr::or(expr_edx, Expr::zext(64, get_register(x86_reg::X86_REG_EAX)?.get()?)?)?
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
        let multiplicand = match detail.op_count {
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
            _ => bail!("invalid number of operands for imul {} at 0x{:x}",
                    detail.op_count,
                    instruction.address)
        };

        // Get multiplier
        let multiplier = match detail.op_count {
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
        block.assign(result.clone(), Expr::mul(
            Expr::zext(bit_width, multiplicand)?,
            Expr::zext(bit_width, multiplier)?
        )?);

        // Set the result
        match detail.op_count {
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
        block.assign(scalar("OF", 1),
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
        block.assign(scalar("CF", 1), expr_scalar("OF", 1));

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



pub fn int(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let expr = operand_load(&mut block, &detail.operands[0])?;

        block.raise(expr);

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
            let expr = cc_condition(&instruction)?;
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

        let src = operand_value(&detail.operands[1])?;

        operand_store(&mut block, &detail.operands[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn leave(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(scalar("esp", 32), expr_scalar("ebp", 32));
        let ebp = pop_value(&mut block, 32)?;
        block.assign(scalar("ebp", 32), ebp);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn lodsb(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let head_index = {
        let mut block = control_flow_graph.new_block()?;

        let rhs = operand_load(&mut block, &detail.operands[1])?;

        get_register(x86_reg::X86_REG_AL)?.set(&mut block, rhs)?;

        block.index()
    };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::add(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let dec_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::sub(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let tail_index = {
        control_flow_graph.new_block()?.index()
    };


    control_flow_graph.conditional_edge(
        head_index,
        inc_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        dec_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
    )?;

    control_flow_graph.unconditional_edge(inc_index, tail_index)?;
    control_flow_graph.unconditional_edge(dec_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

    Ok(())
}



pub fn loop_(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        let ecx = scalar("ecx", 32);

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



pub fn movs(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let head_index = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;

        operand_store(&mut block, &detail.operands[0], src.clone())?;

        block.assign(
            scalar("esi", 32),
            Expr::add(expr_scalar("esi", 32), expr_const((src.bits() / 8) as u64, 32))?
        );
        block.assign(
            scalar("edi", 32),
            Expr::add(expr_scalar("edi", 32), expr_const((src.bits() / 8) as u64, 32))?
        );

        block.index()
    };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::add(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let dec_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("esi", 32),
            Expr::sub(expr_scalar("esi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let tail_index = {
        control_flow_graph.new_block()?.index()
    };


    control_flow_graph.conditional_edge(
        head_index,
        inc_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        dec_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
    )?;

    control_flow_graph.unconditional_edge(inc_index, tail_index)?;
    control_flow_graph.unconditional_edge(dec_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;

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
        let expr = Expr::mul(Expr::zext(bit_width, lhs)?, Expr::zext(bit_width, rhs.clone())?)?;
        block.assign(result.clone(), expr);

        match rhs.bits() {
            8 => {
                let ax = get_register(x86_reg::X86_REG_AX)?;
                ax.set(&mut block, result.into())?;
                let expr = Expr::cmpeq(get_register(x86_reg::X86_REG_AH)?.get()?, expr_const(0, 8))?;
                block.assign(scalar("ZF", 1), expr);
                block.assign(scalar("CF", 1), expr_scalar("ZF", 1));
            },
            16 => {
                let dx = get_register(x86_reg::X86_REG_DX)?;
                let ax = get_register(x86_reg::X86_REG_AX)?;
                dx.set(&mut block, Expr::trun(16, Expr::shr(result.clone().into(), expr_const(16, 32))?)?)?;
                ax.set(&mut block, Expr::trun(16, result.into())?)?;
                block.assign(scalar("ZF", 1), Expr::cmpeq(dx.get()?, expr_const(0, 16))?);
                block.assign(scalar("CF", 1), expr_scalar("ZF", 1));
            },
            32 => {
                let edx = get_register(x86_reg::X86_REG_EDX)?;
                let eax = get_register(x86_reg::X86_REG_EAX)?;
                edx.set(&mut block, Expr::trun(32, Expr::shr(result.clone().into(), expr_const(32, 64))?)?)?;
                eax.set(&mut block, Expr::trun(32, result.into())?)?;
                block.assign(scalar("ZF", 1), Expr::cmpeq(edx.get()?, expr_const(0, 32))?);
                block.assign(scalar("CF", 1), expr_scalar("ZF", 1));
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

        block.assign(scalar("CF", 1), Expr::cmpneq(dst.clone().into(), expr_const(0, dst.bits()))?);
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



pub fn nop(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
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
        block.assign(scalar("CF", 1), expr_const(0, 1));
        block.assign(scalar("OF", 1), expr_const(0, 1));

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

        let value = match detail.operands[0].type_ {
            x86_op_type::X86_OP_MEM => pop_value(&mut block, detail.operands[0].size as usize * 8)?,
            x86_op_type::X86_OP_REG => 
                pop_value(&mut block, get_register(detail.operands[0].reg())?.bits())?,
            _ => bail!("invalid op type for `pop` instruction")
        };

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

        let value = pop_value(&mut block, 32)?;

        if detail.op_count == 1 {
            let imm = operand_load(&mut block, &detail.operands[0])?;
            block.assign(scalar("esp", 32), Expr::add(expr_scalar("esp", 32), imm)?);
        }

        block.brc(value, expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn rol(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let count = operand_load(&mut block, &detail.operands[1])?;

        let mut count = Expr::and(count.clone(), expr_const(0x1f, count.bits()))?;

        if count.bits() < lhs.bits() {
            count = Expr::zext(lhs.bits(), count)?;
        }

        let shift_left_bits = count;
        let shift_right_bits = Expr::sub(
            expr_const(lhs.bits() as u64, lhs.bits()),
            shift_left_bits.clone()
        )?;

        let result = Expr::or(
            Expr::shl(lhs.clone(), shift_left_bits.clone())?,
            Expr::shr(lhs.clone(), shift_right_bits.clone())?
        )?;

        // CF is the bit sent from one end to the other. In our case, it should be LSB of result
        block.assign(scalar("CF", 1), Expr::shr(
            result.clone(),
            expr_const(result.bits() as u64 - 1, result.bits())
        )?);

        // OF is XOR of two most-significant bits of result
        block.assign(scalar("OF", 1), Expr::xor(
            Expr::trun(1, Expr::shr(result.clone(), expr_const(result.bits() as u64 - 1, result.bits()))?)?,
            Expr::trun(1, Expr::shr(result.clone(), expr_const(result.bits() as u64 - 2, result.bits()))?)?
        )?);

        // SF/ZF are unaffected

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn ror(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let count = operand_load(&mut block, &detail.operands[1])?;

        let mut count = Expr::and(count.clone(), expr_const(0x1f, count.bits()))?;

        if count.bits() < lhs.bits() {
            count = Expr::zext(lhs.bits(), count)?;
        }

        let shift_right_bits = count;
        let shift_left_bits = Expr::sub(
            expr_const(lhs.bits() as u64, lhs.bits()),
            shift_right_bits.clone()
        )?;

        let result = Expr::or(
            Expr::shl(lhs.clone(), shift_left_bits.clone())?,
            Expr::shr(lhs.clone(), shift_right_bits.clone())?
        )?;

        // CF is the bit sent from one end to the other. In our case, it should be MSB of result
        block.assign(scalar("CF", 1), Expr::shr(
            result.clone(),
            expr_const(result.bits() as u64 - 1, result.bits())
        )?);

        // OF is XOR of two most-significant bits of result
        block.assign(scalar("OF", 1), Expr::xor(
            Expr::trun(1, Expr::shr(result.clone(), expr_const(result.bits() as u64 - 1, result.bits()))?)?,
            Expr::trun(1, Expr::shr(result.clone(), expr_const(result.bits() as u64 - 2, result.bits()))?)?
        )?);

        // SF/ZF are unaffected

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn sar(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::zext(lhs.bits(), rhs)?;
        }

        // Create the mask we apply if that lhs is signed
        let mask = Expr::shl(expr_const(1, lhs.bits()), rhs.clone())?;
        let mask = Expr::sub(mask, expr_const(1, lhs.bits()))?;
        let mask = Expr::shl(mask, Expr::sub(
            expr_const(lhs.bits() as u64, lhs.bits()),
            rhs.clone())?
        )?;

        // Multiple the mask by the sign bit
        let expr = Expr::shr(lhs.clone(), expr_const(lhs.bits() as u64 - 1, lhs.bits()))?;
        let expr = Expr::mul(mask, expr)?;

        // Do the SAR
        let expr = Expr::or(expr, Expr::shr(lhs.clone(), rhs.clone())?)?;

        let temp = block.temp(lhs.bits());

        block.assign(temp.clone(), expr);

        // OF is the last bit shifted out
        block.assign(scalar("OF", 1), expr_const(0, lhs.bits()));

        set_zf(&mut block, temp.clone().into())?;
        set_sf(&mut block, temp.clone().into())?;
        set_cf(&mut block, temp.clone().into(), lhs.clone())?;

        operand_store(&mut block, &detail.operands[0], temp.into())?;

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

        let rhs = Expr::add(rhs.clone(), Expr::zext(rhs.bits(), expr_scalar("CF", 1))?)?;

        let expr = Expr::sub(lhs.clone(), rhs.clone())?;

        // calculate flags
        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, expr.clone(), lhs.clone())?;

        // store result
        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn scasb(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let head_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;

        let expr = Expr::sub(lhs.clone(), rhs.clone())?;

        // calculate flags
        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;
        set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
        set_cf(&mut block, expr.clone(), lhs.clone())?;

        block.index()
    };

    let inc_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("edi", 32),
            Expr::add(expr_scalar("edi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let dec_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(
            scalar("edi", 32),
            Expr::sub(expr_scalar("edi", 32), expr_const(1, 32))?
        );

        block.index()
    };

    let tail_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        head_index,
        inc_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
    )?;

    control_flow_graph.conditional_edge(
        head_index,
        dec_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
    )?;

    control_flow_graph.unconditional_edge(inc_index, tail_index)?;
    control_flow_graph.unconditional_edge(dec_index, tail_index)?;

    control_flow_graph.set_entry(head_index)?;
    control_flow_graph.set_exit(tail_index)?;


    Ok(())
}



pub fn setcc(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        let expr = cc_condition(instruction)?;

        operand_store(&mut block, &detail.operands[0], Expr::zext(8, expr)?)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn shl(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::zext(lhs.bits(), rhs)?;
        }

        // Do the SHL
        let expr = Expr::shl(lhs.clone(), rhs.clone())?;

        // CF is the last bit shifted out
        // This will give us a bit mask if rhs is not equal to zero
        let non_zero_mask = Expr::sub(
            expr_const(0, rhs.bits()),
            Expr::zext(rhs.bits(), Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?)?
        )?;
        // This shifts lhs left by (rhs - 1)
        let cf = Expr::shl(lhs.clone(), Expr::sub(rhs.clone(), expr_const(1, rhs.bits()))?)?;
        // Apply mask
        let cf = Expr::trun(1, Expr::and(cf, non_zero_mask)?)?;
        block.assign(scalar("CF", 1), cf.clone());

        // OF is set if most significant bit of result is equal to OF
        let of = Expr::cmpeq(
            cf,
            Expr::trun(
                1,
                Expr::shr(
                    expr.clone(),
                    expr_const(expr.bits() as u64 - 1, expr.bits())
                )?
            )?
        )?;
        block.assign(scalar("OF", 1), of);

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn shr(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let lhs = operand_load(&mut block, &detail.operands[0])?;
        let mut rhs = operand_load(&mut block, &detail.operands[1])?;

        if lhs.bits() != rhs.bits() {
            rhs = Expr::zext(lhs.bits(), rhs)?;
        }

        // Do the SHR
        let expr = Expr::shr(lhs.clone(), rhs.clone())?;

        // CF is the last bit shifted out
        // This will give us a bit mask if rhs is not equal to zero
        let non_zero_mask = Expr::sub(
            expr_const(0, rhs.bits()),
            Expr::zext(rhs.bits(), Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?)?
        )?;
        // This shifts lhs right by (rhs - 1)
        let cf = Expr::shr(lhs.clone(), Expr::sub(rhs.clone(), expr_const(1, rhs.bits()))?)?;
        // Apply mask
        let cf = Expr::trun(1, Expr::and(cf, non_zero_mask)?)?;
        block.assign(scalar("CF", 1), cf);

        // OF set to most significant bit of the original operand
        block.assign(scalar("OF", 1), Expr::trun(
            1,
            Expr::shr(lhs.clone(), expr_const(lhs.bits() as u64 - 1, lhs.bits()))?
        )?);

        set_zf(&mut block, expr.clone())?;
        set_sf(&mut block, expr.clone())?;

        operand_store(&mut block, &detail.operands[0], expr)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn shld(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;
        let count = operand_load(&mut block, &detail.operands[2])?;

        let tmp = Expr::or(
            Expr::shl(Expr::zext(dst.bits() * 2, dst.clone())?, expr_const(dst.bits() as u64, dst.bits() * 2))?,
            Expr::zext(dst.bits() * 2, rhs)?
        )?;

        let result = Expr::shl(tmp.clone(), Expr::zext(tmp.bits(), count.clone())?)?;

        let cf = Expr::trun(
            1,
            Expr::shl(
                tmp.clone(),
                Expr::zext(
                    tmp.bits(),
                    Expr::sub(count.clone(), expr_const(1, count.bits()))?
                )?
            )?
        )?;

        block.assign(scalar("CF", 1), cf);

        set_zf(&mut block, result.clone())?;
        set_sf(&mut block, result.clone())?;

        operand_store(&mut block, &detail.operands[0], Expr::trun(dst.bits(), result)?)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn shrd(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        // get operands
        let dst = operand_load(&mut block, &detail.operands[0])?;
        let rhs = operand_load(&mut block, &detail.operands[1])?;
        let count = operand_load(&mut block, &detail.operands[2])?;

        let tmp = Expr::or(
            Expr::zext(dst.bits() * 2, dst.clone())?,
            Expr::shl(Expr::zext(dst.bits() * 2, rhs)?, expr_const(dst.bits() as u64, dst.bits() * 2))?
        )?;

        let result = Expr::shr(tmp.clone(), Expr::zext(tmp.bits(), count.clone())?)?;

        let cf = Expr::trun(
            1,
            Expr::shr(
                tmp.clone(),
                Expr::zext(
                    tmp.bits(),
                    Expr::sub(count.clone(), expr_const(1, count.bits()))?
                )?
            )?
        )?;

        block.assign(scalar("CF", 1), cf);

        set_zf(&mut block, result.clone())?;
        set_sf(&mut block, result.clone())?;

        operand_store(&mut block, &detail.operands[0], Expr::trun(dst.bits(), result)?)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn stc(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("CF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn std(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("DF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn sti(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.assign(scalar("IF", 1), expr_const(1, 1));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn stos(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
    let detail = try!(details(instruction));

    // create a block for this instruction
    let (block_index, bits) = {
        let mut block = control_flow_graph.new_block()?;

        let src = operand_load(&mut block, &detail.operands[1])?;

        let bits = src.bits();

        operand_store(&mut block, &detail.operands[0], src)?;

        (block.index(), bits as u64)
    };

    let inc_index = {
        let inc_block = control_flow_graph.new_block()?;;

        inc_block.assign(
            scalar("edi", 32),
            Expr::add(expr_scalar("edi", 32), expr_const(bits / 8, 32))?
        );

        inc_block.index()
    };

    let dec_index = {
        let dec_block = control_flow_graph.new_block()?;;

        dec_block.assign(
            scalar("edi", 32),
            Expr::sub(expr_scalar("edi", 32), expr_const(bits / 8, 32))?
        );

        dec_block.index()
    };

    let terminating_index = {
        control_flow_graph.new_block()?.index()
    };

    control_flow_graph.conditional_edge(
        block_index,
        inc_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
    )?;
    control_flow_graph.conditional_edge(
        block_index,
        dec_index,
        Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
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



pub fn sysenter(control_flow_graph: &mut ControlFlowGraph, _: &capstone::Instr) -> Result<()> {
    // create a block for this instruction
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        block.raise(expr_scalar("sysenter", 1));

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
        block.assign(scalar("CF", 1), expr_const(0, 1));
        block.assign(scalar("OF", 1), expr_const(0, 1));;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}



pub fn xadd(control_flow_graph: &mut ControlFlowGraph, instruction: &capstone::Instr) -> Result<()> {
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
        operand_store(&mut block, &detail.operands[1], rhs)?;

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
        block.assign(scalar("CF", 1), expr_const(0, 1));
        block.assign(scalar("OF", 1), expr_const(0, 1));;

        // store result
        operand_store(&mut block, &detail.operands[0], result.into())?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}
