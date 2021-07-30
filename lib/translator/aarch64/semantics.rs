use crate::error::Result;
use crate::il;
use crate::translator::aarch64::register::get_register;

/// Get the scalar for a well-known register.
macro_rules! scalar {
    ("x30") => {
        // the link register
        il::scalar("x30", 64)
    };
    ($x:literal) => {
        compile_error!(concat!($x, " is not a well-known register"))
    };
}

/// Get the expression representing a well-known register's value.
macro_rules! expr {
    ($x:tt) => {
        il::Expression::Scalar(scalar!($x))
    };
}

// A convenience function for turning unhandled instructions into intrinsics
pub(super) fn unhandled_intrinsic(
    bytes: &[u8],
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(il::Intrinsic::new(
            instruction.op().to_string(),
            instruction.to_string(),
            Vec::new(),
            None,
            None,
            bytes.to_vec(),
        ));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

/// `out_bits` is only used for zero/sign-extension modifier.
fn operand_load(
    block: &mut il::Block,
    opr: &bad64::Operand,
    out_bits: usize,
) -> Result<il::Expression> {
    // TODO: Consider `unsupported_are_intrinsics`
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => get_register(*reg)?.get(),
        bad64::Operand::Imm32 { imm, shift } => maybe_shift(
            il::expr_const(imm_to_u64(imm) as u32 as u64, 32),
            shift.as_ref(),
            out_bits,
        ),
        bad64::Operand::Imm64 { imm, shift } => maybe_shift(
            il::expr_const(imm_to_u64(imm), 64),
            shift.as_ref(),
            out_bits,
        ),
        bad64::Operand::ShiftReg { reg, shift: shift_ } => {
            shift(get_register(*reg)?.get()?, shift_, out_bits)
        }
        bad64::Operand::Label(imm) => Ok(il::expr_const(imm_to_u64(imm), 64)),
        bad64::Operand::FImm32(_)
        | bad64::Operand::QualReg { .. }
        | bad64::Operand::Reg {
            arrspec: Some(_), ..
        }
        | bad64::Operand::MultiReg { .. }
        | bad64::Operand::SysReg(_)
        | bad64::Operand::MemReg(_)
        | bad64::Operand::MemOffset { .. }
        | bad64::Operand::MemPreIdx { .. }
        | bad64::Operand::MemPostIdxReg(_)
        | bad64::Operand::MemPostIdxImm { .. }
        | bad64::Operand::MemExt { .. }
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => bail!("Unsupported operand: `{}`", opr),
    }
}

fn operand_store(block: &mut il::Block, opr: &bad64::Operand, value: il::Expression) -> Result<()> {
    // TODO: Consider `unsupported_are_intrinsics`
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => get_register(*reg)?.set(block, value),
        bad64::Operand::ShiftReg { .. }
        | bad64::Operand::Imm32 { .. }
        | bad64::Operand::Imm64 { .. }
        | bad64::Operand::FImm32(_) => {
            bail!("Can't store to operand `{}`", opr)
        }
        bad64::Operand::QualReg { .. }
        | bad64::Operand::Reg {
            arrspec: Some(_), ..
        }
        | bad64::Operand::MultiReg { .. }
        | bad64::Operand::SysReg(_)
        | bad64::Operand::MemReg(_)
        | bad64::Operand::MemOffset { .. }
        | bad64::Operand::MemPreIdx { .. }
        | bad64::Operand::MemPostIdxReg(_)
        | bad64::Operand::MemPostIdxImm { .. }
        | bad64::Operand::MemExt { .. }
        | bad64::Operand::Label(_)
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => bail!("Unsupported operand: `{}`", opr),
    }
}

fn operand_storing_width(opr: &bad64::Operand) -> Result<usize> {
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => Ok(get_register(*reg)?.bits()),
        bad64::Operand::ShiftReg { .. }
        | bad64::Operand::Imm32 { .. }
        | bad64::Operand::Imm64 { .. }
        | bad64::Operand::FImm32(_) => {
            bail!("Can't store to operand `{}`", opr)
        }
        bad64::Operand::QualReg { .. }
        | bad64::Operand::Reg {
            arrspec: Some(_), ..
        }
        | bad64::Operand::MultiReg { .. }
        | bad64::Operand::SysReg(_)
        | bad64::Operand::MemReg(_)
        | bad64::Operand::MemOffset { .. }
        | bad64::Operand::MemPreIdx { .. }
        | bad64::Operand::MemPostIdxReg(_)
        | bad64::Operand::MemPostIdxImm { .. }
        | bad64::Operand::MemExt { .. }
        | bad64::Operand::Label(_)
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => bail!("Unsupported operand: `{}`", opr),
    }
}

fn maybe_shift(
    value: il::Expression,
    bad64_shift: Option<&bad64::Shift>,
    out_bits: usize,
) -> Result<il::Expression> {
    if let Some(bad64_shift) = bad64_shift {
        shift(value, bad64_shift, out_bits)
    } else {
        Ok(value)
    }
}

fn shift(
    value: il::Expression,
    bad64_shift: &bad64::Shift,
    out_bits: usize,
) -> Result<il::Expression> {
    let (unsigned, len, shift_amount) = match *bad64_shift {
        // ShiftReg
        bad64::Shift::LSL(amount) => return lsl(value, il::expr_const(amount.into(), out_bits)),
        bad64::Shift::LSR(amount) => return lsr(value, il::expr_const(amount.into(), out_bits)),
        bad64::Shift::ASR(amount) => return asr(value, il::expr_const(amount.into(), out_bits)),
        bad64::Shift::ROR(amount) => return ror(value, il::expr_const(amount.into(), out_bits)),
        // AdvSIMDExpandImm with `op == 0 && cmode == 110x`
        bad64::Shift::MSL(amount) => bail!("Unsupported MSL shifting in operand"),
        // ExtendReg
        bad64::Shift::SXTB(amount) => (false, 8, amount),
        bad64::Shift::SXTH(amount) => (false, 16, amount),
        bad64::Shift::SXTW(amount) => (false, 32, amount),
        bad64::Shift::SXTX(amount) => (false, 64, amount),
        bad64::Shift::UXTB(amount) => (true, 8, amount),
        bad64::Shift::UXTH(amount) => (true, 16, amount),
        bad64::Shift::UXTW(amount) => (true, 32, amount),
        bad64::Shift::UXTX(amount) => (true, 64, amount),
    };

    let extended = if len < value.bits() {
        il::Expression::trun(len, value)?
    } else {
        value
    };
    let extended = if len < out_bits {
        if unsigned {
            il::Expression::zext(out_bits, extended)?
        } else {
            il::Expression::sext(out_bits, extended)?
        }
    } else {
        extended
    };

    il::Expression::shl(extended, il::expr_const(shift_amount.into(), out_bits))
}

/// Logical shift left
fn lsl(value: il::Expression, shift: il::Expression) -> Result<il::Expression> {
    il::Expression::shl(value, shift)
}

/// Logical shift right
fn lsr(value: il::Expression, shift: il::Expression) -> Result<il::Expression> {
    il::Expression::shr(value, shift)
}

/// Arithmetic shift right
fn asr(value: il::Expression, shift: il::Expression) -> Result<il::Expression> {
    il::Expression::sra(value, shift)
}

/// Rotate right
fn ror(value: il::Expression, shift: il::Expression) -> Result<il::Expression> {
    let shift_right_bits = shift;
    let shift_left_bits = il::Expression::sub(
        il::expr_const(value.bits() as u64, value.bits()),
        shift_right_bits.clone(),
    )?;
    il::Expression::or(
        il::Expression::shl(value.clone(), shift_left_bits)?,
        il::Expression::shr(value, shift_right_bits)?,
    )
}

fn imm_to_u64(imm: &bad64::Imm) -> u64 {
    match *imm {
        bad64::Imm::Signed(x) => x as u64,
        bad64::Imm::Unsigned(x) => x,
    }
}

pub(super) fn add(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let lhs = operand_load(block, &instruction.operands()[1], bits)?;
        let rhs = operand_load(block, &instruction.operands()[2], bits)?;

        // perform operation
        let src = il::Expression::add(lhs, rhs)?;

        // store result
        operand_store(block, &instruction.operands()[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub(super) fn b(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = operand_load(block, &instruction.operands()[0], 64)?;

        block.branch(dst);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub(super) fn bl(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let dst = operand_load(block, &instruction.operands()[0], 64)?;

        block.assign(
            scalar!("x30"),
            il::expr_const(instruction.address().wrapping_add(4), 64),
        );
        block.branch(dst);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub(super) fn mov(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let rhs = operand_load(block, &instruction.operands()[1], bits)?;

        // store result
        operand_store(block, &instruction.operands()[0], rhs)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub(super) fn nop(
    control_flow_graph: &mut il::ControlFlowGraph,
    _instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.nop();

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub(super) fn ret(
    control_flow_graph: &mut il::ControlFlowGraph,
    _instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.branch(expr!("x30"));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

// TODO: Rest of the instructions
