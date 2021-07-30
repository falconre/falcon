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

fn operand_load(block: &mut il::Block, opr: &bad64::Operand) -> Result<il::Expression> {
    // TODO: Consider `unsupported_are_intrinsics`
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => get_register(*reg)?.get(),
        bad64::Operand::Imm32 { imm, shift: None } => {
            Ok(il::expr_const(imm_to_u64(imm) as u32 as u64, 32))
        }
        bad64::Operand::Imm64 { imm, shift: None } => Ok(il::expr_const(imm_to_u64(imm), 64)),
        bad64::Operand::Label(imm) => Ok(il::expr_const(imm_to_u64(imm), 64)),
        bad64::Operand::Imm32 { shift: Some(_), .. }
        | bad64::Operand::Imm64 { shift: Some(_), .. }
        | bad64::Operand::FImm32(_)
        | bad64::Operand::ShiftReg { .. }
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
        bad64::Operand::Imm32 { .. } | bad64::Operand::Imm64 { .. } | bad64::Operand::FImm32(_) => {
            bail!("Can't store to operand `{}`", opr)
        }
        bad64::Operand::ShiftReg { .. }
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
        | bad64::Operand::Label(_)
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => bail!("Unsupported operand: `{}`", opr),
    }
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
        let lhs = operand_load(block, &instruction.operands()[1])?;
        let rhs = operand_load(block, &instruction.operands()[2])?;

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
        let dst = operand_load(block, &instruction.operands()[0])?;

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
        let dst = operand_load(block, &instruction.operands()[0])?;

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
        let rhs = operand_load(block, &instruction.operands()[1])?;

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
