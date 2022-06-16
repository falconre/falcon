//! Capstone-based translator for MIPS.

use crate::architecture::Endian;
use crate::il::*;
use crate::translator::{
    unhandled_intrinsic, BlockTranslationResult, Options, Translator,
    DEFAULT_TRANSLATION_BLOCK_BYTES,
};
use crate::Error;
use falcon_capstone::capstone;

mod semantics;
#[cfg(test)]
mod test;

/// The MIPS translator.
#[derive(Clone, Debug, Default)]
pub struct Mips;

impl Mips {
    pub fn new() -> Mips {
        Mips
    }
}

impl Translator for Mips {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translate_block(bytes, address, Endian::Big, options)
    }
}

/// This MIPSel translator.
#[derive(Clone, Debug, Default)]
pub struct Mipsel;

impl Mipsel {
    pub fn new() -> Mipsel {
        Mipsel
    }
}

impl Translator for Mipsel {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translate_block(bytes, address, Endian::Little, options)
    }
}

enum TranslateBranchDelay {
    None,
    Branch,
    DelaySlot(u64, ControlFlowGraph),
    BranchFallThrough,
    DelaySlotFallThrough(u64, ControlFlowGraph),
}

// Direct branches are omitted, and we emit edges in the control flow graph
// instead. However, this can mess up some analyses where we expect an
// instruction at that address, such as branching to a return address. We emit
// a NOP instruction in these cases.
fn nop_graph(address: u64) -> Result<ControlFlowGraph, Error> {
    let mut cfg = ControlFlowGraph::new();

    let block_index = {
        let block = cfg.new_block()?;
        block.nop();
        block.index()
    };

    cfg.set_entry(block_index)?;
    cfg.set_exit(block_index)?;

    cfg.set_address(Some(address));

    Ok(cfg)
}

// If a branch has a delay slot, we need to calculate the condition for the
// branch before we execute the delay slow. We create a graph which sets a
// scalar "branching" condition, and execute this prior to the delay slot.
fn conditional_graph(
    address: u64,
    branching_condition: Expression,
) -> Result<ControlFlowGraph, Error> {
    let mut cfg = ControlFlowGraph::new();

    let block_index = {
        let block = cfg.new_block()?;
        block.assign(scalar("branching_condition", 1), branching_condition);
        block.index()
    };

    cfg.set_entry(block_index)?;
    cfg.set_exit(block_index)?;

    cfg.set_address(Some(address));

    Ok(cfg)
}

fn translate_block(
    bytes: &[u8],
    address: u64,
    endian: Endian,
    options: &Options,
) -> Result<BlockTranslationResult, Error> {
    let mode = match endian {
        Endian::Big => capstone::CS_MODE_32 | capstone::CS_MODE_BIG_ENDIAN,
        Endian::Little => capstone::CS_MODE_32 | capstone::CS_MODE_LITTLE_ENDIAN,
    };
    let cs = match capstone::Capstone::new(capstone::cs_arch::CS_ARCH_MIPS, mode) {
        Ok(cs) => cs,
        Err(_) => return Err(Error::CapstoneError),
    };

    cs.option(
        capstone::cs_opt_type::CS_OPT_DETAIL,
        capstone::cs_opt_value::CS_OPT_ON,
    )
    .unwrap();

    // A vec which holds each lifted instruction in this block.
    let mut block_graphs: Vec<(u64, ControlFlowGraph)> = Vec::new();

    // the length of this block in bytes.
    let mut length: usize = 0;

    // The successors which exit this block.
    let mut successors = Vec::new();

    // Offset in bytes to the next instruction from the address given at entry.
    let mut offset: usize = 0;

    // MIPS-specific enum to handle branch delay slot.
    let mut branch_delay = TranslateBranchDelay::None;

    loop {
        // if we read in the maximum number of bytes possible (meaning there are
        // likely more bytes), and we don't have enough bytes to handle a delay
        // slot, return. We always want to have enough bytes to handle a delay
        // slot.
        if offset >= bytes.len() {
            successors.push((address + offset as u64, None));
            break;
        }
        let disassembly_range = (offset)..bytes.len();
        let disassembly_bytes = bytes.get(disassembly_range).unwrap();
        let instructions = match cs.disasm(disassembly_bytes, address + offset as u64, 1) {
            Ok(instructions) => instructions,
            Err(e) => return Err(Error::Capstone(e)),
        };

        if instructions.count() == 0 {
            return Err("Capstone failed to disassemble any instruction".into());
        }

        let instruction = instructions.get(0).unwrap();

        if let capstone::InstrIdArch::MIPS(instruction_id) = instruction.id {
            let mut instruction_graph = ControlFlowGraph::new();

            match instruction_id {
                capstone::mips_insn::MIPS_INS_ADD => {
                    semantics::add(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_ADDI => {
                    semantics::addi(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_ADDIU => {
                    semantics::addiu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_ADDU => {
                    semantics::addu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_AND => {
                    semantics::and(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_ANDI => {
                    semantics::andi(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_B => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BAL => {
                    semantics::bal(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BEQ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BEQZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BGEZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BGEZAL => {
                    semantics::bgezal(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BGTZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BLEZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BLTZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BLTZAL => {
                    semantics::bltzal(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BNE => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BNEZ => {
                    semantics::b(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_BREAK => {
                    semantics::break_(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_CLO => {
                    semantics::clo(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_CLZ => {
                    semantics::clz(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_DIV => {
                    semantics::div(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_DIVU => {
                    semantics::divu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_J => {
                    semantics::j(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_JR => {
                    semantics::jr(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_JAL => {
                    semantics::jal(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_JALR => {
                    semantics::jalr(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LB => {
                    semantics::lb(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LBU => {
                    semantics::lbu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LH => {
                    semantics::lh(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LHU => {
                    semantics::lhu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LL => {
                    semantics::ll(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LUI => {
                    semantics::lui(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LW => {
                    semantics::lw(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LWL => {
                    semantics::lwl(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_LWR => {
                    semantics::lwr(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MADD => {
                    semantics::madd(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MADDU => {
                    semantics::maddu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MFHI => {
                    semantics::mfhi(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MFLO => {
                    semantics::mflo(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MOVE => {
                    semantics::move_(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MOVN => {
                    semantics::movn(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MOVZ => {
                    semantics::movz(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MSUB => {
                    semantics::msub(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MSUBU => {
                    semantics::msubu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MTHI => {
                    semantics::mthi(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MTLO => {
                    semantics::mtlo(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MUL => {
                    semantics::mul(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MULT => {
                    semantics::mult(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_MULTU => {
                    semantics::multu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_NEGU => {
                    semantics::negu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_NOP => {
                    semantics::nop(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_NOR => {
                    semantics::nor(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_OR => {
                    semantics::or(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_ORI => {
                    semantics::ori(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_RDHWR => {
                    semantics::rdhwr(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_PREF => {
                    semantics::nop(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SB => {
                    semantics::sb(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SC => {
                    semantics::sc(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SH => {
                    semantics::sh(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLL => {
                    semantics::sll(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLLV => {
                    semantics::sllv(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLT => {
                    semantics::slt(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLTI => {
                    semantics::slti(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLTIU => {
                    semantics::sltiu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SLTU => {
                    semantics::sltu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SRA => {
                    semantics::sra(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SRAV => {
                    semantics::srav(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SRL => {
                    semantics::srl(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SRLV => {
                    semantics::srlv(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SUB => {
                    semantics::sub(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SUBU => {
                    semantics::subu(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SW => {
                    semantics::sw(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SWL => {
                    semantics::swl(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SWR => {
                    semantics::swr(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SYNC => {
                    semantics::nop(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_SYSCALL => {
                    semantics::syscall(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_TEQ => {
                    semantics::teq(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_XOR => {
                    semantics::xor(&mut instruction_graph, &instruction)
                }
                capstone::mips_insn::MIPS_INS_XORI => {
                    semantics::xori(&mut instruction_graph, &instruction)
                }
                _ => {
                    if options.unsupported_are_intrinsics() {
                        unhandled_intrinsic(&mut instruction_graph, &instruction)
                    } else {
                        let bytes = (0..4)
                            .map(|i| disassembly_bytes[i])
                            .map(|byte| format!("{:02x}", byte))
                            .collect::<Vec<String>>()
                            .join("");
                        return Err(format!(
                            "Unhandled instruction ({:?}) {} {} {} at 0x{:x}",
                            instruction_id,
                            bytes,
                            instruction.mnemonic,
                            instruction.op_str,
                            instruction.address
                        )
                        .into());
                    }
                }
            }?;

            fn conditional_direct_branch(
                block_graphs: &mut Vec<(u64, ControlFlowGraph)>,
                successors: &mut Vec<(u64, Option<Expression>)>,
                address: u64,
                true_target: u64,
                false_target: u64,
                branch_condition: Expression,
            ) -> Result<(), Error> {
                block_graphs.push((address, conditional_graph(address, branch_condition)?));

                let branch_condition = expr_scalar("branching_condition", 1);

                successors.push((true_target, Some(branch_condition.clone())));
                successors.push((
                    false_target,
                    Some(Expression::cmpeq(branch_condition, expr_const(0, 1))?),
                ));

                Ok(())
            }

            // Before we even attempt to handle an instruction with a delay
            // slot, make sure we have enough bytes left over to handle the
            // delay slot
            match instruction_id {
                capstone::mips_insn::MIPS_INS_B
                | capstone::mips_insn::MIPS_INS_BEQ
                | capstone::mips_insn::MIPS_INS_BEQZ
                | capstone::mips_insn::MIPS_INS_BGEZ
                | capstone::mips_insn::MIPS_INS_BGTZ
                | capstone::mips_insn::MIPS_INS_BLTZ
                | capstone::mips_insn::MIPS_INS_BNE
                | capstone::mips_insn::MIPS_INS_BNEZ
                | capstone::mips_insn::MIPS_INS_J
                | capstone::mips_insn::MIPS_INS_BAL
                | capstone::mips_insn::MIPS_INS_BGEZAL
                | capstone::mips_insn::MIPS_INS_BLTZAL
                | capstone::mips_insn::MIPS_INS_JAL
                | capstone::mips_insn::MIPS_INS_JALR
                | capstone::mips_insn::MIPS_INS_JR => {
                    if bytes.len() == DEFAULT_TRANSLATION_BLOCK_BYTES && offset + 8 >= bytes.len() {
                        successors.push((address + offset as u64, None));
                        break;
                    }
                }
                _ => {}
            }

            // We need to make the conditional branch comparison, save it to a
            // temporary, and branch based on the temporary.
            //
            // This temporary will always be called, "Branching condition"
            match instruction_id {
                capstone::mips_insn::MIPS_INS_B => {
                    block_graphs.push((instruction.address, nop_graph(instruction.address)?));
                    let operand = semantics::details(&instruction)?.operands[0];
                    successors.push((operand.imm() as u64, None));
                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BEQ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let rhs = semantics::get_register(detail.operands[1].reg())?.expression();
                    let target = detail.operands[2].imm() as u64;
                    let condition = Expression::cmpeq(lhs, rhs)?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BEQZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let rhs = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition = Expression::cmpeq(lhs, rhs)?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BGEZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let zero = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition =
                        Expression::cmpeq(Expression::cmplts(lhs, zero)?, expr_const(0, 1))?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BGTZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let zero = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition = Expression::cmplts(zero, lhs)?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BLEZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let zero = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition = Expression::or(
                        Expression::cmplts(lhs.clone(), zero.clone())?,
                        Expression::cmpeq(lhs, zero)?,
                    )?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BLTZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let zero = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition = Expression::cmplts(lhs, zero)?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BNE => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let rhs = semantics::get_register(detail.operands[1].reg())?.expression();
                    let target = detail.operands[2].imm() as u64;
                    let condition = Expression::cmpneq(lhs.clone(), rhs.clone())?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BNEZ => {
                    let detail = semantics::details(&instruction)?;
                    let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                    let rhs = expr_const(0, 32);
                    let target = detail.operands[1].imm() as u64;
                    let condition = Expression::cmpneq(lhs.clone(), rhs.clone())?;

                    conditional_direct_branch(
                        &mut block_graphs,
                        &mut successors,
                        instruction.address,
                        target,
                        instruction.address + 8,
                        condition,
                    )?;

                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_J => {
                    block_graphs.push((instruction.address, nop_graph(instruction.address)?));
                    let operand = semantics::details(&instruction)?.operands[0];
                    successors.push((operand.imm() as u64, None));
                    branch_delay = TranslateBranchDelay::Branch;
                }
                capstone::mips_insn::MIPS_INS_BAL
                | capstone::mips_insn::MIPS_INS_BGEZAL
                | capstone::mips_insn::MIPS_INS_BLTZAL
                | capstone::mips_insn::MIPS_INS_JAL
                | capstone::mips_insn::MIPS_INS_JALR => {
                    block_graphs.push((instruction.address, nop_graph(instruction.address)?));
                    branch_delay = TranslateBranchDelay::BranchFallThrough;
                }
                capstone::mips_insn::MIPS_INS_JR => {
                    block_graphs.push((instruction.address, nop_graph(instruction.address)?));
                    branch_delay = TranslateBranchDelay::Branch;
                }
                _ => {
                    // We only set an address for this function is there isn't
                    // a branch. Branch instruction addresses are set in a
                    // nop instruction emitted before the delay slot
                    // instruction.
                    instruction_graph.set_address(Some(instruction.address));
                }
            }

            branch_delay = match branch_delay {
                TranslateBranchDelay::None => {
                    block_graphs.push((instruction.address, instruction_graph));
                    TranslateBranchDelay::None
                }
                TranslateBranchDelay::Branch => {
                    instruction_graph.set_address(Some(instruction.address + 1));
                    TranslateBranchDelay::DelaySlot(instruction.address, instruction_graph)
                }
                TranslateBranchDelay::DelaySlot(address, cfg) => {
                    block_graphs.push((instruction.address, instruction_graph));
                    // this +1 is a hack to make parsing BlockTranslationResult
                    // blocks work correctly
                    block_graphs.push((address + 1, cfg));
                    break;
                }
                TranslateBranchDelay::BranchFallThrough => {
                    instruction_graph.set_address(Some(instruction.address + 1));
                    TranslateBranchDelay::DelaySlotFallThrough(
                        instruction.address,
                        instruction_graph,
                    )
                }
                TranslateBranchDelay::DelaySlotFallThrough(address, cfg) => {
                    block_graphs.push((instruction.address, instruction_graph));
                    // this +1 is a hack to make parsing BlockTranslationResult
                    // blocks work correctly
                    block_graphs.push((address + 1, cfg));
                    TranslateBranchDelay::None
                }
            };

            length += instruction.size as usize;
        } else {
            return Err(Error::Custom("Not a MIPS instruction".to_string()));
        }

        offset += instruction.size as usize;
    }

    Ok(BlockTranslationResult::new(
        block_graphs,
        address,
        length,
        successors,
    ))
}
