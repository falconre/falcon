//! Capstone-based translator for 32-bit x86.

use capstone_rust::{capstone, capstone_sys};
use error::*;
use il::*;
use translator::{Arch, BlockTranslationResult, Endian};


#[cfg(test)] mod test;
mod semantics;

/// The X86 translator.
#[derive(Clone)]
pub struct Mips;


impl Mips {
    pub fn new() -> Mips {
        Mips
    }
}


enum TranslateBranchDelay {
    None,
    Branch,
    DelaySlot(ControlFlowGraph),
    BranchFallThrough,
    DelaySlotFallThrough(ControlFlowGraph)
}



impl Arch for Mips {
    fn endian(&self) -> Endian {
        Endian::Big
    }

    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
        let cs = match capstone::Capstone::new(
            capstone::cs_arch::CS_ARCH_MIPS,
            capstone::CS_MODE_32 | capstone::CS_MODE_BIG_ENDIAN
        ) {
            Ok(cs) => cs,
            Err(_) => return Err("Capstone Error".into())
        };

        cs.option(capstone::cs_opt_type::CS_OPT_DETAIL, capstone::cs_opt_value::CS_OPT_ON).unwrap();

        // our graph for the block which we will build iteratively with each instruction
        let mut block_graph = ControlFlowGraph::new();

        // the length of this block in bytes
        let mut length: usize = 0;

        let mut successors = Vec::new();

        let mut offset: usize = 0;

        let mut branch_delay = TranslateBranchDelay::None;

        loop {
            let disassembly_range = (offset)..bytes.len();
            let disassembly_bytes = bytes.get(disassembly_range).unwrap();
            let instructions = match cs.disasm(disassembly_bytes, address + offset as u64, 1) {
                Ok(instructions) => instructions,
                Err(e) => match e.code() {
                    capstone_sys::cs_err::CS_ERR_OK => {
                        successors.push((address + offset as u64, None));
                        break;
                    }
                    _ => bail!("Capstone Error: {}", e.code() as u32)
                }
            };

            if instructions.count() == 0 {
                return Err("Capstone failed to disassemble any instruction".into());
            }

            let instruction = instructions.get(0).unwrap();

            if let capstone::InstrIdArch::MIPS(instruction_id) = instruction.id {
                
                let mut instruction_graph = ControlFlowGraph::new();

                match instruction_id {
                    capstone::mips_insn::MIPS_INS_ADD    => semantics::add(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_ADDI   => semantics::addi(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_ADDIU  => semantics::addiu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_ADDU   => semantics::addu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_AND    => semantics::and(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_ANDI   => semantics::andi(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_B      => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BAL    => semantics::bal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BEQ    => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BEQZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BGEZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BGEZAL => semantics::bgezal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BGTZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLEZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLTZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLTZAL => semantics::bltzal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BNE    => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BNEZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BREAK  => semantics::break_(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_CLO    => semantics::clo(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_CLZ    => semantics::clz(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_DIV    => semantics::div(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_DIVU   => semantics::divu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_J      => semantics::j(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_JR     => semantics::jr(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_JAL    => semantics::jal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_JALR   => semantics::jalr(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LB     => semantics::lb(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LBU    => semantics::lbu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LH     => semantics::lh(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LHU    => semantics::lhu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LUI    => semantics::lui(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LW     => semantics::lw(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MADD   => semantics::madd(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MADDU  => semantics::maddu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MFHI   => semantics::mfhi(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MFLO   => semantics::mflo(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MOVE   => semantics::move_(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MOVN   => semantics::movn(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MOVZ   => semantics::movz(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MSUB   => semantics::msub(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MSUBU  => semantics::msubu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MTHI   => semantics::mthi(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MTLO   => semantics::mtlo(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MUL    => semantics::mul(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MULT   => semantics::mult(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_MULTU  => semantics::multu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_NOP    => semantics::nop(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_NOR    => semantics::nor(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_OR     => semantics::or(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_ORI    => semantics::ori(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SB     => semantics::sb(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SH     => semantics::sh(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLL    => semantics::sll(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLLV   => semantics::sllv(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLT    => semantics::slt(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLTI   => semantics::slti(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLTIU  => semantics::sltiu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SLTU   => semantics::sltu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SRA    => semantics::sra(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SRAV   => semantics::srav(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SRL    => semantics::srl(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SRLV   => semantics::srlv(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SUB    => semantics::sub(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SUBU   => semantics::subu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SW     => semantics::sw(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_SYSCALL => semantics::syscall(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_XOR    => semantics::xor(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_XORI   => semantics::xori(&mut instruction_graph, &instruction),
                    _ => return Err(format!("Unhandled instruction {} at 0x{:x}",
                        instruction.mnemonic,
                        instruction.address
                    ).into())
                }?;

                match instruction_id {
                    capstone::mips_insn::MIPS_INS_B => {
                        let operand = semantics::details(&instruction)?.operands[0];
                        successors.push((operand.imm() as u64, None));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BEQ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let rhs = semantics::get_register(detail.operands[1].reg())?.expression();
                        let target = detail.operands[2].imm() as u64;
                        successors.push((target, Some(Expression::cmpeq(lhs.clone(), rhs.clone())?)));
                        successors.push((instruction.address + 8, Some(Expression::cmpneq(lhs.clone(), rhs.clone())?)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BEQZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let rhs = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        successors.push((target, Some(Expression::cmpeq(lhs.clone(), rhs.clone())?)));
                        successors.push((instruction.address + 8, Some(Expression::cmpneq(lhs.clone(), rhs.clone())?)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BGEZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let false_condition = Expression::cmplts(lhs, zero)?;
                        let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BGTZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let false_condition = Expression::or(
                            Expression::cmplts(lhs.clone(), zero.clone())?,
                            Expression::cmpeq(zero, lhs)?
                        )?;
                        let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BLEZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let true_condition = Expression::or(
                            Expression::cmplts(lhs.clone(), zero.clone())?,
                            Expression::cmpeq(lhs, zero)?
                        )?;
                        let false_condition = Expression::cmpeq(true_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BLTZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let true_condition = Expression::cmplts(lhs, zero)?;
                        let false_condition = Expression::cmpeq(true_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BNE => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let rhs = semantics::get_register(detail.operands[1].reg())?.expression();
                        let target = detail.operands[2].imm() as u64;
                        let true_condition = Expression::cmpneq(lhs.clone(), rhs.clone())?;
                        let false_condition = Expression::cmpeq(lhs, rhs)?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BNEZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let rhs = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let true_condition = Expression::cmpneq(lhs.clone(), rhs.clone())?;
                        let false_condition = Expression::cmpeq(lhs, rhs)?;
                        successors.push((target, Some(true_condition)));
                        successors.push((instruction.address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_J => {
                        let operand = semantics::details(&instruction)?.operands[0];
                        successors.push((operand.imm() as u64, None));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BAL |
                    capstone::mips_insn::MIPS_INS_BGEZAL |
                    capstone::mips_insn::MIPS_INS_BLTZAL |
                    capstone::mips_insn::MIPS_INS_JAL |
                    capstone::mips_insn::MIPS_INS_JALR => {
                        branch_delay = TranslateBranchDelay::BranchFallThrough;
                    },
                    capstone::mips_insn::MIPS_INS_JR => {
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    _ => {}
                }

                instruction_graph.set_address(Some(instruction.address));

                branch_delay = match branch_delay {
                    TranslateBranchDelay::None => {
                        block_graph.append(&instruction_graph)?;
                        TranslateBranchDelay::None
                    },
                    TranslateBranchDelay::Branch => {
                        TranslateBranchDelay::DelaySlot(instruction_graph)
                    },
                    TranslateBranchDelay::DelaySlot(cfg) => {
                        block_graph.append(&instruction_graph)?;
                        block_graph.append(&cfg)?;
                        break
                    },
                    TranslateBranchDelay::BranchFallThrough => {
                        TranslateBranchDelay::DelaySlotFallThrough(instruction_graph)
                    },
                    TranslateBranchDelay::DelaySlotFallThrough(cfg) => {
                        block_graph.append(&instruction_graph)?;
                        block_graph.append(&cfg)?;
                        TranslateBranchDelay::None
                    }
                };

                length += instruction.size as usize;
            }
            else {
                bail!("not a MIPS instruction")
            }

            offset += instruction.size as usize;
        }

        Ok(BlockTranslationResult::new(block_graph, address, length, successors))
    }
}