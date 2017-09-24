//! Capstone-based translator for 32-bit x86.

use capstone_rust::{capstone, capstone_sys};
use error::*;
use il::*;
use translator::{Arch, BlockTranslationResult, Endian};


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
                    capstone::mips_insn::MIPS_INS_BGEZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BGEZAL => semantics::bgezal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BGTZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLEZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLTZ   => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BLTZAL => semantics::bltzal(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BNE    => semantics::b(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_BREAK  => semantics::break_(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_CLO    => semantics::clo(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_CLZ    => semantics::clz(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_DIV    => semantics::div(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_DIVU   => semantics::divu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LB     => semantics::lb(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LBU    => semantics::lbu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LH     => semantics::lh(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LHU    => semantics::lhu(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LUI    => semantics::lui(&mut instruction_graph, &instruction),
                    capstone::mips_insn::MIPS_INS_LW     => semantics::lw(&mut instruction_graph, &instruction),
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
                        successors.push((address + 8, Some(Expression::cmpneq(lhs.clone(), rhs.clone())?)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BGEZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let false_condition = Expression::cmplts(zero, lhs)?;
                        let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BGTZ => {
                        let detail = semantics::details(&instruction)?;
                        let lhs = semantics::get_register(detail.operands[0].reg())?.expression();
                        let zero = expr_const(0, 32);
                        let target = detail.operands[1].imm() as u64;
                        let false_condition = Expression::or(
                            Expression::cmplts(zero.clone(), lhs.clone())?,
                            Expression::cmpneq(zero, lhs)?
                        )?;
                        let true_condition = Expression::cmpeq(false_condition.clone(), expr_const(0, 1))?;
                        successors.push((target, Some(true_condition)));
                        successors.push((address + 8, Some(false_condition)));
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
                        successors.push((address + 8, Some(false_condition)));
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
                        successors.push((address + 8, Some(false_condition)));
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
                        successors.push((address + 8, Some(false_condition)));
                        branch_delay = TranslateBranchDelay::Branch;
                    },
                    capstone::mips_insn::MIPS_INS_BAL |
                    capstone::mips_insn::MIPS_INS_BGEZAL |
                    capstone::mips_insn::MIPS_INS_BLTZAL => {
                        branch_delay = TranslateBranchDelay::BranchFallThrough;
                    }
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
