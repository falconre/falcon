//! Capstone-based translator for MIPS.

use crate::il::*;
use crate::translator::{unhandled_intrinsic, BlockTranslationResult, Options, Translator};
use crate::Error;
use falcon_capstone::capstone;

pub mod semantics;
#[cfg(test)]
mod test;

/// The MIPS translator.
#[derive(Clone, Debug, Default)]
pub struct Ppc;

impl Ppc {
    pub fn new() -> Ppc {
        Ppc
    }
}

impl Translator for Ppc {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translate_block(bytes, address, options)
    }
}

pub fn nop(control_flow_graph: &mut ControlFlowGraph) -> Result<(), Error> {
    let block_index = {
        let block = control_flow_graph.new_block()?;
        block.nop();
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

fn translate_block(
    bytes: &[u8],
    address: u64,
    options: &Options,
) -> Result<BlockTranslationResult, Error> {
    let mode = capstone::CS_MODE_32 | capstone::CS_MODE_BIG_ENDIAN;
    let cs = match capstone::Capstone::new(capstone::cs_arch::CS_ARCH_PPC, mode) {
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
    let mut successors: Vec<(u64, Option<Expression>)> = Vec::new();

    // Offset in bytes to the next instruction from the address given at entry.
    let mut offset: usize = 0;

    loop {
        // println!("offset: 0x{:x}, address + offset: 0x{:x}",
        //          offset,
        //          address + offset as u64);
        if offset == bytes.len() {
            successors.push((address + offset as u64, None));
            break;
        }

        let disassembly_range = (offset)..bytes.len();
        let disassembly_bytes = bytes.get(disassembly_range).unwrap();
        let instructions = match cs.disasm(disassembly_bytes, address + offset as u64, 1) {
            Ok(instructions) => instructions,
            Err(_) => return Err(Error::CapstoneError),
        };

        if instructions.count() == 0 {
            return Err(Error::CapstoneError);
        }

        let instruction = instructions.get(0).unwrap();

        if let capstone::InstrIdArch::PPC(instruction_id) = instruction.id {
            let mut instruction_graph = ControlFlowGraph::new();

            match instruction_id {
                capstone::ppc_insn::PPC_INS_ADD => {
                    semantics::add(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_ADDI => {
                    semantics::addi(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_ADDIS => {
                    semantics::addis(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_ADDZE => {
                    semantics::addze(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_B => nop(&mut instruction_graph),
                capstone::ppc_insn::PPC_INS_BL => {
                    semantics::bl(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_BC => nop(&mut instruction_graph),
                capstone::ppc_insn::PPC_INS_BCLR => {
                    semantics::bclr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_BCTR => {
                    semantics::bctr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_BDNZL => nop(&mut instruction_graph),
                capstone::ppc_insn::PPC_INS_BLR => nop(&mut instruction_graph),
                capstone::ppc_insn::PPC_INS_CMPWI => {
                    semantics::cmpwi(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_CMPLWI => {
                    semantics::cmplwi(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_LBZ => {
                    semantics::lbz(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_LWZ => {
                    semantics::lwz(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_LWZU => {
                    semantics::lwzu(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_LI => {
                    semantics::li(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_LIS => {
                    semantics::lis(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_MTCTR => {
                    semantics::mtctr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_MFLR => {
                    semantics::mflr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_MR => {
                    semantics::mr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_MTLR => {
                    semantics::mflr(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_NOP => {
                    semantics::nop(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_RLWINM => {
                    semantics::rlwinm(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_SLWI => {
                    semantics::slwi(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_SRAWI => {
                    semantics::srawi(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_STMW => {
                    semantics::stmw(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_STW => {
                    semantics::stw(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_STWU => {
                    semantics::stwu(&mut instruction_graph, &instruction)
                }
                capstone::ppc_insn::PPC_INS_SUBF => {
                    semantics::subf(&mut instruction_graph, &instruction)
                }
                _ => {
                    if options.unsupported_are_intrinsics() {
                        unhandled_intrinsic(&mut instruction_graph, &instruction)?;
                    }
                    let bytes = (0..4)
                        .map(|i| disassembly_bytes[i])
                        .map(|byte| format!("{:02x}", byte))
                        .collect::<Vec<String>>()
                        .join("");
                    return Err(format!(
                        "Unhandled instruction {} {} {} at 0x{:x}",
                        bytes, instruction.mnemonic, instruction.op_str, instruction.address
                    )
                    .into());
                }
            }?;

            match instruction_id {
                capstone::ppc_insn::PPC_INS_B => {
                    let detail = semantics::details(&instruction)?;

                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    successors.push((detail.operands[0].imm() as u64, None));

                    break;
                }
                capstone::ppc_insn::PPC_INS_BCTR => {
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    break;
                }
                capstone::ppc_insn::PPC_INS_BC => {
                    let detail = semantics::details(&instruction)?;

                    // beq
                    if detail.operands[0].imm() == 12 && detail.operands[1].imm() == 10 {
                        let true_condition = expr_scalar("cr0-eq", 1);
                        let false_condition =
                            Expression::cmpneq(true_condition.clone(), expr_const(1, 1))?;
                        successors.push((instruction.address + 4, Some(false_condition)));
                        successors.push((detail.operands[0].imm() as u64, Some(true_condition)));
                    } else {
                        return Err(Error::Custom("Unhandled bc instruction".to_string()));
                    }
                    break;
                }
                capstone::ppc_insn::PPC_INS_BLR | capstone::ppc_insn::PPC_INS_BL => {
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));
                }
                _ => {
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));
                }
            }

            length += instruction.size as usize;
        } else {
            return Err(Error::Custom("not a MIPS instruction".to_string()));
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
