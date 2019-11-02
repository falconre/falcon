//! Capstone-based translator for MIPS.

use error::*;
use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::arm_cc;
use il::*;
use translator::{BlockTranslationResult, Translator};

pub mod semantics;
#[cfg(test)]
mod test;

/// The MIPS translator.
#[derive(Clone, Debug)]
pub struct Arm;

impl Arm {
    pub fn new() -> Arm {
        Arm
    }
}

impl Translator for Arm {
    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
        translate_block(bytes, address)
    }
}

pub fn nop(control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;
        block.nop();
        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

// Ensure there is an instruction in the first block of the graph
fn ensure_block_instruction(control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
    let head_block_num_instructions = control_flow_graph
        .block(control_flow_graph.entry().unwrap())?
        .instructions()
        .len();

    if head_block_num_instructions == 0 {
        let head_index = control_flow_graph.entry().unwrap();
        control_flow_graph.block_mut(head_index)?.nop();
    }

    Ok(())
}

fn get_instruction_conditional(instruction: &capstone::Instr) -> Result<Option<Expression>> {
    let detail = semantics::details(instruction)?;

    let condition: Option<Expression> = match detail.cc {
        arm_cc::ARM_CC_EQ => Some(Expression::cmpeq(expr_scalar("Z", 1), expr_const(1, 1))?),
        arm_cc::ARM_CC_NE => Some(Expression::cmpeq(expr_scalar("Z", 1), expr_const(0, 1))?),
        arm_cc::ARM_CC_HS => Some(Expression::cmpeq(expr_scalar("C", 1), expr_const(1, 1))?),
        arm_cc::ARM_CC_LO => Some(Expression::cmpeq(expr_scalar("C", 1), expr_const(0, 1))?),
        arm_cc::ARM_CC_MI => Some(Expression::cmpeq(expr_scalar("N", 1), expr_const(1, 1))?),
        arm_cc::ARM_CC_PL => Some(Expression::cmpeq(expr_scalar("N", 1), expr_const(0, 1))?),
        arm_cc::ARM_CC_VS => Some(Expression::cmpeq(expr_scalar("V", 1), expr_const(1, 1))?),
        arm_cc::ARM_CC_VC => Some(Expression::cmpeq(expr_scalar("V", 1), expr_const(0, 1))?),
        arm_cc::ARM_CC_HI => Some(Expression::and(
            Expression::cmpeq(expr_scalar("C", 1), expr_const(1, 1))?,
            Expression::cmpeq(expr_scalar("Z", 1), expr_const(0, 1))?,
        )?),
        arm_cc::ARM_CC_LS => Some(Expression::and(
            Expression::cmpeq(expr_scalar("C", 1), expr_const(0, 1))?,
            Expression::cmpeq(expr_scalar("Z", 1), expr_const(1, 1))?,
        )?),
        arm_cc::ARM_CC_GE => Some(Expression::cmpeq(expr_scalar("N", 1), expr_scalar("V", 1))?),
        arm_cc::ARM_CC_LT => Some(Expression::cmpneq(
            expr_scalar("N", 1),
            expr_scalar("V", 1),
        )?),
        arm_cc::ARM_CC_GT => Some(Expression::and(
            Expression::cmpeq(expr_scalar("Z", 1), expr_const(0, 1))?,
            Expression::cmpeq(expr_scalar("N", 1), expr_scalar("V", 1))?,
        )?),
        arm_cc::ARM_CC_LE => Some(Expression::and(
            Expression::cmpeq(expr_scalar("Z", 1), expr_const(1, 1))?,
            Expression::cmpeq(expr_scalar("N", 1), expr_scalar("V", 1))?,
        )?),
        _ => None,
    };

    Ok(condition)
}

fn make_instruction_conditional(
    instruction: &capstone::Instr,
    control_flow_graph: &mut ControlFlowGraph,
) -> Result<()> {
    let condition = match get_instruction_conditional(instruction)? {
        Some(condition) => condition,
        None => return Ok(()),
    };

    // Create an entry and exit vertex
    let entry_block_index = control_flow_graph.new_block()?.index();
    let exit_block_index = control_flow_graph.new_block()?.index();

    let current_entry_index = control_flow_graph.entry().unwrap();
    let current_exit_block = control_flow_graph.exit().unwrap();

    // Edge from new entry to previous entry
    control_flow_graph.conditional_edge(
        entry_block_index,
        current_entry_index,
        condition.clone(),
    )?;

    // Edge from new entry to new exit
    control_flow_graph.conditional_edge(
        entry_block_index,
        exit_block_index,
        Expression::cmpeq(condition, expr_const(0, 1))?,
    )?;

    // Edge from previous exit to new exit
    control_flow_graph.unconditional_edge(current_exit_block, exit_block_index)?;

    control_flow_graph.set_entry(entry_block_index)?;
    control_flow_graph.set_exit(exit_block_index)?;

    Ok(())
}

fn translate_block(bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
    let mode = capstone::CS_MODE_ARM | capstone::CS_MODE_BIG_ENDIAN;
    let cs = match capstone::Capstone::new(capstone::cs_arch::CS_ARCH_ARM, mode) {
        Ok(cs) => cs,
        Err(_) => return Err(ErrorKind::CapstoneError.into()),
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
            Err(_) => return Err(ErrorKind::CapstoneError.into()),
        };

        if instructions.count() == 0 {
            return Err(ErrorKind::CapstoneError.into());
        }

        let instruction = instructions.get(0).unwrap();

        if let capstone::InstrIdArch::ARM(instruction_id) = instruction.id {
            let mut instruction_graph = ControlFlowGraph::new();

            match instruction_id {
                capstone::arm_insn::ARM_INS_ADC => {
                    semantics::adc(&mut instruction_graph, &instruction)
                }
                capstone::arm_insn::ARM_INS_ADD => {
                    semantics::add(&mut instruction_graph, &instruction)
                }
                capstone::arm_insn::ARM_INS_AND => {
                    semantics::and(&mut instruction_graph, &instruction)
                }
                capstone::arm_insn::ARM_INS_LDR |
                capstone::arm_insn::ARM_INS_LDRB |
                capstone::arm_insn::ARM_INS_LDRH |
                capstone::arm_insn::ARM_INS_LDRSB |
                capstone::arm_insn::ARM_INS_LDRSH => {
                    semantics::ldr_multi(&mut instruction_graph, &instruction)
                }
                capstone::arm_insn::ARM_INS_ORR => {
                    semantics::orr(&mut instruction_graph, &instruction)
                }
                _ => {
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
                capstone::arm_insn::ARM_INS_B => {
                    ensure_block_instruction(&mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    let condition = get_instruction_conditional(&instruction)?;
                    let detail = semantics::details(&instruction)?;

                    match condition {
                        Some(condition) => {
                            successors.push((
                                instruction.address + instruction.size as u64,
                                Some(Expression::cmpeq(condition.clone(), expr_const(0, 1))?),
                            ));
                            successors.push((detail.operands[0].imm() as u64, Some(condition)));
                        }
                        None => {
                            successors.push((detail.operands[0].imm() as u64, None));
                        }
                    }

                    break;
                }
                _ => {
                    make_instruction_conditional(&instruction, &mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));
                }
            }

            length += instruction.size as usize;
        } else {
            bail!("not an ARM instruction")
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
