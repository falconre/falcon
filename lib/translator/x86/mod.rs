use capstone_rust::{capstone, capstone_sys};
use error::*;
use il::*;
use translator::{Arch, BlockTranslationResult, Endian};


pub mod semantics;

pub struct X86;


impl X86 {
    pub fn new() -> X86 {
        X86
    }
}


impl Arch for X86 {
    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult> {
        let cs = match capstone::Capstone::new(capstone::cs_arch::CS_ARCH_X86, capstone::cs_mode::CS_MODE_32) {
            Ok(cs) => cs,
            Err(e) => return Err("Capstone Error".into())
        };

        cs.option(capstone::cs_opt_type::CS_OPT_DETAIL, capstone::cs_opt_value::CS_OPT_ON).unwrap();

        let instructions = match cs.disasm(bytes, address, 0) {
            Ok(instructions) => instructions,
            Err(_) => return Err("Capstone Error".into())
        };

        // our graph for the block which we will build iteratively with each instruction
        let mut block_graph = ControlFlowGraph::new();

        // the length of this block in bytes
        let mut length: usize = 0;

        let mut successors = Vec::new();

        for instruction in instructions.iter() {

            if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
                
                let mut instruction_graph = ControlFlowGraph::new();

                try!(match instruction_id {
                    capstone::x86_insn::X86_INS_ADC  => semantics::adc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_ADD  => semantics::add(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_AND  => semantics::and(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BSF  => semantics::bsf(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BSR  => semantics::bsr(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BT   => semantics::bt(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BTC  => semantics::btc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BTR  => semantics::bts(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_BTS  => semantics::btr(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CALL => semantics::call(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CBW  => semantics::cbw(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CDQ  => semantics::cdq(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CLC  => semantics::clc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CLD  => semantics::cld(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CLI  => semantics::cli(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CMC  => semantics::cmc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CMP  => semantics::cmp(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CWD  => semantics::cwd(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_CWDE => semantics::cwde(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_DEC  => semantics::dec(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_DIV  => semantics::div(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_HLT  => semantics::nop(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_IDIV => semantics::idiv(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_IMUL => semantics::imul(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_INC  => semantics::inc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_INT  => semantics::int(&mut instruction_graph, &instruction),
                    // conditional jumps will only emit a brc if the destination is undetermined at
                    // translation time
                    capstone::x86_insn::X86_INS_JA   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JAE  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JB   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JBE  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JCXZ => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JECXZ => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JE   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JG   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JGE  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JL   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JLE  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JNE  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JNO  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JNP  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JNS  => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JO   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JP   => semantics::jcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_JS   => semantics::jcc(&mut instruction_graph, &instruction),
                    // unconditional jumps will only emit a brc if the destination is undetermined at
                    // translation time
                    capstone::x86_insn::X86_INS_JMP  => semantics::jmp(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_LEA  => semantics::lea(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_LEAVE => semantics::leave(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_LOOP => semantics::loop_(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_LOOPE => semantics::loop_(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_LOOPNE => semantics::loop_(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_MOV  => semantics::mov(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_MOVSX => semantics::movsx(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_MOVZX => semantics::movzx(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_MUL  => semantics::mul(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_NEG  => semantics::neg(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_NOP  => semantics::nop(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_NOT  => semantics::not(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_OR   => semantics::or(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_POP  => semantics::pop(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_PUSH => semantics::push(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_RET  => semantics::ret(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SAR  => semantics::sar(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SBB  => semantics::sbb(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETAE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETA => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETBE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETB => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETGE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETG => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETLE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETL => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETNE => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETNO => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETNP => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETNS => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETO => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETP => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SETS => semantics::setcc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SHR  => semantics::shr(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_STC => semantics::stc(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_STD => semantics::std(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_STI => semantics::std(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_STOSD => semantics::stosd(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_SUB => semantics::sub(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_TEST => semantics::test(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_XCHG => semantics::xchg(&mut instruction_graph, &instruction),
                    capstone::x86_insn::X86_INS_XOR => semantics::xor(&mut instruction_graph, &instruction),

                    _ => return Err(format!("Unhandled instruction {}", instruction.mnemonic).into())
                });

                let detail = semantics::details(&instruction)?;
                if detail.prefix.contains(&(capstone_sys::x86_prefix::X86_PREFIX_REP as u8)) {
                    semantics::rep_prefix(&mut instruction_graph, &instruction)?;
                }

                instruction_graph.set_address(Some(instruction.address));

                block_graph.append(&instruction_graph)?;

                length += instruction.size as usize;

                // instructions that terminate blocks
                match instruction_id {
                    // conditional branching instructions
                    capstone::x86_insn::X86_INS_JA |
                    capstone::x86_insn::X86_INS_JAE |
                    capstone::x86_insn::X86_INS_JB |
                    capstone::x86_insn::X86_INS_JBE |
                    capstone::x86_insn::X86_INS_JCXZ |
                    capstone::x86_insn::X86_INS_JECXZ |
                    capstone::x86_insn::X86_INS_JE |
                    capstone::x86_insn::X86_INS_JG |
                    capstone::x86_insn::X86_INS_JGE |
                    capstone::x86_insn::X86_INS_JL |
                    capstone::x86_insn::X86_INS_JLE |
                    capstone::x86_insn::X86_INS_JNO |
                    capstone::x86_insn::X86_INS_JNE |
                    capstone::x86_insn::X86_INS_JNP |
                    capstone::x86_insn::X86_INS_JNS |
                    capstone::x86_insn::X86_INS_JO |
                    capstone::x86_insn::X86_INS_JP |
                    capstone::x86_insn::X86_INS_JS => {
                        let condition = semantics::jcc_condition(&instruction)?;
                        successors.push((address + length as u64, Some(Expression::cmpeq(condition.clone(), expr_const(0, 1))?)));
                        let operand = semantics::details(&instruction)?.operands[0];
                        if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                            successors.push((operand.imm() as u64, Some(condition)));
                        }
                        break;
                    }
                    capstone::x86_insn::X86_INS_LOOP |
                    capstone::x86_insn::X86_INS_LOOPE |
                    capstone::x86_insn::X86_INS_LOOPNE => {
                        let condition = semantics::loop_condition(&instruction)?;
                        successors.push((address + length as u64, Some(Expression::cmpeq(condition.clone(), expr_const(0, 1))?)));
                        let operand = semantics::details(&instruction)?.operands[0];
                        if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                            successors.push((operand.imm() as u64, Some(condition)));
                        }
                        break;
                    }
                    // non-conditional branching instructions
                    capstone::x86_insn::X86_INS_JMP => {
                        let operand = semantics::details(&instruction)?.operands[0];
                        if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                            successors.push((operand.imm() as u64, None));
                        }
                        break;
                    }
                    // instructions without successors
                    capstone::x86_insn::X86_INS_HLT => break,
                    capstone::x86_insn::X86_INS_RET => break,
                    _ => ()
                }
            }
            else {
                bail!("not an x86 instruction")
            }
        }

        Ok(BlockTranslationResult::new(block_graph, address, length, successors))
    }
}
