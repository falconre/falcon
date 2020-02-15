//! Capstone-based translator for 32-bit x86.

use crate::error::*;
use crate::il::*;
use crate::translator::x86::mode::Mode;
use crate::translator::BlockTranslationResult;
use falcon_capstone::{capstone, capstone_sys};

use crate::translator::x86::semantics::Semantics;

fn unhandled_intrinsic(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(Intrinsic::new(
            instruction.mnemonic.clone(),
            format!("{} {}", instruction.mnemonic, instruction.op_str),
            Vec::new(),
            None,
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        ));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

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

pub(crate) fn translate_block(
    mode: Mode,
    bytes: &[u8],
    address: u64,
) -> Result<BlockTranslationResult> {
    let cs = match mode {
        Mode::X86 => capstone::Capstone::new(capstone::cs_arch::CS_ARCH_X86, capstone::CS_MODE_32),
        Mode::Amd64 => {
            capstone::Capstone::new(capstone::cs_arch::CS_ARCH_X86, capstone::CS_MODE_64)
        }
    }?;

    cs.option(
        capstone::cs_opt_type::CS_OPT_DETAIL,
        capstone::cs_opt_value::CS_OPT_ON,
    )
    .unwrap();

    // A vec which holds each lifted instruction in this block.
    let mut block_graphs: Vec<(u64, ControlFlowGraph)> = Vec::new();

    // the length of this block in bytes
    let mut length: usize = 0;

    let mut successors = Vec::new();

    let mut offset: usize = 0;

    loop {
        /* We must have at least 16 bytes left in the buffer. */
        // if bytes.len() - offset < 16 {
        //     successors.push((address + offset as u64, None));
        //     break;
        // }
        let disassembly_range = (offset)..bytes.len();
        let disassembly_bytes = bytes.get(disassembly_range).unwrap();
        let instructions = match cs.disasm(disassembly_bytes, address + offset as u64, 1) {
            Ok(instructions) => instructions,
            Err(e) => match e.code() {
                // We can reach this in a couple of circumstances.
                // One circumstance is there isn't enough data in disassembly_bytes
                // to disassemble the next instruction, in which case we need to return
                // and let the translator give us more bytes.
                //
                // Another case is just capstone has gone bonkers. In this case, return
                // a DisassemblyFailure error.
                //
                // We can tell the difference based on offset. If it's non-zero, first
                // case. If zero, second case.
                capstone_sys::cs_err::CS_ERR_OK => {
                    if offset == 0 {
                        return Err(ErrorKind::DisassemblyFailure.into());
                    }
                    successors.push((address + offset as u64, None));
                    break;
                }
                _ => return Err(ErrorKind::CapstoneError.into()),
            },
        };

        if instructions.count() == 0 {
            return Err("Capstone failed to disassemble any instruction".into());
        }

        let instruction = instructions.get(0).unwrap();

        if let capstone::InstrIdArch::X86(instruction_id) = instruction.id {
            let semantics = Semantics::new(&mode, &instruction);
            let mut instruction_graph = ControlFlowGraph::new();

            match instruction_id {
                capstone::x86_insn::X86_INS_ADC => semantics.adc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_ADD => semantics.add(&mut instruction_graph),
                capstone::x86_insn::X86_INS_AND => semantics.and(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BSF => semantics.bsf(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BSR => semantics.bsr(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BSWAP => semantics.bswap(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BT => semantics.bt(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BTC => semantics.btc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BTR => semantics.bts(&mut instruction_graph),
                capstone::x86_insn::X86_INS_BTS => semantics.btr(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CALL => semantics.call(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CBW => semantics.cbw(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CDQ => semantics.cdq(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CDQE => semantics.cdqe(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CLC => semantics.clc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CLD => semantics.cld(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CLI => semantics.cli(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CMC => semantics.cmc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CMOVA
                | capstone::x86_insn::X86_INS_CMOVAE
                | capstone::x86_insn::X86_INS_CMOVB
                | capstone::x86_insn::X86_INS_CMOVBE
                | capstone::x86_insn::X86_INS_CMOVE
                | capstone::x86_insn::X86_INS_CMOVG
                | capstone::x86_insn::X86_INS_CMOVGE
                | capstone::x86_insn::X86_INS_CMOVL
                | capstone::x86_insn::X86_INS_CMOVLE
                | capstone::x86_insn::X86_INS_CMOVNE
                | capstone::x86_insn::X86_INS_CMOVNO
                | capstone::x86_insn::X86_INS_CMOVNP
                | capstone::x86_insn::X86_INS_CMOVNS
                | capstone::x86_insn::X86_INS_CMOVO
                | capstone::x86_insn::X86_INS_CMOVP
                | capstone::x86_insn::X86_INS_CMOVS => semantics.cmovcc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CMP => semantics.cmp(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CMPSB => semantics.cmpsb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CMPXCHG => semantics.cmpxchg(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CPUID => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_CWD => semantics.cwd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_CWDE => semantics.cwde(&mut instruction_graph),
                capstone::x86_insn::X86_INS_DEC => semantics.dec(&mut instruction_graph),
                capstone::x86_insn::X86_INS_DIV => semantics.div(&mut instruction_graph),
                capstone::x86_insn::X86_INS_F2XM1 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FABS => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FADD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FADDP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FCHS => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FCOMP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FCOMPP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FDIV => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FDIVR => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FDIVRP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FFREE => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FILD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FINCSTP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FISTP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLDCW => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLD1 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLDENV => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLDL2E => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLDLN2 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FLDZ => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FDIVP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FMUL => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FMULP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FNCLEX => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FNSTENV => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FNSTCW => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FNSTSW => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FRNDINT => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSCALE => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FST => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSTP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSUB => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSUBP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSUBR => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FSUBRP => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FTST => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FUCOMI => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                #[cfg(not(feature = "capstone4"))]
                capstone::x86_insn::X86_INS_FUCOMPI => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FXAM => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FXCH => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_FYL2X => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_HLT => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_IDIV => semantics.idiv(&mut instruction_graph),
                capstone::x86_insn::X86_INS_IMUL => semantics.imul(&mut instruction_graph),
                capstone::x86_insn::X86_INS_INC => semantics.inc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_INT => semantics.int(&mut instruction_graph),
                capstone::x86_insn::X86_INS_INT3 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                // conditional jumps will only emit a brc if the destination is undetermined at
                // translation time
                capstone::x86_insn::X86_INS_JA
                | capstone::x86_insn::X86_INS_JAE
                | capstone::x86_insn::X86_INS_JB
                | capstone::x86_insn::X86_INS_JBE
                | capstone::x86_insn::X86_INS_JCXZ
                | capstone::x86_insn::X86_INS_JECXZ
                | capstone::x86_insn::X86_INS_JE
                | capstone::x86_insn::X86_INS_JG
                | capstone::x86_insn::X86_INS_JGE
                | capstone::x86_insn::X86_INS_JL
                | capstone::x86_insn::X86_INS_JLE
                | capstone::x86_insn::X86_INS_JNE
                | capstone::x86_insn::X86_INS_JNO
                | capstone::x86_insn::X86_INS_JNP
                | capstone::x86_insn::X86_INS_JNS
                | capstone::x86_insn::X86_INS_JO
                | capstone::x86_insn::X86_INS_JP
                | capstone::x86_insn::X86_INS_JS => semantics.nop(&mut instruction_graph),
                // unconditional jumps will only emit a brc if the destination is undetermined at
                // translation time
                capstone::x86_insn::X86_INS_JMP => semantics.jmp(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LEA => semantics.lea(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LEAVE => semantics.leave(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LODSB => semantics.lodsb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LODSD => semantics.lodsd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LOOP => semantics.loop_(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LOOPE => semantics.loop_(&mut instruction_graph),
                capstone::x86_insn::X86_INS_LOOPNE => semantics.loop_(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVLPD => semantics.movlpd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOV
                | capstone::x86_insn::X86_INS_MOVABS
                | capstone::x86_insn::X86_INS_MOVAPS
                | capstone::x86_insn::X86_INS_MOVAPD
                | capstone::x86_insn::X86_INS_MOVDQU
                | capstone::x86_insn::X86_INS_MOVNTI
                | capstone::x86_insn::X86_INS_MOVUPS => semantics.mov(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVD | capstone::x86_insn::X86_INS_MOVDQA => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_MOVQ => semantics.movq(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVSB
                | capstone::x86_insn::X86_INS_MOVSW
                | capstone::x86_insn::X86_INS_MOVSD
                | capstone::x86_insn::X86_INS_MOVSQ => semantics.movs(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVSX => semantics.movsx(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVSXD => semantics.movsx(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MOVZX => semantics.movzx(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MUL => semantics.mul(&mut instruction_graph),
                capstone::x86_insn::X86_INS_NEG => semantics.neg(&mut instruction_graph),
                capstone::x86_insn::X86_INS_NOP => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_NOT => semantics.not(&mut instruction_graph),
                capstone::x86_insn::X86_INS_OR => semantics.or(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PADDQ => semantics.paddq(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PAUSE => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PCMPEQB => semantics.pcmpeqb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PCMPEQD => semantics.pcmpeqd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PMOVMSKB => semantics.pmovmskb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PMINUB => semantics.pminub(&mut instruction_graph),
                capstone::x86_insn::X86_INS_POP => semantics.pop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PREFETCHT0 => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PREFETCHT1 => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PREFETCHT2 => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PREFETCHNTA => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PSHUFD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_PSUBQ => semantics.psubq(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PUNPCKLBW => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_PUNPCKLWD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_PUSH => semantics.push(&mut instruction_graph),
                capstone::x86_insn::X86_INS_PUSHFD => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_PXOR => semantics.pxor(&mut instruction_graph),
                capstone::x86_insn::X86_INS_RDTSC => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_RET => semantics.ret(&mut instruction_graph),
                capstone::x86_insn::X86_INS_ROL => semantics.rol(&mut instruction_graph),
                capstone::x86_insn::X86_INS_ROR => semantics.ror(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SAHF => semantics.sahf(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SAR => semantics.sar(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SBB => semantics.sbb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SCASB => semantics.scasb(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SCASW => semantics.scasw(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SETAE
                | capstone::x86_insn::X86_INS_SETA
                | capstone::x86_insn::X86_INS_SETBE
                | capstone::x86_insn::X86_INS_SETB
                | capstone::x86_insn::X86_INS_SETE
                | capstone::x86_insn::X86_INS_SETGE
                | capstone::x86_insn::X86_INS_SETG
                | capstone::x86_insn::X86_INS_SETLE
                | capstone::x86_insn::X86_INS_SETL
                | capstone::x86_insn::X86_INS_SETNE
                | capstone::x86_insn::X86_INS_SETNO
                | capstone::x86_insn::X86_INS_SETNP
                | capstone::x86_insn::X86_INS_SETNS
                | capstone::x86_insn::X86_INS_SETO
                | capstone::x86_insn::X86_INS_SETP
                | capstone::x86_insn::X86_INS_SETS => semantics.setcc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SHL => semantics.shl(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SHR => semantics.shr(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SHLD => semantics.shld(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SHRD => semantics.shrd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STC => semantics.stc(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STD => semantics.std(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STI => semantics.sti(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STOSB => semantics.stos(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STOSW => semantics.stos(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STOSD => semantics.stos(&mut instruction_graph),
                capstone::x86_insn::X86_INS_STOSQ => semantics.stos(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SUB => semantics.sub(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SYSCALL => semantics.syscall(&mut instruction_graph),
                capstone::x86_insn::X86_INS_SYSENTER => semantics.sysenter(&mut instruction_graph),
                capstone::x86_insn::X86_INS_TEST => semantics.test(&mut instruction_graph),
                capstone::x86_insn::X86_INS_WAIT => semantics.nop(&mut instruction_graph),
                capstone::x86_insn::X86_INS_UD2 => semantics.ud2(&mut instruction_graph),
                capstone::x86_insn::X86_INS_XADD => semantics.xadd(&mut instruction_graph),
                capstone::x86_insn::X86_INS_XCHG => semantics.xchg(&mut instruction_graph),
                capstone::x86_insn::X86_INS_XGETBV => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                capstone::x86_insn::X86_INS_XOR => semantics.xor(&mut instruction_graph),
                capstone::x86_insn::X86_INS_MFENCE
                | capstone::x86_insn::X86_INS_SFENCE
                | capstone::x86_insn::X86_INS_LFENCE => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                #[cfg(feature = "capstone4")]
                capstone::x86_insn::X86_INS_UD0 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }
                #[cfg(feature = "capstone4")]
                capstone::x86_insn::X86_INS_ENDBR32 | capstone::x86_insn::X86_INS_ENDBR64 => {
                    unhandled_intrinsic(&mut instruction_graph, &instruction)
                }

                _ => {
                    return Err(format!(
                        "Unhandled instruction {} {} at 0x{:x}",
                        instruction.mnemonic, instruction.op_str, instruction.address
                    )
                    .into())
                }
            }?;

            let detail = semantics.details()?;
            if detail
                .prefix
                .contains(&(capstone_sys::x86_prefix::X86_PREFIX_REP as u8))
            {
                semantics.rep_prefix(&mut instruction_graph)?;
            }
            if detail
                .prefix
                .contains(&(capstone_sys::x86_prefix::X86_PREFIX_REPNE as u8))
            {
                semantics.repne_prefix(&mut instruction_graph)?;
            }

            length += instruction.size as usize;

            // instructions that terminate blocks
            match instruction_id {
                // conditional branching instructions
                capstone::x86_insn::X86_INS_JA
                | capstone::x86_insn::X86_INS_JAE
                | capstone::x86_insn::X86_INS_JB
                | capstone::x86_insn::X86_INS_JBE
                | capstone::x86_insn::X86_INS_JCXZ
                | capstone::x86_insn::X86_INS_JECXZ
                | capstone::x86_insn::X86_INS_JE
                | capstone::x86_insn::X86_INS_JG
                | capstone::x86_insn::X86_INS_JGE
                | capstone::x86_insn::X86_INS_JL
                | capstone::x86_insn::X86_INS_JLE
                | capstone::x86_insn::X86_INS_JNO
                | capstone::x86_insn::X86_INS_JNE
                | capstone::x86_insn::X86_INS_JNP
                | capstone::x86_insn::X86_INS_JNS
                | capstone::x86_insn::X86_INS_JO
                | capstone::x86_insn::X86_INS_JP
                | capstone::x86_insn::X86_INS_JS => {
                    ensure_block_instruction(&mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    let condition = semantics.cc_condition()?;
                    successors.push((
                        address + length as u64,
                        Some(Expression::cmpeq(condition.clone(), expr_const(0, 1))?),
                    ));
                    let operand = semantics.details()?.operands[0];
                    if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                        successors.push((operand.imm() as u64, Some(condition)));
                    }
                    break;
                }
                capstone::x86_insn::X86_INS_LOOP
                | capstone::x86_insn::X86_INS_LOOPE
                | capstone::x86_insn::X86_INS_LOOPNE => {
                    ensure_block_instruction(&mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    let condition = semantics.loop_condition()?;
                    successors.push((
                        address + length as u64,
                        Some(Expression::cmpeq(condition.clone(), expr_const(0, 1))?),
                    ));
                    let operand = semantics.details()?.operands[0];
                    if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                        successors.push((operand.imm() as u64, Some(condition)));
                    }
                    break;
                }
                // non-conditional branching instructions
                capstone::x86_insn::X86_INS_JMP => {
                    ensure_block_instruction(&mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    let operand = semantics.details()?.operands[0];
                    if operand.type_ == capstone_sys::x86_op_type::X86_OP_IMM {
                        successors.push((operand.imm() as u64, None));
                    }
                    break;
                }
                // instructions without successors
                capstone::x86_insn::X86_INS_HLT | capstone::x86_insn::X86_INS_RET => {
                    ensure_block_instruction(&mut instruction_graph)?;
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));

                    break;
                }
                _ => {
                    instruction_graph.set_address(Some(instruction.address));
                    block_graphs.push((instruction.address, instruction_graph));
                }
            }
        } else {
            bail!("not an x86 instruction")
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
