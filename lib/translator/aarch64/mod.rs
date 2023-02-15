//! Capstone-based translator for AArch64.

use crate::architecture::Endian;
use crate::il::*;
use crate::translator::{BlockTranslationResult, Options, Translator};
use crate::Error;

mod register;
mod semantics;
#[cfg(test)]
mod test;

/// The little-endian AArch64 translator.
#[derive(Clone, Debug, Default)]
pub struct AArch64;

impl AArch64 {
    pub fn new() -> AArch64 {
        AArch64
    }
}

impl Translator for AArch64 {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translate_block(bytes, address, Endian::Little, options)
    }
}

/// The big-endian AArch64 translator.
#[derive(Clone, Debug, Default)]
pub struct AArch64Eb;

impl AArch64Eb {
    pub fn new() -> AArch64Eb {
        AArch64Eb
    }
}

impl Translator for AArch64Eb {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translate_block(bytes, address, Endian::Big, options)
    }
}

fn translate_block(
    bytes: &[u8],
    address: u64,
    _endian: Endian,
    options: &Options,
) -> Result<BlockTranslationResult, Error> {
    // A vec which holds each lifted instruction in this block.
    let mut block_graphs: Vec<(u64, ControlFlowGraph)> = Vec::new();

    // the length of this block in bytes.
    let mut length: usize = 0;

    // The successors which exit this block.
    let mut successors = Vec::new();

    // Offset in bytes to the next instruction from the address given at entry.
    let mut offset: usize = 0;

    loop {
        if offset >= bytes.len() {
            successors.push((address + offset as u64, None));
            break;
        }

        let disassembly_bytes = &bytes[offset..];
        let instruction = if let [b0, b1, b2, b3, ..] = *disassembly_bytes {
            let encoding = u32::from_le_bytes([b0, b1, b2, b3]);
            let instruction_address = address + offset as u64;
            let result = bad64::decode(encoding, instruction_address);

            if options.unsupported_are_intrinsics() {
                // Known undefined instructions will terminate the flow
                // TODO: `unsupported_are_intrinsics` might not be the right option
                if result.is_err() {
                    let mut instruction_graph = ControlFlowGraph::new();

                    semantics::undefined_intrinsic(encoding, &mut instruction_graph);

                    instruction_graph.set_address(Some(instruction_address));
                    block_graphs.push((instruction_address, instruction_graph));
                }
            }

            result?
        } else {
            return Err("Short read".into());
        };

        let mut instruction_graph = ControlFlowGraph::new();

        const TERMINATING: bool = true;
        const NON_TERMINATING: bool = false;

        macro_rules! instr {
            ($ident:ident, TERMINATING) => {{
                (
                    semantics::$ident(&mut instruction_graph, &mut successors, &instruction),
                    TERMINATING,
                )
            }};
            (b_cc($cond:expr), TERMINATING) => {{
                (
                    semantics::b_cc(&mut instruction_graph, &mut successors, &instruction, $cond),
                    TERMINATING,
                )
            }};

            ($ident:ident, NON_TERMINATING) => {{
                (
                    semantics::$ident(&mut instruction_graph, &instruction),
                    NON_TERMINATING,
                )
            }};
        }

        let (instruction_translate_result, terminating) = match instruction.op() {
            // Terminating
            bad64::Op::B => instr!(b, TERMINATING),
            bad64::Op::B_AL => instr!(b_cc(0b1110), TERMINATING),
            bad64::Op::B_CC => instr!(b_cc(0b0011), TERMINATING),
            bad64::Op::B_CS => instr!(b_cc(0b0010), TERMINATING),
            bad64::Op::B_EQ => instr!(b_cc(0b0000), TERMINATING),
            bad64::Op::B_GE => instr!(b_cc(0b1010), TERMINATING),
            bad64::Op::B_GT => instr!(b_cc(0b1100), TERMINATING),
            bad64::Op::B_HI => instr!(b_cc(0b1000), TERMINATING),
            bad64::Op::B_LE => instr!(b_cc(0b1101), TERMINATING),
            bad64::Op::B_LS => instr!(b_cc(0b1001), TERMINATING),
            bad64::Op::B_LT => instr!(b_cc(0b1011), TERMINATING),
            bad64::Op::B_MI => instr!(b_cc(0b0100), TERMINATING),
            bad64::Op::B_NE => instr!(b_cc(0b0001), TERMINATING),
            bad64::Op::B_NV => instr!(b_cc(0b1111), TERMINATING),
            bad64::Op::B_PL => instr!(b_cc(0b0101), TERMINATING),
            bad64::Op::B_VC => instr!(b_cc(0b0111), TERMINATING),
            bad64::Op::B_VS => instr!(b_cc(0b0110), TERMINATING),
            bad64::Op::BR => instr!(br, TERMINATING),
            bad64::Op::CBNZ => instr!(cbnz, TERMINATING),
            bad64::Op::CBZ => instr!(cbz, TERMINATING),
            bad64::Op::TBNZ => instr!(tbnz, TERMINATING),
            bad64::Op::TBZ => instr!(tbz, TERMINATING),
            bad64::Op::RET => instr!(ret, TERMINATING),

            bad64::Op::BRK
            | bad64::Op::ERET
            | bad64::Op::ERETAA
            | bad64::Op::ERETAB
            | bad64::Op::UDF => (Err(unsupported()), TERMINATING),

            // Non-terminating
            bad64::Op::ADD => instr!(add, NON_TERMINATING),
            bad64::Op::ADDS => instr!(adds, NON_TERMINATING),
            bad64::Op::BL => instr!(bl, NON_TERMINATING),
            bad64::Op::BLR => instr!(blr, NON_TERMINATING),
            bad64::Op::LDAR => instr!(ldar, NON_TERMINATING),
            bad64::Op::LDARB => instr!(ldarb, NON_TERMINATING),
            bad64::Op::LDARH => instr!(ldarh, NON_TERMINATING),
            bad64::Op::LDLAR => instr!(ldlar, NON_TERMINATING),
            bad64::Op::LDLARB => instr!(ldlarb, NON_TERMINATING),
            bad64::Op::LDLARH => instr!(ldlarh, NON_TERMINATING),
            bad64::Op::LDP => instr!(ldp, NON_TERMINATING),
            bad64::Op::LDNP => instr!(ldnp, NON_TERMINATING),
            bad64::Op::LDPSW => instr!(ldpsw, NON_TERMINATING),
            bad64::Op::LDR => instr!(ldr, NON_TERMINATING),
            bad64::Op::LDRB => instr!(ldrb, NON_TERMINATING),
            bad64::Op::LDRH => instr!(ldrh, NON_TERMINATING),
            bad64::Op::LDRSW => instr!(ldrsw, NON_TERMINATING),
            bad64::Op::LDRSB => instr!(ldrsb, NON_TERMINATING),
            bad64::Op::LDRSH => instr!(ldrsh, NON_TERMINATING),
            bad64::Op::LDUR => instr!(ldr, NON_TERMINATING),
            bad64::Op::LDURB => instr!(ldrb, NON_TERMINATING),
            bad64::Op::LDURH => instr!(ldrh, NON_TERMINATING),
            bad64::Op::LDURSW => instr!(ldrsw, NON_TERMINATING),
            bad64::Op::LDURSB => instr!(ldrsb, NON_TERMINATING),
            bad64::Op::LDURSH => instr!(ldrsh, NON_TERMINATING),
            bad64::Op::MOV => instr!(mov, NON_TERMINATING),
            bad64::Op::NOP => instr!(nop, NON_TERMINATING),
            bad64::Op::STP => instr!(stp, NON_TERMINATING),
            bad64::Op::STNP => instr!(stnp, NON_TERMINATING),
            bad64::Op::STR => instr!(str, NON_TERMINATING),
            bad64::Op::STRB => instr!(strb, NON_TERMINATING),
            bad64::Op::STRH => instr!(strh, NON_TERMINATING),
            bad64::Op::STUR => instr!(str, NON_TERMINATING),
            bad64::Op::STURB => instr!(strb, NON_TERMINATING),
            bad64::Op::STURH => instr!(strh, NON_TERMINATING),
            bad64::Op::STLLR => instr!(stllr, NON_TERMINATING),
            bad64::Op::STLLRB => instr!(stllrb, NON_TERMINATING),
            bad64::Op::STLLRH => instr!(stllrh, NON_TERMINATING),
            bad64::Op::STLR => instr!(stlr, NON_TERMINATING),
            bad64::Op::STLRB => instr!(stlrb, NON_TERMINATING),
            bad64::Op::STLRH => instr!(stlrh, NON_TERMINATING),
            bad64::Op::STLUR => instr!(stlr, NON_TERMINATING),
            bad64::Op::STLURB => instr!(stlrb, NON_TERMINATING),
            bad64::Op::STLURH => instr!(stlrh, NON_TERMINATING),
            bad64::Op::SUB => instr!(sub, NON_TERMINATING),
            bad64::Op::SUBS => instr!(subs, NON_TERMINATING),

            // Prefetch
            bad64::Op::PRFB
            | bad64::Op::PRFD
            | bad64::Op::PRFH
            | bad64::Op::PRFM
            | bad64::Op::PRFUM
            | bad64::Op::PRFW => instr!(nop, NON_TERMINATING),

            bad64::Op::ABS
            | bad64::Op::ADC
            | bad64::Op::ADCLB
            | bad64::Op::ADCLT
            | bad64::Op::ADCS
            | bad64::Op::ADDG
            | bad64::Op::ADDHN
            | bad64::Op::ADDHA
            | bad64::Op::ADDHN2
            | bad64::Op::ADDHNB
            | bad64::Op::ADDHNT
            | bad64::Op::ADDVA
            | bad64::Op::ADDP
            | bad64::Op::ADDPL
            | bad64::Op::ADDV
            | bad64::Op::ADDVL
            | bad64::Op::ADR
            | bad64::Op::ADRP
            | bad64::Op::AESD
            | bad64::Op::AESE
            | bad64::Op::AESIMC
            | bad64::Op::AESMC
            | bad64::Op::AND
            | bad64::Op::ANDS
            | bad64::Op::ANDV
            | bad64::Op::ASR
            | bad64::Op::ASRD
            | bad64::Op::ASRR
            | bad64::Op::ASRV
            | bad64::Op::AT
            | bad64::Op::AUTDA
            | bad64::Op::AUTDB
            | bad64::Op::AUTDZA
            | bad64::Op::AUTDZB
            | bad64::Op::AUTIA
            | bad64::Op::AUTIA1716
            | bad64::Op::AUTIASP
            | bad64::Op::AUTIAZ
            | bad64::Op::AUTIB
            | bad64::Op::AUTIB1716
            | bad64::Op::AUTIBSP
            | bad64::Op::AUTIBZ
            | bad64::Op::AUTIZA
            | bad64::Op::AUTIZB
            | bad64::Op::AXFLAG
            | bad64::Op::BCAX
            | bad64::Op::BDEP
            | bad64::Op::BEXT
            | bad64::Op::BFC
            | bad64::Op::BFCVT
            | bad64::Op::BFCVTN
            | bad64::Op::BFCVTN2
            | bad64::Op::BFCVTNT
            | bad64::Op::BFDOT
            | bad64::Op::BFI
            | bad64::Op::BFM
            | bad64::Op::BFMLAL
            | bad64::Op::BFMLALB
            | bad64::Op::BFMLALT
            | bad64::Op::BFMMLA
            | bad64::Op::BFXIL
            | bad64::Op::BGRP
            | bad64::Op::BIC
            | bad64::Op::BICS
            | bad64::Op::BIF
            | bad64::Op::BIT
            | bad64::Op::BLRAA
            | bad64::Op::BLRAAZ
            | bad64::Op::BLRAB
            | bad64::Op::BLRABZ
            | bad64::Op::BFMOPA
            | bad64::Op::BFMOPS
            | bad64::Op::BRAA
            | bad64::Op::BRAAZ
            | bad64::Op::BRAB
            | bad64::Op::BRABZ
            | bad64::Op::BRKA
            | bad64::Op::BRKAS
            | bad64::Op::BRKB
            | bad64::Op::BRKBS
            | bad64::Op::BRKN
            | bad64::Op::BRKNS
            | bad64::Op::BRKPA
            | bad64::Op::BRKPAS
            | bad64::Op::BRKPB
            | bad64::Op::BRKPBS
            | bad64::Op::BSL
            | bad64::Op::BSL1N
            | bad64::Op::BSL2N
            | bad64::Op::BTI
            | bad64::Op::CADD
            | bad64::Op::CAS
            | bad64::Op::CASA
            | bad64::Op::CASAB
            | bad64::Op::CASAH
            | bad64::Op::CASAL
            | bad64::Op::CASALB
            | bad64::Op::CASALH
            | bad64::Op::CASB
            | bad64::Op::CASH
            | bad64::Op::CASL
            | bad64::Op::CASLB
            | bad64::Op::CASLH
            | bad64::Op::CASP
            | bad64::Op::CASPA
            | bad64::Op::CASPAL
            | bad64::Op::CASPL
            | bad64::Op::CCMN
            | bad64::Op::CCMP
            | bad64::Op::CDOT
            | bad64::Op::CFINV
            | bad64::Op::CFP
            | bad64::Op::CINC
            | bad64::Op::CINV
            | bad64::Op::CLASTA
            | bad64::Op::CLASTB
            | bad64::Op::CLREX
            | bad64::Op::CLS
            | bad64::Op::CLZ
            | bad64::Op::CMEQ
            | bad64::Op::CMGE
            | bad64::Op::CMGT
            | bad64::Op::CMHI
            | bad64::Op::CMHS
            | bad64::Op::CMLA
            | bad64::Op::CMLE
            | bad64::Op::CMLT
            | bad64::Op::CMN
            | bad64::Op::CMP
            | bad64::Op::CMPEQ
            | bad64::Op::CMPGE
            | bad64::Op::CMPGT
            | bad64::Op::CMPHI
            | bad64::Op::CMPHS
            | bad64::Op::CMPLE
            | bad64::Op::CMPLO
            | bad64::Op::CMPLS
            | bad64::Op::CMPLT
            | bad64::Op::CMPNE
            | bad64::Op::CMPP
            | bad64::Op::CMTST
            | bad64::Op::CNEG
            | bad64::Op::CNOT
            | bad64::Op::CNT
            | bad64::Op::CNTB
            | bad64::Op::CNTD
            | bad64::Op::CNTH
            | bad64::Op::CNTP
            | bad64::Op::CNTW
            | bad64::Op::COMPACT
            | bad64::Op::CPP
            | bad64::Op::CPY
            | bad64::Op::CRC32B
            | bad64::Op::CRC32CB
            | bad64::Op::CRC32CH
            | bad64::Op::CRC32CW
            | bad64::Op::CRC32CX
            | bad64::Op::CRC32H
            | bad64::Op::CRC32W
            | bad64::Op::CRC32X
            | bad64::Op::CSDB
            | bad64::Op::CSEL
            | bad64::Op::CSET
            | bad64::Op::CSETM
            | bad64::Op::CSINC
            | bad64::Op::CSINV
            | bad64::Op::CSNEG
            | bad64::Op::CTERMEQ
            | bad64::Op::CTERMNE
            | bad64::Op::DC
            | bad64::Op::DCPS1
            | bad64::Op::DCPS2
            | bad64::Op::DCPS3
            | bad64::Op::DECB
            | bad64::Op::DECD
            | bad64::Op::DECH
            | bad64::Op::DECP
            | bad64::Op::DECW
            | bad64::Op::DGH
            | bad64::Op::DMB
            | bad64::Op::DRPS
            | bad64::Op::DSB
            | bad64::Op::DUP
            | bad64::Op::DUPM
            | bad64::Op::DVP
            | bad64::Op::EON
            | bad64::Op::EOR
            | bad64::Op::EOR3
            | bad64::Op::EORBT
            | bad64::Op::EORS
            | bad64::Op::EORTB
            | bad64::Op::EORV
            | bad64::Op::ESB
            | bad64::Op::EXT
            | bad64::Op::EXTR
            | bad64::Op::FABD
            | bad64::Op::FABS
            | bad64::Op::FACGE
            | bad64::Op::FACGT
            | bad64::Op::FACLE
            | bad64::Op::FACLT
            | bad64::Op::FADD
            | bad64::Op::FADDA
            | bad64::Op::FADDP
            | bad64::Op::FADDV
            | bad64::Op::FCADD
            | bad64::Op::FCCMP
            | bad64::Op::FCCMPE
            | bad64::Op::FCMEQ
            | bad64::Op::FCMGE
            | bad64::Op::FCMGT
            | bad64::Op::FCMLA
            | bad64::Op::FCMLE
            | bad64::Op::FCMLT
            | bad64::Op::FCMNE
            | bad64::Op::FCMP
            | bad64::Op::FCMPE
            | bad64::Op::FCMUO
            | bad64::Op::FCPY
            | bad64::Op::FCSEL
            | bad64::Op::FCVT
            | bad64::Op::FCVTAS
            | bad64::Op::FCVTAU
            | bad64::Op::FCVTL
            | bad64::Op::FCVTL2
            | bad64::Op::FCVTLT
            | bad64::Op::FCVTMS
            | bad64::Op::FCVTMU
            | bad64::Op::FCVTN
            | bad64::Op::FCVTN2
            | bad64::Op::FCVTNS
            | bad64::Op::FCVTNT
            | bad64::Op::FCVTNU
            | bad64::Op::FCVTPS
            | bad64::Op::FCVTPU
            | bad64::Op::FCVTX
            | bad64::Op::FCVTXN
            | bad64::Op::FCVTXN2
            | bad64::Op::FCVTXNT
            | bad64::Op::FCVTZS
            | bad64::Op::FCVTZU
            | bad64::Op::FDIV
            | bad64::Op::FDIVR
            | bad64::Op::FDUP
            | bad64::Op::FEXPA
            | bad64::Op::FJCVTZS
            | bad64::Op::FLOGB
            | bad64::Op::FMAD
            | bad64::Op::FMADD
            | bad64::Op::FMAX
            | bad64::Op::FMAXNM
            | bad64::Op::FMAXNMP
            | bad64::Op::FMAXNMV
            | bad64::Op::FMAXP
            | bad64::Op::FMAXV
            | bad64::Op::FMIN
            | bad64::Op::FMINNM
            | bad64::Op::FMINNMP
            | bad64::Op::FMINNMV
            | bad64::Op::FMINP
            | bad64::Op::FMINV
            | bad64::Op::FMLA
            | bad64::Op::FMLAL
            | bad64::Op::FMLAL2
            | bad64::Op::FMLALB
            | bad64::Op::FMLALT
            | bad64::Op::FMLS
            | bad64::Op::FMLSL
            | bad64::Op::FMLSL2
            | bad64::Op::FMLSLB
            | bad64::Op::FMLSLT
            | bad64::Op::FMMLA
            | bad64::Op::FMOPA
            | bad64::Op::FMOPS
            | bad64::Op::FMOV
            | bad64::Op::FMSB
            | bad64::Op::FMSUB
            | bad64::Op::FMUL
            | bad64::Op::FMULX
            | bad64::Op::FNEG
            | bad64::Op::FNMAD
            | bad64::Op::FNMADD
            | bad64::Op::FNMLA
            | bad64::Op::FNMLS
            | bad64::Op::FNMSB
            | bad64::Op::FNMSUB
            | bad64::Op::FNMUL
            | bad64::Op::FRECPE
            | bad64::Op::FRECPS
            | bad64::Op::FRECPX
            | bad64::Op::FRINT32X
            | bad64::Op::FRINT32Z
            | bad64::Op::FRINT64X
            | bad64::Op::FRINT64Z
            | bad64::Op::FRINTA
            | bad64::Op::FRINTI
            | bad64::Op::FRINTM
            | bad64::Op::FRINTN
            | bad64::Op::FRINTP
            | bad64::Op::FRINTX
            | bad64::Op::FRINTZ
            | bad64::Op::FRSQRTE
            | bad64::Op::FRSQRTS
            | bad64::Op::FSCALE
            | bad64::Op::FSQRT
            | bad64::Op::FSUB
            | bad64::Op::FSUBR
            | bad64::Op::FTMAD
            | bad64::Op::FTSMUL
            | bad64::Op::FTSSEL
            | bad64::Op::GMI
            | bad64::Op::HINT
            | bad64::Op::HISTCNT
            | bad64::Op::HISTSEG
            | bad64::Op::HLT
            | bad64::Op::HVC
            | bad64::Op::IC
            | bad64::Op::INCB
            | bad64::Op::INCD
            | bad64::Op::INCH
            | bad64::Op::INCP
            | bad64::Op::INCW
            | bad64::Op::INDEX
            | bad64::Op::INS
            | bad64::Op::INSR
            | bad64::Op::IRG
            | bad64::Op::ISB
            | bad64::Op::LASTA
            | bad64::Op::LASTB
            | bad64::Op::LD1
            | bad64::Op::LD1B
            | bad64::Op::LD1D
            | bad64::Op::LD1H
            | bad64::Op::LD1Q
            | bad64::Op::LD1R
            | bad64::Op::LD1RB
            | bad64::Op::LD1RD
            | bad64::Op::LD1RH
            | bad64::Op::LD1ROB
            | bad64::Op::LD1ROD
            | bad64::Op::LD1ROH
            | bad64::Op::LD1ROW
            | bad64::Op::LD1RQB
            | bad64::Op::LD1RQD
            | bad64::Op::LD1RQH
            | bad64::Op::LD1RQW
            | bad64::Op::LD1RSB
            | bad64::Op::LD1RSH
            | bad64::Op::LD1RSW
            | bad64::Op::LD1RW
            | bad64::Op::LD1SB
            | bad64::Op::LD1SH
            | bad64::Op::LD1SW
            | bad64::Op::LD1W
            | bad64::Op::LD2
            | bad64::Op::LD2B
            | bad64::Op::LD2D
            | bad64::Op::LD2H
            | bad64::Op::LD2R
            | bad64::Op::LD2W
            | bad64::Op::LD3
            | bad64::Op::LD3B
            | bad64::Op::LD3D
            | bad64::Op::LD3H
            | bad64::Op::LD3R
            | bad64::Op::LD3W
            | bad64::Op::LD4
            | bad64::Op::LD4B
            | bad64::Op::LD4D
            | bad64::Op::LD4H
            | bad64::Op::LD4R
            | bad64::Op::LD4W
            | bad64::Op::LD64B
            | bad64::Op::LDADD
            | bad64::Op::LDADDA
            | bad64::Op::LDADDAB
            | bad64::Op::LDADDAH
            | bad64::Op::LDADDAL
            | bad64::Op::LDADDALB
            | bad64::Op::LDADDALH
            | bad64::Op::LDADDB
            | bad64::Op::LDADDH
            | bad64::Op::LDADDL
            | bad64::Op::LDADDLB
            | bad64::Op::LDADDLH
            | bad64::Op::LDAPR
            | bad64::Op::LDAPRB
            | bad64::Op::LDAPRH
            | bad64::Op::LDAPUR
            | bad64::Op::LDAPURB
            | bad64::Op::LDAPURH
            | bad64::Op::LDAPURSB
            | bad64::Op::LDAPURSH
            | bad64::Op::LDAPURSW
            | bad64::Op::LDAXP
            | bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDCLR
            | bad64::Op::LDCLRA
            | bad64::Op::LDCLRAB
            | bad64::Op::LDCLRAH
            | bad64::Op::LDCLRAL
            | bad64::Op::LDCLRALB
            | bad64::Op::LDCLRALH
            | bad64::Op::LDCLRB
            | bad64::Op::LDCLRH
            | bad64::Op::LDCLRL
            | bad64::Op::LDCLRLB
            | bad64::Op::LDCLRLH
            | bad64::Op::LDEOR
            | bad64::Op::LDEORA
            | bad64::Op::LDEORAB
            | bad64::Op::LDEORAH
            | bad64::Op::LDEORAL
            | bad64::Op::LDEORALB
            | bad64::Op::LDEORALH
            | bad64::Op::LDEORB
            | bad64::Op::LDEORH
            | bad64::Op::LDEORL
            | bad64::Op::LDEORLB
            | bad64::Op::LDEORLH
            | bad64::Op::LDFF1B
            | bad64::Op::LDFF1D
            | bad64::Op::LDFF1H
            | bad64::Op::LDFF1SB
            | bad64::Op::LDFF1SH
            | bad64::Op::LDFF1SW
            | bad64::Op::LDFF1W
            | bad64::Op::LDG
            | bad64::Op::LDGM
            | bad64::Op::LDNF1B
            | bad64::Op::LDNF1D
            | bad64::Op::LDNF1H
            | bad64::Op::LDNF1SB
            | bad64::Op::LDNF1SH
            | bad64::Op::LDNF1SW
            | bad64::Op::LDNF1W
            | bad64::Op::LDNT1B
            | bad64::Op::LDNT1D
            | bad64::Op::LDNT1H
            | bad64::Op::LDNT1SB
            | bad64::Op::LDNT1SH
            | bad64::Op::LDNT1SW
            | bad64::Op::LDNT1W
            | bad64::Op::LDRAA
            | bad64::Op::LDRAB
            | bad64::Op::LDSET
            | bad64::Op::LDSETA
            | bad64::Op::LDSETAB
            | bad64::Op::LDSETAH
            | bad64::Op::LDSETAL
            | bad64::Op::LDSETALB
            | bad64::Op::LDSETALH
            | bad64::Op::LDSETB
            | bad64::Op::LDSETH
            | bad64::Op::LDSETL
            | bad64::Op::LDSETLB
            | bad64::Op::LDSETLH
            | bad64::Op::LDSMAX
            | bad64::Op::LDSMAXA
            | bad64::Op::LDSMAXAB
            | bad64::Op::LDSMAXAH
            | bad64::Op::LDSMAXAL
            | bad64::Op::LDSMAXALB
            | bad64::Op::LDSMAXALH
            | bad64::Op::LDSMAXB
            | bad64::Op::LDSMAXH
            | bad64::Op::LDSMAXL
            | bad64::Op::LDSMAXLB
            | bad64::Op::LDSMAXLH
            | bad64::Op::LDSMIN
            | bad64::Op::LDSMINA
            | bad64::Op::LDSMINAB
            | bad64::Op::LDSMINAH
            | bad64::Op::LDSMINAL
            | bad64::Op::LDSMINALB
            | bad64::Op::LDSMINALH
            | bad64::Op::LDSMINB
            | bad64::Op::LDSMINH
            | bad64::Op::LDSMINL
            | bad64::Op::LDSMINLB
            | bad64::Op::LDSMINLH
            | bad64::Op::LDTR
            | bad64::Op::LDTRB
            | bad64::Op::LDTRH
            | bad64::Op::LDTRSB
            | bad64::Op::LDTRSH
            | bad64::Op::LDTRSW
            | bad64::Op::LDUMAX
            | bad64::Op::LDUMAXA
            | bad64::Op::LDUMAXAB
            | bad64::Op::LDUMAXAH
            | bad64::Op::LDUMAXAL
            | bad64::Op::LDUMAXALB
            | bad64::Op::LDUMAXALH
            | bad64::Op::LDUMAXB
            | bad64::Op::LDUMAXH
            | bad64::Op::LDUMAXL
            | bad64::Op::LDUMAXLB
            | bad64::Op::LDUMAXLH
            | bad64::Op::LDUMIN
            | bad64::Op::LDUMINA
            | bad64::Op::LDUMINAB
            | bad64::Op::LDUMINAH
            | bad64::Op::LDUMINAL
            | bad64::Op::LDUMINALB
            | bad64::Op::LDUMINALH
            | bad64::Op::LDUMINB
            | bad64::Op::LDUMINH
            | bad64::Op::LDUMINL
            | bad64::Op::LDUMINLB
            | bad64::Op::LDUMINLH
            | bad64::Op::LDXP
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
            | bad64::Op::LSL
            | bad64::Op::LSLR
            | bad64::Op::LSLV
            | bad64::Op::LSR
            | bad64::Op::LSRR
            | bad64::Op::LSRV
            | bad64::Op::MAD
            | bad64::Op::MADD
            | bad64::Op::MATCH
            | bad64::Op::MLA
            | bad64::Op::MLS
            | bad64::Op::MNEG
            | bad64::Op::MOVA
            | bad64::Op::MOVI
            | bad64::Op::MOVK
            | bad64::Op::MOVN
            | bad64::Op::MOVPRFX
            | bad64::Op::MOVS
            | bad64::Op::MOVZ
            | bad64::Op::MRS
            | bad64::Op::MSB
            | bad64::Op::MSR
            | bad64::Op::MSUB
            | bad64::Op::MUL
            | bad64::Op::MVN
            | bad64::Op::MVNI
            | bad64::Op::NAND
            | bad64::Op::NANDS
            | bad64::Op::NBSL
            | bad64::Op::NEG
            | bad64::Op::NEGS
            | bad64::Op::NGC
            | bad64::Op::NGCS
            | bad64::Op::NMATCH
            | bad64::Op::NOR
            | bad64::Op::NORS
            | bad64::Op::NOT
            | bad64::Op::NOTS
            | bad64::Op::ORN
            | bad64::Op::ORNS
            | bad64::Op::ORR
            | bad64::Op::ORRS
            | bad64::Op::ORV
            | bad64::Op::PACDA
            | bad64::Op::PACDB
            | bad64::Op::PACDZA
            | bad64::Op::PACDZB
            | bad64::Op::PACGA
            | bad64::Op::PACIA
            | bad64::Op::PACIA1716
            | bad64::Op::PACIASP
            | bad64::Op::PACIAZ
            | bad64::Op::PACIB
            | bad64::Op::PACIB1716
            | bad64::Op::PACIBSP
            | bad64::Op::PACIBZ
            | bad64::Op::PACIZA
            | bad64::Op::PACIZB
            | bad64::Op::PFALSE
            | bad64::Op::PFIRST
            | bad64::Op::PMUL
            | bad64::Op::PMULL
            | bad64::Op::PMULL2
            | bad64::Op::PMULLB
            | bad64::Op::PMULLT
            | bad64::Op::PNEXT
            | bad64::Op::PSB
            | bad64::Op::PSSBB
            | bad64::Op::PTEST
            | bad64::Op::PTRUE
            | bad64::Op::PTRUES
            | bad64::Op::PUNPKHI
            | bad64::Op::PUNPKLO
            | bad64::Op::RADDHN
            | bad64::Op::RADDHN2
            | bad64::Op::RADDHNB
            | bad64::Op::RADDHNT
            | bad64::Op::RAX1
            | bad64::Op::RBIT
            | bad64::Op::RDFFR
            | bad64::Op::RDFFRS
            | bad64::Op::RDVL
            | bad64::Op::RETAA
            | bad64::Op::RETAB
            | bad64::Op::REV
            | bad64::Op::REV16
            | bad64::Op::REV32
            | bad64::Op::REV64
            | bad64::Op::REVB
            | bad64::Op::REVD
            | bad64::Op::REVH
            | bad64::Op::REVW
            | bad64::Op::RMIF
            | bad64::Op::ROR
            | bad64::Op::RORV
            | bad64::Op::RSHRN
            | bad64::Op::RSHRN2
            | bad64::Op::RSHRNB
            | bad64::Op::RSHRNT
            | bad64::Op::RSUBHN
            | bad64::Op::RSUBHN2
            | bad64::Op::RSUBHNB
            | bad64::Op::RSUBHNT
            | bad64::Op::SABA
            | bad64::Op::SABAL
            | bad64::Op::SABAL2
            | bad64::Op::SABALB
            | bad64::Op::SABALT
            | bad64::Op::SABD
            | bad64::Op::SABDL
            | bad64::Op::SABDL2
            | bad64::Op::SABDLB
            | bad64::Op::SABDLT
            | bad64::Op::SADALP
            | bad64::Op::SADDL
            | bad64::Op::SADDL2
            | bad64::Op::SADDLB
            | bad64::Op::SADDLBT
            | bad64::Op::SADDLP
            | bad64::Op::SADDLT
            | bad64::Op::SADDLV
            | bad64::Op::SADDV
            | bad64::Op::SADDW
            | bad64::Op::SADDW2
            | bad64::Op::SADDWB
            | bad64::Op::SADDWT
            | bad64::Op::SB
            | bad64::Op::SBC
            | bad64::Op::SBCLB
            | bad64::Op::SBCLT
            | bad64::Op::SBCS
            | bad64::Op::SBFIZ
            | bad64::Op::SBFM
            | bad64::Op::SBFX
            | bad64::Op::SCLAMP
            | bad64::Op::SCVTF
            | bad64::Op::SDIV
            | bad64::Op::SDIVR
            | bad64::Op::SDOT
            | bad64::Op::SEL
            | bad64::Op::SETF16
            | bad64::Op::SETF8
            | bad64::Op::SETFFR
            | bad64::Op::SEV
            | bad64::Op::SEVL
            | bad64::Op::SHA1C
            | bad64::Op::SHA1H
            | bad64::Op::SHA1M
            | bad64::Op::SHA1P
            | bad64::Op::SHA1SU0
            | bad64::Op::SHA1SU1
            | bad64::Op::SHA256H
            | bad64::Op::SHA256H2
            | bad64::Op::SHA256SU0
            | bad64::Op::SHA256SU1
            | bad64::Op::SHA512H
            | bad64::Op::SHA512H2
            | bad64::Op::SHA512SU0
            | bad64::Op::SHA512SU1
            | bad64::Op::SHADD
            | bad64::Op::SHL
            | bad64::Op::SHLL
            | bad64::Op::SHLL2
            | bad64::Op::SHRN
            | bad64::Op::SHRN2
            | bad64::Op::SHRNB
            | bad64::Op::SHRNT
            | bad64::Op::SHSUB
            | bad64::Op::SHSUBR
            | bad64::Op::SLI
            | bad64::Op::SM3PARTW1
            | bad64::Op::SM3PARTW2
            | bad64::Op::SM3SS1
            | bad64::Op::SM3TT1A
            | bad64::Op::SM3TT1B
            | bad64::Op::SM3TT2A
            | bad64::Op::SM3TT2B
            | bad64::Op::SM4E
            | bad64::Op::SM4EKEY
            | bad64::Op::SMADDL
            | bad64::Op::SMAX
            | bad64::Op::SMAXP
            | bad64::Op::SMAXV
            | bad64::Op::SMC
            | bad64::Op::SMIN
            | bad64::Op::SMINP
            | bad64::Op::SMINV
            | bad64::Op::SMLAL
            | bad64::Op::SMLAL2
            | bad64::Op::SMLALB
            | bad64::Op::SMLALT
            | bad64::Op::SMLSL
            | bad64::Op::SMLSL2
            | bad64::Op::SMLSLB
            | bad64::Op::SMLSLT
            | bad64::Op::SMMLA
            | bad64::Op::SMNEGL
            | bad64::Op::SMOPA
            | bad64::Op::SMOPS
            | bad64::Op::SMOV
            | bad64::Op::SMSTART
            | bad64::Op::SMSTOP
            | bad64::Op::SMSUBL
            | bad64::Op::SMULH
            | bad64::Op::SMULL
            | bad64::Op::SMULL2
            | bad64::Op::SMULLB
            | bad64::Op::SMULLT
            | bad64::Op::SPLICE
            | bad64::Op::SQABS
            | bad64::Op::SQADD
            | bad64::Op::SQCADD
            | bad64::Op::SQDECB
            | bad64::Op::SQDECD
            | bad64::Op::SQDECH
            | bad64::Op::SQDECP
            | bad64::Op::SQDECW
            | bad64::Op::SQDMLAL
            | bad64::Op::SQDMLAL2
            | bad64::Op::SQDMLALB
            | bad64::Op::SQDMLALBT
            | bad64::Op::SQDMLALT
            | bad64::Op::SQDMLSL
            | bad64::Op::SQDMLSL2
            | bad64::Op::SQDMLSLB
            | bad64::Op::SQDMLSLBT
            | bad64::Op::SQDMLSLT
            | bad64::Op::SQDMULH
            | bad64::Op::SQDMULL
            | bad64::Op::SQDMULL2
            | bad64::Op::SQDMULLB
            | bad64::Op::SQDMULLT
            | bad64::Op::SQINCB
            | bad64::Op::SQINCD
            | bad64::Op::SQINCH
            | bad64::Op::SQINCP
            | bad64::Op::SQINCW
            | bad64::Op::SQNEG
            | bad64::Op::SQRDCMLAH
            | bad64::Op::SQRDMLAH
            | bad64::Op::SQRDMLSH
            | bad64::Op::SQRDMULH
            | bad64::Op::SQRSHL
            | bad64::Op::SQRSHLR
            | bad64::Op::SQRSHRN
            | bad64::Op::SQRSHRN2
            | bad64::Op::SQRSHRNB
            | bad64::Op::SQRSHRNT
            | bad64::Op::SQRSHRUN
            | bad64::Op::SQRSHRUN2
            | bad64::Op::SQRSHRUNB
            | bad64::Op::SQRSHRUNT
            | bad64::Op::SQSHL
            | bad64::Op::SQSHLR
            | bad64::Op::SQSHLU
            | bad64::Op::SQSHRN
            | bad64::Op::SQSHRN2
            | bad64::Op::SQSHRNB
            | bad64::Op::SQSHRNT
            | bad64::Op::SQSHRUN
            | bad64::Op::SQSHRUN2
            | bad64::Op::SQSHRUNB
            | bad64::Op::SQSHRUNT
            | bad64::Op::SQSUB
            | bad64::Op::SQSUBR
            | bad64::Op::SQXTN
            | bad64::Op::SQXTN2
            | bad64::Op::SQXTNB
            | bad64::Op::SQXTNT
            | bad64::Op::SQXTUN
            | bad64::Op::SQXTUN2
            | bad64::Op::SQXTUNB
            | bad64::Op::SQXTUNT
            | bad64::Op::SRHADD
            | bad64::Op::SRI
            | bad64::Op::SRSHL
            | bad64::Op::SRSHLR
            | bad64::Op::SRSHR
            | bad64::Op::SRSRA
            | bad64::Op::SSBB
            | bad64::Op::SSHL
            | bad64::Op::SSHLL
            | bad64::Op::SSHLL2
            | bad64::Op::SSHLLB
            | bad64::Op::SSHLLT
            | bad64::Op::SSHR
            | bad64::Op::SSRA
            | bad64::Op::SSUBL
            | bad64::Op::SSUBL2
            | bad64::Op::SSUBLB
            | bad64::Op::SSUBLBT
            | bad64::Op::SSUBLT
            | bad64::Op::SSUBLTB
            | bad64::Op::SSUBW
            | bad64::Op::SSUBW2
            | bad64::Op::SSUBWB
            | bad64::Op::SSUBWT
            | bad64::Op::ST1
            | bad64::Op::ST1B
            | bad64::Op::ST1D
            | bad64::Op::ST1H
            | bad64::Op::ST1Q
            | bad64::Op::ST1W
            | bad64::Op::ST2
            | bad64::Op::ST2B
            | bad64::Op::ST2D
            | bad64::Op::ST2G
            | bad64::Op::ST2H
            | bad64::Op::ST2W
            | bad64::Op::ST3
            | bad64::Op::ST3B
            | bad64::Op::ST3D
            | bad64::Op::ST3H
            | bad64::Op::ST3W
            | bad64::Op::ST4
            | bad64::Op::ST4B
            | bad64::Op::ST4D
            | bad64::Op::ST4H
            | bad64::Op::ST4W
            | bad64::Op::ST64B
            | bad64::Op::ST64BV
            | bad64::Op::ST64BV0
            | bad64::Op::STADD
            | bad64::Op::STADDB
            | bad64::Op::STADDH
            | bad64::Op::STADDL
            | bad64::Op::STADDLB
            | bad64::Op::STADDLH
            | bad64::Op::STCLR
            | bad64::Op::STCLRB
            | bad64::Op::STCLRH
            | bad64::Op::STCLRL
            | bad64::Op::STCLRLB
            | bad64::Op::STCLRLH
            | bad64::Op::STEOR
            | bad64::Op::STEORB
            | bad64::Op::STEORH
            | bad64::Op::STEORL
            | bad64::Op::STEORLB
            | bad64::Op::STEORLH
            | bad64::Op::STG
            | bad64::Op::STGM
            | bad64::Op::STGP
            | bad64::Op::STLXP
            | bad64::Op::STLXR
            | bad64::Op::STLXRB
            | bad64::Op::STLXRH
            | bad64::Op::STNT1B
            | bad64::Op::STNT1D
            | bad64::Op::STNT1H
            | bad64::Op::STNT1W
            | bad64::Op::STSET
            | bad64::Op::STSETB
            | bad64::Op::STSETH
            | bad64::Op::STSETL
            | bad64::Op::STSETLB
            | bad64::Op::STSETLH
            | bad64::Op::STSMAX
            | bad64::Op::STSMAXB
            | bad64::Op::STSMAXH
            | bad64::Op::STSMAXL
            | bad64::Op::STSMAXLB
            | bad64::Op::STSMAXLH
            | bad64::Op::STSMIN
            | bad64::Op::STSMINB
            | bad64::Op::STSMINH
            | bad64::Op::STSMINL
            | bad64::Op::STSMINLB
            | bad64::Op::STSMINLH
            | bad64::Op::STTR
            | bad64::Op::STTRB
            | bad64::Op::STTRH
            | bad64::Op::STUMAX
            | bad64::Op::STUMAXB
            | bad64::Op::STUMAXH
            | bad64::Op::STUMAXL
            | bad64::Op::STUMAXLB
            | bad64::Op::STUMAXLH
            | bad64::Op::STUMIN
            | bad64::Op::STUMINB
            | bad64::Op::STUMINH
            | bad64::Op::STUMINL
            | bad64::Op::STUMINLB
            | bad64::Op::STUMINLH
            | bad64::Op::STXP
            | bad64::Op::STXR
            | bad64::Op::STXRB
            | bad64::Op::STXRH
            | bad64::Op::STZ2G
            | bad64::Op::STZG
            | bad64::Op::STZGM
            | bad64::Op::SUBG
            | bad64::Op::SUBHN
            | bad64::Op::SUBHN2
            | bad64::Op::SUBHNB
            | bad64::Op::SUBHNT
            | bad64::Op::SUBP
            | bad64::Op::SUBPS
            | bad64::Op::SUBR
            | bad64::Op::SUDOT
            | bad64::Op::SUMOPA
            | bad64::Op::SUMOPS
            | bad64::Op::SUNPKHI
            | bad64::Op::SUNPKLO
            | bad64::Op::SUQADD
            | bad64::Op::SVC
            | bad64::Op::SWP
            | bad64::Op::SWPA
            | bad64::Op::SWPAB
            | bad64::Op::SWPAH
            | bad64::Op::SWPAL
            | bad64::Op::SWPALB
            | bad64::Op::SWPALH
            | bad64::Op::SWPB
            | bad64::Op::SWPH
            | bad64::Op::SWPL
            | bad64::Op::SWPLB
            | bad64::Op::SWPLH
            | bad64::Op::SXTB
            | bad64::Op::SXTH
            | bad64::Op::SXTL
            | bad64::Op::SXTL2
            | bad64::Op::SXTW
            | bad64::Op::SYS
            | bad64::Op::SYSL
            | bad64::Op::TBL
            | bad64::Op::TBX
            | bad64::Op::TCANCEL
            | bad64::Op::TCOMMIT
            | bad64::Op::TLBI
            | bad64::Op::TRN1
            | bad64::Op::TRN2
            | bad64::Op::TSB
            | bad64::Op::TST
            | bad64::Op::TSTART
            | bad64::Op::TTEST
            | bad64::Op::UABA
            | bad64::Op::UABAL
            | bad64::Op::UABAL2
            | bad64::Op::UABALB
            | bad64::Op::UABALT
            | bad64::Op::UABD
            | bad64::Op::UABDL
            | bad64::Op::UABDL2
            | bad64::Op::UABDLB
            | bad64::Op::UABDLT
            | bad64::Op::UADALP
            | bad64::Op::UADDL
            | bad64::Op::UADDL2
            | bad64::Op::UADDLB
            | bad64::Op::UADDLP
            | bad64::Op::UADDLT
            | bad64::Op::UADDLV
            | bad64::Op::UADDV
            | bad64::Op::UADDW
            | bad64::Op::UADDW2
            | bad64::Op::UADDWB
            | bad64::Op::UADDWT
            | bad64::Op::UBFIZ
            | bad64::Op::UBFM
            | bad64::Op::UBFX
            | bad64::Op::UCVTF
            | bad64::Op::UCLAMP
            | bad64::Op::UDIV
            | bad64::Op::UDIVR
            | bad64::Op::UDOT
            | bad64::Op::UHADD
            | bad64::Op::UHSUB
            | bad64::Op::UHSUBR
            | bad64::Op::UMADDL
            | bad64::Op::UMAX
            | bad64::Op::UMAXP
            | bad64::Op::UMAXV
            | bad64::Op::UMIN
            | bad64::Op::UMINP
            | bad64::Op::UMINV
            | bad64::Op::UMLAL
            | bad64::Op::UMLAL2
            | bad64::Op::UMLALB
            | bad64::Op::UMLALT
            | bad64::Op::UMLSL
            | bad64::Op::UMLSL2
            | bad64::Op::UMLSLB
            | bad64::Op::UMLSLT
            | bad64::Op::UMMLA
            | bad64::Op::UMNEGL
            | bad64::Op::UMOV
            | bad64::Op::UMOPA
            | bad64::Op::UMOPS
            | bad64::Op::UMSUBL
            | bad64::Op::UMULH
            | bad64::Op::UMULL
            | bad64::Op::UMULL2
            | bad64::Op::UMULLB
            | bad64::Op::UMULLT
            | bad64::Op::USMOPA
            | bad64::Op::USMOPS
            | bad64::Op::UQADD
            | bad64::Op::UQDECB
            | bad64::Op::UQDECD
            | bad64::Op::UQDECH
            | bad64::Op::UQDECP
            | bad64::Op::UQDECW
            | bad64::Op::UQINCB
            | bad64::Op::UQINCD
            | bad64::Op::UQINCH
            | bad64::Op::UQINCP
            | bad64::Op::UQINCW
            | bad64::Op::UQRSHL
            | bad64::Op::UQRSHLR
            | bad64::Op::UQRSHRN
            | bad64::Op::UQRSHRN2
            | bad64::Op::UQRSHRNB
            | bad64::Op::UQRSHRNT
            | bad64::Op::UQSHL
            | bad64::Op::UQSHLR
            | bad64::Op::UQSHRN
            | bad64::Op::UQSHRN2
            | bad64::Op::UQSHRNB
            | bad64::Op::UQSHRNT
            | bad64::Op::UQSUB
            | bad64::Op::UQSUBR
            | bad64::Op::UQXTN
            | bad64::Op::UQXTN2
            | bad64::Op::UQXTNB
            | bad64::Op::UQXTNT
            | bad64::Op::URECPE
            | bad64::Op::URHADD
            | bad64::Op::URSHL
            | bad64::Op::URSHLR
            | bad64::Op::URSHR
            | bad64::Op::URSQRTE
            | bad64::Op::URSRA
            | bad64::Op::USDOT
            | bad64::Op::USHL
            | bad64::Op::USHLL
            | bad64::Op::USHLL2
            | bad64::Op::USHLLB
            | bad64::Op::USHLLT
            | bad64::Op::USHR
            | bad64::Op::USMMLA
            | bad64::Op::USQADD
            | bad64::Op::USRA
            | bad64::Op::USUBL
            | bad64::Op::USUBL2
            | bad64::Op::USUBLB
            | bad64::Op::USUBLT
            | bad64::Op::USUBW
            | bad64::Op::USUBW2
            | bad64::Op::USUBWB
            | bad64::Op::USUBWT
            | bad64::Op::UUNPKHI
            | bad64::Op::UUNPKLO
            | bad64::Op::UXTB
            | bad64::Op::UXTH
            | bad64::Op::UXTL
            | bad64::Op::UXTL2
            | bad64::Op::UXTW
            | bad64::Op::UZP1
            | bad64::Op::UZP2
            | bad64::Op::WFE
            | bad64::Op::WFET
            | bad64::Op::WFI
            | bad64::Op::WFIT
            | bad64::Op::WHILEGE
            | bad64::Op::WHILEGT
            | bad64::Op::WHILEHI
            | bad64::Op::WHILEHS
            | bad64::Op::WHILELE
            | bad64::Op::WHILELO
            | bad64::Op::WHILELS
            | bad64::Op::WHILELT
            | bad64::Op::WHILERW
            | bad64::Op::WHILEWR
            | bad64::Op::WRFFR
            | bad64::Op::XAFLAG
            | bad64::Op::XAR
            | bad64::Op::XPACD
            | bad64::Op::XPACI
            | bad64::Op::XPACLRI
            | bad64::Op::XTN
            | bad64::Op::XTN2
            | bad64::Op::YIELD
            | bad64::Op::ZERO
            | bad64::Op::ZIP1
            | bad64::Op::ZIP2 => (Err(unsupported()), NON_TERMINATING),
        };

        match instruction_translate_result {
            Ok(()) => {}
            Err(UnsupportedError(_)) => {
                if options.unsupported_are_intrinsics() {
                    semantics::unhandled_intrinsic(
                        &disassembly_bytes[..4],
                        &mut instruction_graph,
                        &instruction,
                    );
                } else {
                    return Err(format!(
                        "Unhandled instruction {:#x} ({}) at {:#x}",
                        instruction.opcode(),
                        instruction,
                        instruction.address()
                    )
                    .into());
                }
            }
        }

        instruction_graph.set_address(Some(instruction.address()));
        block_graphs.push((instruction.address(), instruction_graph));

        if terminating == TERMINATING {
            break;
        }

        length += 4;
        offset += 4;
    }

    Ok(BlockTranslationResult::new(
        block_graphs,
        address,
        length,
        successors,
    ))
}

#[derive(Debug)]
struct UnsupportedError(());

#[inline]
fn unsupported() -> UnsupportedError {
    UnsupportedError(())
}
