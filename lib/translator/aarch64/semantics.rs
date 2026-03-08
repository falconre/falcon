use crate::il;
use crate::translator::aarch64::{
    register::{get_register, AArch64Register},
    unsupported, UnsupportedError,
};

type Result<T> = std::result::Result<T, UnsupportedError>;

/// Get the scalar for a well-known register.
macro_rules! scalar {
    ("x30") => {
        // the link register
        il::scalar("x30", 64)
    };
    ("n") => {
        il::scalar("n", 1)
    };
    ("z") => {
        il::scalar("z", 1)
    };
    ("c") => {
        il::scalar("c", 1)
    };
    ("v") => {
        il::scalar("v", 1)
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

/// A convenience function for turning unhandled instructions into intrinsics
pub(super) fn unhandled_intrinsic(
    bytes: &[u8],
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

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

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();
}

/// A convenience function for turning undefined instructions into intrinsics
pub(super) fn undefined_intrinsic(bytes: u32, control_flow_graph: &mut il::ControlFlowGraph) {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.intrinsic(il::Intrinsic::new(
            ".word",
            format!(".word {:#x}", bytes),
            Vec::new(),
            None,
            None,
            bytes.to_le_bytes().to_vec(),
        ));

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();
}

/// Only supports non-memory operands.
/// `out_bits` is only used for zero/sign-extension modifier.
fn operand_load(
    _block: &mut il::Block,
    opr: &bad64::Operand,
    out_bits: usize,
) -> Result<il::Expression> {
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => Ok(get_register(*reg)?.get()),
        bad64::Operand::Reg {
            reg,
            arrspec: Some(arrspec),
        } => {
            let reg = get_register(*reg)?;
            let reg_value = reg.get();
            assert_eq!(reg.bits(), 128);

            let (shift, width) = arr_spec_offset_width(arrspec);

            let value =
                il::Expression::shr(reg_value, il::expr_const(shift as u64, reg.bits())).unwrap();
            Ok(resize_zext(width, value))
        }
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
            shift(get_register(*reg)?.get(), shift_, out_bits)
        }
        bad64::Operand::Label(imm) => Ok(il::expr_const(imm_to_u64(imm), 64)),
        bad64::Operand::FImm32(_)
        | bad64::Operand::SmeTile { .. }
        | bad64::Operand::AccumArray { .. }
        | bad64::Operand::IndexedElement { .. }
        | bad64::Operand::QualReg { .. }
        | bad64::Operand::MultiReg { .. }
        | bad64::Operand::SysReg(_)
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => Err(unsupported()),
        bad64::Operand::MemReg(_)
        | bad64::Operand::MemOffset { .. }
        | bad64::Operand::MemPreIdx { .. }
        | bad64::Operand::MemPostIdxReg(_)
        | bad64::Operand::MemPostIdxImm { .. }
        | bad64::Operand::MemExt { .. } => unreachable!("Memory operand is unexpected here"),
    }
}

/// Get an immediate operand of type `u64`. Will panic if it's not an immediate
/// operand. A signed immediate is bit-cast to an unsigned one.
///
/// **Shifted immediates aren't supported.**
fn operand_imm_u64(opr: &bad64::Operand) -> u64 {
    match opr {
        bad64::Operand::Imm32 { imm, shift: None } | bad64::Operand::Imm64 { imm, shift: None } => {
            imm_to_u64(imm)
        }
        bad64::Operand::Imm32 { shift: Some(_), .. }
        | bad64::Operand::Imm64 { shift: Some(_), .. } => {
            unreachable!("unshifted immediate expected")
        }
        bad64::Operand::Reg { .. }
        | bad64::Operand::SmeTile { .. }
        | bad64::Operand::AccumArray { .. }
        | bad64::Operand::IndexedElement { .. }
        | bad64::Operand::ShiftReg { .. }
        | bad64::Operand::FImm32(_)
        | bad64::Operand::QualReg { .. }
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
        | bad64::Operand::StrImm { .. } => unreachable!("immediate expected"),
    }
}

fn operand_store(block: &mut il::Block, opr: &bad64::Operand, value: il::Expression) -> Result<()> {
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => get_register(*reg)?.set(block, value),
        bad64::Operand::Reg {
            reg,
            arrspec: Some(arrspec),
        } => {
            let reg = get_register(*reg)?;
            assert_eq!(reg.bits(), 128);

            let (shift, width) = arr_spec_offset_width(arrspec);
            let is_indexed = is_arr_spec_indexed(arrspec);

            if is_indexed {
                // Replace only the selected element. First mask the unselected
                // bits of the old value...
                let masked_lower = if shift > 0 {
                    assert!(shift < reg.bits());
                    Some(
                        il::Expression::zext(
                            reg.bits(),
                            il::Expression::trun(shift, reg.get()).unwrap(),
                        )
                        .unwrap(),
                    )
                } else {
                    None
                };
                let masked_upper = if shift + width < reg.bits() {
                    Some(
                        il::Expression::shl(
                            il::Expression::shr(
                                reg.get(),
                                il::expr_const((shift + width) as u64, reg.bits()),
                            )
                            .unwrap(),
                            il::expr_const((shift + width) as u64, reg.bits()),
                        )
                        .unwrap(),
                    )
                } else {
                    None
                };
                let masked = match (masked_lower, masked_upper) {
                    (Some(x), Some(y)) => il::Expression::or(x, y).unwrap(),
                    (Some(x), None) | (None, Some(x)) => x,
                    (None, None) => {
                        reg.set(block, resize_zext(reg.bits(), value));
                        return Ok(());
                    }
                };

                // Shift the new value into the desired place...
                let replacement = if value.bits() <= width {
                    value
                } else {
                    il::Expression::trun(width, value).unwrap()
                };
                let replacement = il::Expression::shl(
                    resize_zext(reg.bits(), replacement),
                    il::expr_const(shift as u64, reg.bits()),
                )
                .unwrap();

                // And construct the final value.
                reg.set(block, il::Expression::or(masked, replacement).unwrap());
            } else {
                // Replace the whole with zero extension
                reg.set(block, resize_zext(reg.bits(), value));
            }
        }
        bad64::Operand::ShiftReg { .. }
        | bad64::Operand::Imm32 { .. }
        | bad64::Operand::Imm64 { .. }
        | bad64::Operand::FImm32(_) => {
            panic!("Can't store to operand `{}`", opr)
        }
        bad64::Operand::QualReg { .. }
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
        | bad64::Operand::StrImm { .. }
        | bad64::Operand::SmeTile { .. }
        | bad64::Operand::AccumArray { .. }
        | bad64::Operand::IndexedElement { .. } => return Err(unsupported()),
    }
    Ok(())
}

/// Only supports non-memory operands.
/// `out_bits` is only used for zero/sign-extension modifier.
fn mem_operand_address(opr: &bad64::Operand) -> Result<(il::Expression, MemOperandSideeffect)> {
    let (address_expr, sideeffect) = match opr {
        bad64::Operand::MemReg(reg) => (get_register(*reg)?.get(), MemOperandSideeffect::None),
        bad64::Operand::MemOffset {
            reg,
            offset,
            mul_vl: false,
            arrspec: None,
        } => {
            let reg = get_register(*reg)?;
            let offset = il::expr_const(imm_to_u64(offset), 64);
            let indexed_address = il::Expression::add(reg.get(), offset).unwrap();
            (indexed_address, MemOperandSideeffect::None)
        }
        bad64::Operand::MemPreIdx { reg, imm } => {
            let reg = get_register(*reg)?;
            let imm = il::expr_const(imm_to_u64(imm), 64);
            let indexed_address = il::Expression::add(reg.get(), imm).unwrap();
            (
                indexed_address.clone(),
                MemOperandSideeffect::Assign(reg, indexed_address),
            )
        }
        bad64::Operand::MemPostIdxReg([reg, reg_offset]) => {
            // TODO: Test this using `LD1R`
            let reg = get_register(*reg)?;
            let reg_offset = get_register(*reg_offset)?.get();
            let indexed_address = il::Expression::add(reg.get(), reg_offset).unwrap();
            (
                reg.get(),
                MemOperandSideeffect::Assign(reg, indexed_address),
            )
        }
        bad64::Operand::MemPostIdxImm { reg, imm } => {
            let reg = get_register(*reg)?;
            let imm = il::expr_const(imm_to_u64(imm), 64);
            let indexed_address = il::Expression::add(reg.get(), imm).unwrap();
            (
                reg.get(),
                MemOperandSideeffect::Assign(reg, indexed_address),
            )
        }
        bad64::Operand::MemExt {
            regs: [reg, reg_offset],
            shift: shift_,
            arrspec: None,
        } => {
            let reg = get_register(*reg)?.get();
            let reg_offset = if let Some(shift_) = shift_ {
                shift(get_register(*reg_offset)?.get(), shift_, 64)?
            } else {
                get_register(*reg_offset)?.get()
            };
            let indexed_address = il::Expression::add(reg, reg_offset).unwrap();
            (indexed_address, MemOperandSideeffect::None)
        }

        bad64::Operand::MemOffset { mul_vl: true, .. }
        | bad64::Operand::SmeTile { .. }
        | bad64::Operand::AccumArray { .. }
        | bad64::Operand::IndexedElement { .. }
        | bad64::Operand::MemOffset {
            arrspec: Some(_), ..
        }
        | bad64::Operand::MemExt {
            arrspec: Some(_), ..
        } => return Err(unsupported()),

        bad64::Operand::Reg { .. }
        | bad64::Operand::Imm32 { .. }
        | bad64::Operand::Imm64 { .. }
        | bad64::Operand::ShiftReg { .. }
        | bad64::Operand::FImm32(_)
        | bad64::Operand::QualReg { .. }
        | bad64::Operand::MultiReg { .. }
        | bad64::Operand::SysReg(_)
        | bad64::Operand::ImplSpec { .. }
        | bad64::Operand::Cond(_)
        | bad64::Operand::Label(_)
        | bad64::Operand::Name(_)
        | bad64::Operand::StrImm { .. } => unreachable!("Memory operand is expected here"),
    };

    Ok((address_expr, sideeffect))
}

#[must_use]
enum MemOperandSideeffect {
    None,
    Assign(&'static AArch64Register, il::Expression),
}

impl MemOperandSideeffect {
    fn apply(self, block: &mut il::Block) {
        if let MemOperandSideeffect::Assign(scalar, value) = self {
            scalar.set(block, value);
        }
    }
}

fn operand_storing_width(opr: &bad64::Operand) -> Result<usize> {
    match opr {
        bad64::Operand::Reg { reg, arrspec: None } => Ok(get_register(*reg)?.bits()),
        bad64::Operand::Reg {
            reg,
            arrspec: Some(arr_spec),
        } => match arr_spec {
            bad64::ArrSpec::Full(_) => Ok(get_register(*reg)?.bits()),
            bad64::ArrSpec::TwoDoubles(_) | bad64::ArrSpec::OneDouble(_) => Ok(64),
            bad64::ArrSpec::FourSingles(_)
            | bad64::ArrSpec::TwoSingles(_)
            | bad64::ArrSpec::OneSingle(_) => Ok(32),
            bad64::ArrSpec::EightHalves(_)
            | bad64::ArrSpec::FourHalves(_)
            | bad64::ArrSpec::TwoHalves(_)
            | bad64::ArrSpec::OneHalf(_) => Ok(16),
            bad64::ArrSpec::SixteenBytes(_)
            | bad64::ArrSpec::EightBytes(_)
            | bad64::ArrSpec::FourBytes(_)
            | bad64::ArrSpec::OneByte(_) => Ok(8),
        },
        bad64::Operand::ShiftReg { .. }
        | bad64::Operand::Imm32 { .. }
        | bad64::Operand::Imm64 { .. }
        | bad64::Operand::FImm32(_) => {
            panic!("Can't store to operand `{}`", opr)
        }
        bad64::Operand::QualReg { .. }
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
        | bad64::Operand::StrImm { .. }
        | bad64::Operand::SmeTile { .. }
        | bad64::Operand::AccumArray { .. }
        | bad64::Operand::IndexedElement { .. } => Err(unsupported()),
    }
}

fn is_arr_spec_indexed(bad64_arrspec: &bad64::ArrSpec) -> bool {
    match bad64_arrspec {
        bad64::ArrSpec::Full(i)
        | bad64::ArrSpec::TwoDoubles(i)
        | bad64::ArrSpec::FourSingles(i)
        | bad64::ArrSpec::EightHalves(i)
        | bad64::ArrSpec::SixteenBytes(i)
        | bad64::ArrSpec::OneDouble(i)
        | bad64::ArrSpec::TwoSingles(i)
        | bad64::ArrSpec::FourHalves(i)
        | bad64::ArrSpec::EightBytes(i)
        | bad64::ArrSpec::OneSingle(i)
        | bad64::ArrSpec::TwoHalves(i)
        | bad64::ArrSpec::FourBytes(i)
        | bad64::ArrSpec::OneHalf(i)
        | bad64::ArrSpec::OneByte(i) => i.is_some(),
    }
}

fn arr_spec_offset_width(bad64_arrspec: &bad64::ArrSpec) -> (usize, usize) {
    match *bad64_arrspec {
        bad64::ArrSpec::Full(_)
        | bad64::ArrSpec::TwoDoubles(None)
        | bad64::ArrSpec::FourSingles(None)
        | bad64::ArrSpec::EightHalves(None)
        | bad64::ArrSpec::SixteenBytes(None) => (0, 128),

        bad64::ArrSpec::OneDouble(None)
        | bad64::ArrSpec::TwoSingles(None)
        | bad64::ArrSpec::FourHalves(None)
        | bad64::ArrSpec::EightBytes(None) => (0, 64),

        bad64::ArrSpec::OneSingle(None)
        | bad64::ArrSpec::TwoHalves(None)
        | bad64::ArrSpec::FourBytes(None) => (0, 32),

        bad64::ArrSpec::OneHalf(None) => (0, 16),

        bad64::ArrSpec::OneByte(None) => (0, 8),

        bad64::ArrSpec::TwoDoubles(Some(i)) | bad64::ArrSpec::OneDouble(Some(i)) => {
            (i as usize * 64, 64)
        }
        bad64::ArrSpec::FourSingles(Some(i))
        | bad64::ArrSpec::TwoSingles(Some(i))
        | bad64::ArrSpec::OneSingle(Some(i)) => (i as usize * 32, 32),
        bad64::ArrSpec::EightHalves(Some(i))
        | bad64::ArrSpec::FourHalves(Some(i))
        | bad64::ArrSpec::TwoHalves(Some(i))
        | bad64::ArrSpec::OneHalf(Some(i)) => (i as usize * 16, 16),
        bad64::ArrSpec::SixteenBytes(Some(i))
        | bad64::ArrSpec::EightBytes(Some(i))
        | bad64::ArrSpec::FourBytes(Some(i))
        | bad64::ArrSpec::OneByte(Some(i)) => (i as usize * 8, 8),
    }
}

fn resize_zext(bits: usize, value: il::Expression) -> il::Expression {
    match bits.cmp(&value.bits()) {
        std::cmp::Ordering::Equal => value,
        std::cmp::Ordering::Greater => il::Expression::zext(bits, value).unwrap(),
        std::cmp::Ordering::Less => il::Expression::trun(bits, value).unwrap(),
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
        bad64::Shift::LSL(amount) => {
            return Ok(lsl(value, il::expr_const(amount.into(), out_bits)))
        }
        bad64::Shift::LSR(amount) => {
            return Ok(lsr(value, il::expr_const(amount.into(), out_bits)))
        }
        bad64::Shift::ASR(amount) => {
            return Ok(asr(value, il::expr_const(amount.into(), out_bits)))
        }
        bad64::Shift::ROR(amount) => {
            return Ok(ror(value, il::expr_const(amount.into(), out_bits)))
        }
        // AdvSIMDExpandImm with `op == 0 && cmode == 110x`
        bad64::Shift::MSL(_amount) => return Err(unsupported()),
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
        il::Expression::trun(len, value).unwrap()
    } else {
        value
    };
    let extended = if len < out_bits {
        if unsigned {
            il::Expression::zext(out_bits, extended).unwrap()
        } else {
            il::Expression::sext(out_bits, extended).unwrap()
        }
    } else {
        extended
    };

    Ok(il::Expression::shl(extended, il::expr_const(shift_amount.into(), out_bits)).unwrap())
}

/// Logical shift left
fn lsl(value: il::Expression, shift: il::Expression) -> il::Expression {
    il::Expression::shl(value, shift).unwrap()
}

/// Logical shift right
fn lsr(value: il::Expression, shift: il::Expression) -> il::Expression {
    il::Expression::shr(value, shift).unwrap()
}

/// Arithmetic shift right
fn asr(value: il::Expression, shift: il::Expression) -> il::Expression {
    il::Expression::sra(value, shift).unwrap()
}

/// Rotate right
fn ror(value: il::Expression, shift: il::Expression) -> il::Expression {
    let shift_right_bits = shift;
    let shift_left_bits = il::Expression::sub(
        il::expr_const(value.bits() as u64, value.bits()),
        shift_right_bits.clone(),
    )
    .unwrap();
    il::Expression::or(
        il::Expression::shl(value.clone(), shift_left_bits).unwrap(),
        il::Expression::shr(value, shift_right_bits).unwrap(),
    )
    .unwrap()
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
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let lhs = operand_load(block, &instruction.operands()[1], bits)?;
        let rhs = operand_load(block, &instruction.operands()[2], bits)?;

        // perform operation
        let src = il::Expression::add(lhs, rhs).unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn adds(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let lhs = operand_load(block, &instruction.operands()[1], bits)?;
        let rhs = operand_load(block, &instruction.operands()[2], bits)?;

        // perform operation
        let result = il::Expression::add(lhs.clone(), rhs.clone()).unwrap();

        let unsigned_sum = il::Expression::add(
            il::Expression::zext(72, lhs.clone()).unwrap(),
            il::Expression::zext(72, rhs.clone()).unwrap(),
        )
        .unwrap();
        let signed_sum = il::Expression::add(
            il::Expression::sext(72, lhs).unwrap(),
            il::Expression::sext(72, rhs).unwrap(),
        )
        .unwrap();

        let n = il::Expression::cmplts(result.clone(), il::expr_const(0, bits)).unwrap();
        let z = il::Expression::cmpeq(result.clone(), il::expr_const(0, bits)).unwrap();
        let c = il::Expression::cmpneq(
            il::Expression::zext(72, result.clone()).unwrap(),
            unsigned_sum,
        )
        .unwrap();
        let v = il::Expression::cmpneq(
            il::Expression::sext(72, result.clone()).unwrap(),
            signed_sum,
        )
        .unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], result)?;
        block.assign(scalar!("n"), n);
        block.assign(scalar!("z"), z);
        block.assign(scalar!("c"), c);
        block.assign(scalar!("v"), v);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn b(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let dst;

    let block_index = {
        let block = instruction_graph.new_block().unwrap();

        // get operands
        dst = operand_load(block, &instruction.operands()[0], 64)?
            .get_constant()
            .expect("branch target is not constant")
            .value_u64()
            .expect("branch target does not fit in 64 bits");

        block.index()
    };
    instruction_graph.set_entry(block_index).unwrap();
    instruction_graph.set_exit(block_index).unwrap();

    successors.push((dst, None));

    Ok(())
}

pub(super) fn b_cc(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
    cond: u8,
) -> Result<()> {
    let (dst, cond_true_false);

    if (cond & 0b1110) == 0b1110 {
        return b(instruction_graph, successors, instruction);
    }

    let block_index = {
        let block = instruction_graph.new_block().unwrap();

        // get operands
        dst = operand_load(block, &instruction.operands()[0], 64)?
            .get_constant()
            .expect("branch target is not constant")
            .value_u64()
            .expect("branch target does not fit in 64 bits");

        // condition
        let cond_true = match (cond & 0b1110) >> 1 {
            0b000 => expr!("z"),
            0b001 => expr!("c"),
            0b010 => expr!("n"),
            0b011 => expr!("v"),
            0b100 => il::Expression::and(
                expr!("c"),
                il::Expression::cmpneq(expr!("z"), il::expr_const(1, 1)).unwrap(),
            )
            .unwrap(),
            0b101 => il::Expression::cmpeq(expr!("n"), expr!("v")).unwrap(),
            0b110 => il::Expression::and(
                il::Expression::cmpeq(expr!("n"), expr!("v")).unwrap(),
                il::Expression::cmpneq(expr!("z"), il::expr_const(1, 1)).unwrap(),
            )
            .unwrap(),
            0b111 => unreachable!(), // handled above
            _ => unreachable!(),
        };
        let cond_false = il::Expression::cmpneq(cond_true.clone(), il::expr_const(1, 1)).unwrap();
        cond_true_false = if (cond & 1) != 0 && cond != 0b1111 {
            (cond_false, cond_true)
        } else {
            (cond_true, cond_false)
        };

        block.index()
    };
    instruction_graph.set_entry(block_index).unwrap();
    instruction_graph.set_exit(block_index).unwrap();

    let (cond_true, cond_false) = cond_true_false;
    successors.push((dst, Some(cond_true)));
    successors.push((instruction.address() + 4, Some(cond_false)));

    Ok(())
}

pub(super) fn br(
    instruction_graph: &mut il::ControlFlowGraph,
    _successors: &mut [(u64, Option<il::Expression>)],
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = instruction_graph.new_block().unwrap();

        // get operands
        let dst = operand_load(block, &instruction.operands()[0], 64)?;

        block.branch(dst);

        block.index()
    };
    instruction_graph.set_entry(block_index).unwrap();
    instruction_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn bl(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let dst = operand_load(block, &instruction.operands()[0], 64)?;

        block.assign(
            scalar!("x30"),
            il::expr_const(instruction.address().wrapping_add(4), 64),
        );
        block.branch(dst);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) use bl as blr;

fn cbz_cbnz_tbz_tbnz(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
    branch_if_zero: bool,
    test_bit: bool,
) -> Result<()> {
    let (dst, mut cond_true, mut cond_false);

    let opr_value = 0;
    let opr_bit = test_bit.then_some(1);
    let opr_target = [1, 2][test_bit as usize];

    let block_index = {
        let block = instruction_graph.new_block().unwrap();

        // get operands
        dst = operand_load(block, &instruction.operands()[opr_target], 64)?
            .get_constant()
            .expect("branch target is not constant")
            .value_u64()
            .expect("branch target does not fit in 64 bits");

        let bits = operand_storing_width(&instruction.operands()[opr_value])?;
        let value = operand_load(block, &instruction.operands()[opr_value], bits)?;

        let value = if let Some(opr_bit) = opr_bit {
            // specific bit
            let bit = operand_imm_u64(&instruction.operands()[opr_bit]);
            assert!(bit < bits as u64);
            il::Expression::and(value, il::expr_const(1 << bit, bits)).unwrap()
        } else {
            // any bit set
            value
        };

        cond_true = il::Expression::cmpneq(value.clone(), il::expr_const(0, bits)).unwrap();
        cond_false = il::Expression::cmpeq(value, il::expr_const(0, bits)).unwrap();

        if branch_if_zero {
            std::mem::swap(&mut cond_true, &mut cond_false);
        }

        block.index()
    };
    instruction_graph.set_entry(block_index).unwrap();
    instruction_graph.set_exit(block_index).unwrap();

    successors.push((dst, Some(cond_true)));
    successors.push((instruction.address() + 4, Some(cond_false)));

    Ok(())
}

pub(super) fn cbnz(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
) -> Result<()> {
    cbz_cbnz_tbz_tbnz(instruction_graph, successors, instruction, false, false)
}

pub(super) fn cbz(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
) -> Result<()> {
    cbz_cbnz_tbz_tbnz(instruction_graph, successors, instruction, true, false)
}

fn temp0(instruction: &bad64::Instruction, bits: usize) -> il::Scalar {
    il::Scalar::temp(instruction.address(), bits)
}

fn temp1(instruction: &bad64::Instruction, bits: usize) -> il::Scalar {
    il::Scalar::temp(instruction.address() + 1, bits)
}

pub(super) fn ldp(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[2])?;

        // perform operation
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let temp0 = temp0(instruction, bits);
        let temp1 = temp1(instruction, bits);
        block.load(temp0.clone(), address.clone());
        block.load(
            temp1.clone(),
            il::Expression::add(address, il::expr_const(bits as u64 / 8, 64)).unwrap(),
        );

        // store result
        operand_store(
            block,
            &instruction.operands()[0],
            il::Expression::Scalar(temp0),
        )?;
        operand_store(
            block,
            &instruction.operands()[1],
            il::Expression::Scalar(temp1),
        )?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldpsw(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[2])?;

        // perform operation
        let temp0 = temp0(instruction, 32);
        let temp1 = temp1(instruction, 32);
        block.load(temp0.clone(), address.clone());
        block.load(
            temp1.clone(),
            il::Expression::add(address, il::expr_const(4, 64)).unwrap(),
        );

        // store result
        operand_store(
            block,
            &instruction.operands()[0],
            il::Expression::sext(64, il::Expression::Scalar(temp0)).unwrap(),
        )?;
        operand_store(
            block,
            &instruction.operands()[1],
            il::Expression::sext(64, il::Expression::Scalar(temp1)).unwrap(),
        )?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

// TODO: Cache hint
pub(super) use ldp as ldnp;

// TODO: Memory ordering
pub(super) use {
    ldr as ldar, ldr as ldlar, ldrb as ldarb, ldrb as ldlarb, ldrh as ldarh, ldrh as ldlarh,
};

pub(super) fn ldr(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let temp = temp0(instruction, bits);
        block.load(temp.clone(), address);

        // store result
        operand_store(
            block,
            &instruction.operands()[0],
            il::Expression::Scalar(temp),
        )?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldrb(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let temp = temp0(instruction, 8);
        block.load(temp.clone(), address);

        // store result
        operand_store(
            block,
            &instruction.operands()[0],
            il::Expression::Scalar(temp),
        )?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldrh(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let temp = temp0(instruction, 16);
        block.load(temp.clone(), address);

        // store result
        operand_store(
            block,
            &instruction.operands()[0],
            il::Expression::Scalar(temp),
        )?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldrsb(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let temp = temp0(instruction, 8);
        block.load(temp.clone(), address);

        let extended = il::Expression::sext(bits, il::Expression::Scalar(temp)).unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], extended)?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldrsh(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let temp = temp0(instruction, 16);
        block.load(temp.clone(), address);

        let extended = il::Expression::sext(bits, il::Expression::Scalar(temp)).unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], extended)?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ldrsw(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operand
        let bits = operand_storing_width(&instruction.operands()[0])?;
        assert_eq!(bits, 64);
        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        let temp = temp0(instruction, 32);
        block.load(temp.clone(), address);

        let extended = il::Expression::sext(bits, il::Expression::Scalar(temp)).unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], extended)?;

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn mov(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let rhs = operand_load(block, &instruction.operands()[1], bits)?;

        // store result
        operand_store(block, &instruction.operands()[0], rhs)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn nop(
    control_flow_graph: &mut il::ControlFlowGraph,
    _instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.nop();

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn ret(
    instruction_graph: &mut il::ControlFlowGraph,
    _successors: &mut [(u64, Option<il::Expression>)],
    _instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = instruction_graph.new_block().unwrap();

        block.branch(expr!("x30"));

        block.index()
    };
    instruction_graph.set_entry(block_index).unwrap();
    instruction_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn stp(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let value0 = operand_load(block, &instruction.operands()[0], bits)?;
        let value1 = operand_load(block, &instruction.operands()[1], bits)?;

        let (address, sideeffect) = mem_operand_address(&instruction.operands()[2])?;

        // perform operation
        block.store(address.clone(), value0);
        block.store(
            il::Expression::add(address, il::expr_const(bits as u64 / 8, 64)).unwrap(),
            value1,
        );

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

// TODO: Cache hint
pub(super) use stp as stnp;

// TODO: Memory ordering
pub(super) use {
    str as stlr, str as stllr, strb as stlrb, strb as stllrb, strh as stlrh, strh as stllrh,
};

pub(super) fn str(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let value = operand_load(block, &instruction.operands()[0], bits)?;

        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        block.store(address, value);

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn strb(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let value = operand_load(block, &instruction.operands()[0], 32)?;

        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        block.store(address, il::Expression::trun(8, value).unwrap());

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn strh(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let value = operand_load(block, &instruction.operands()[0], 32)?;

        let (address, sideeffect) = mem_operand_address(&instruction.operands()[1])?;

        // perform operation
        block.store(address, il::Expression::trun(16, value).unwrap());

        // write-back
        sideeffect.apply(block);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn sub(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let lhs = operand_load(block, &instruction.operands()[1], bits)?;
        let rhs = operand_load(block, &instruction.operands()[2], bits)?;

        // perform operation
        let src = il::Expression::sub(lhs, rhs).unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], src)?;

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn subs(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block().unwrap();

        // get operands
        let bits = operand_storing_width(&instruction.operands()[0])?;
        let lhs = operand_load(block, &instruction.operands()[1], bits)?;
        let rhs = operand_load(block, &instruction.operands()[2], bits)?;

        // perform operation
        let result = il::Expression::sub(lhs.clone(), rhs.clone()).unwrap();

        let unsigned_sum = il::Expression::sub(
            il::Expression::zext(72, lhs.clone()).unwrap(),
            il::Expression::zext(72, rhs.clone()).unwrap(),
        )
        .unwrap();
        let signed_sum = il::Expression::sub(
            il::Expression::sext(72, lhs).unwrap(),
            il::Expression::sext(72, rhs).unwrap(),
        )
        .unwrap();
        let n = il::Expression::cmplts(result.clone(), il::expr_const(0, bits)).unwrap();
        let z = il::Expression::cmpeq(result.clone(), il::expr_const(0, bits)).unwrap();
        let c = il::Expression::cmpneq(
            il::Expression::zext(72, result.clone()).unwrap(),
            unsigned_sum,
        )
        .unwrap();
        let v = il::Expression::cmpneq(
            il::Expression::sext(72, result.clone()).unwrap(),
            signed_sum,
        )
        .unwrap();

        // store result
        operand_store(block, &instruction.operands()[0], result)?;
        block.assign(scalar!("n"), n);
        block.assign(scalar!("z"), z);
        block.assign(scalar!("c"), c);
        block.assign(scalar!("v"), v);

        block.index()
    };

    control_flow_graph.set_entry(block_index).unwrap();
    control_flow_graph.set_exit(block_index).unwrap();

    Ok(())
}

pub(super) fn tbnz(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
) -> Result<()> {
    cbz_cbnz_tbz_tbnz(instruction_graph, successors, instruction, false, true)
}

pub(super) fn tbz(
    instruction_graph: &mut il::ControlFlowGraph,
    successors: &mut Vec<(u64, Option<il::Expression>)>,
    instruction: &bad64::Instruction,
) -> Result<()> {
    cbz_cbnz_tbz_tbnz(instruction_graph, successors, instruction, true, true)
}

// TODO: Rest of the owl
