use bad64::Reg;

use crate::error::*;
use crate::il::*;

/// Struct for dealing with AArch64 registers
pub struct AArch64Register {
    name: &'static str,
    // The `bad64` enum value for this register.
    bad64_reg: Reg,
    /// The full register. For example, `x0` is the full register for `w0`.
    bad64_full_reg: Reg,
    /// The size of this register in bits
    bits: usize,
}

impl AArch64Register {
    // pub fn bits(&self) -> usize {
    //     self.bits
    // }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Returns true if this is a full-width register (i.e. eax, ebx, etc)
    pub fn is_full(&self) -> bool {
        self.bad64_reg == self.bad64_full_reg
    }

    /// Returns the full-width register for this register
    pub fn get_full(&self) -> Result<&'static AArch64Register> {
        get_register(self.bad64_full_reg)
    }

    /// Returns an expression which evaluates to the value of the register.
    ///
    /// This handles things like `x0`/`w0`.
    pub fn get(&self) -> Result<Expression> {
        if matches!(
            self.bad64_reg,
            Reg::XZR
                | Reg::WZR
                | Reg::VZR
                | Reg::BZR
                | Reg::HZR
                | Reg::SZR
                | Reg::DZR
                | Reg::QZR
                | Reg::ZZR
        ) {
            Ok(expr_const(0, self.bits))
        } else if self.is_full() {
            Ok(expr_scalar(self.name, self.bits))
        } else {
            Expression::trun(self.bits, self.get_full()?.get()?)
        }
    }

    /// Sets the value of this register.
    ///
    /// This handles things like `x0`/`w0`.
    pub fn set(&self, block: &mut Block, value: Expression) -> Result<()> {
        if self.is_full() {
            block.assign(scalar(self.name, self.bits), value);
            Ok(())
        } else {
            let full_reg = self.get_full()?;
            full_reg.set(block, Expression::zext(full_reg.bits, value)?)
        }
    }
}

#[rustfmt::skip]
const AARCH64_REGISTERS: &[AArch64Register] = &[
    AArch64Register { name: "w0", bad64_reg: Reg::W0, bad64_full_reg: Reg::X0, bits: 32 },
    AArch64Register { name: "w1", bad64_reg: Reg::W1, bad64_full_reg: Reg::X1, bits: 32 },
    AArch64Register { name: "w2", bad64_reg: Reg::W2, bad64_full_reg: Reg::X2, bits: 32 },
    AArch64Register { name: "w3", bad64_reg: Reg::W3, bad64_full_reg: Reg::X3, bits: 32 },
    AArch64Register { name: "w4", bad64_reg: Reg::W4, bad64_full_reg: Reg::X4, bits: 32 },
    AArch64Register { name: "w5", bad64_reg: Reg::W5, bad64_full_reg: Reg::X5, bits: 32 },
    AArch64Register { name: "w6", bad64_reg: Reg::W6, bad64_full_reg: Reg::X6, bits: 32 },
    AArch64Register { name: "w7", bad64_reg: Reg::W7, bad64_full_reg: Reg::X7, bits: 32 },
    AArch64Register { name: "w8", bad64_reg: Reg::W8, bad64_full_reg: Reg::X8, bits: 32 },
    AArch64Register { name: "w9", bad64_reg: Reg::W9, bad64_full_reg: Reg::X9, bits: 32 },
    AArch64Register { name: "w10", bad64_reg: Reg::W10, bad64_full_reg: Reg::X10, bits: 32 },
    AArch64Register { name: "w11", bad64_reg: Reg::W11, bad64_full_reg: Reg::X11, bits: 32 },
    AArch64Register { name: "w12", bad64_reg: Reg::W12, bad64_full_reg: Reg::X12, bits: 32 },
    AArch64Register { name: "w13", bad64_reg: Reg::W13, bad64_full_reg: Reg::X13, bits: 32 },
    AArch64Register { name: "w14", bad64_reg: Reg::W14, bad64_full_reg: Reg::X14, bits: 32 },
    AArch64Register { name: "w15", bad64_reg: Reg::W15, bad64_full_reg: Reg::X15, bits: 32 },
    AArch64Register { name: "w16", bad64_reg: Reg::W16, bad64_full_reg: Reg::X16, bits: 32 },
    AArch64Register { name: "w17", bad64_reg: Reg::W17, bad64_full_reg: Reg::X17, bits: 32 },
    AArch64Register { name: "w18", bad64_reg: Reg::W18, bad64_full_reg: Reg::X18, bits: 32 },
    AArch64Register { name: "w19", bad64_reg: Reg::W19, bad64_full_reg: Reg::X19, bits: 32 },
    AArch64Register { name: "w20", bad64_reg: Reg::W20, bad64_full_reg: Reg::X20, bits: 32 },
    AArch64Register { name: "w21", bad64_reg: Reg::W21, bad64_full_reg: Reg::X21, bits: 32 },
    AArch64Register { name: "w22", bad64_reg: Reg::W22, bad64_full_reg: Reg::X22, bits: 32 },
    AArch64Register { name: "w23", bad64_reg: Reg::W23, bad64_full_reg: Reg::X23, bits: 32 },
    AArch64Register { name: "w24", bad64_reg: Reg::W24, bad64_full_reg: Reg::X24, bits: 32 },
    AArch64Register { name: "w25", bad64_reg: Reg::W25, bad64_full_reg: Reg::X25, bits: 32 },
    AArch64Register { name: "w26", bad64_reg: Reg::W26, bad64_full_reg: Reg::X26, bits: 32 },
    AArch64Register { name: "w27", bad64_reg: Reg::W27, bad64_full_reg: Reg::X27, bits: 32 },
    AArch64Register { name: "w28", bad64_reg: Reg::W28, bad64_full_reg: Reg::X28, bits: 32 },
    AArch64Register { name: "w29", bad64_reg: Reg::W29, bad64_full_reg: Reg::X29, bits: 32 },
    AArch64Register { name: "w30", bad64_reg: Reg::W30, bad64_full_reg: Reg::X30, bits: 32 },
    AArch64Register { name: "wzr", bad64_reg: Reg::WZR, bad64_full_reg: Reg::XZR, bits: 32 },
    AArch64Register { name: "wsp", bad64_reg: Reg::WSP, bad64_full_reg: Reg::SP, bits: 32 },
    AArch64Register { name: "x0", bad64_reg: Reg::X0, bad64_full_reg: Reg::X0, bits: 64 },
    AArch64Register { name: "x1", bad64_reg: Reg::X1, bad64_full_reg: Reg::X1, bits: 64 },
    AArch64Register { name: "x2", bad64_reg: Reg::X2, bad64_full_reg: Reg::X2, bits: 64 },
    AArch64Register { name: "x3", bad64_reg: Reg::X3, bad64_full_reg: Reg::X3, bits: 64 },
    AArch64Register { name: "x4", bad64_reg: Reg::X4, bad64_full_reg: Reg::X4, bits: 64 },
    AArch64Register { name: "x5", bad64_reg: Reg::X5, bad64_full_reg: Reg::X5, bits: 64 },
    AArch64Register { name: "x6", bad64_reg: Reg::X6, bad64_full_reg: Reg::X6, bits: 64 },
    AArch64Register { name: "x7", bad64_reg: Reg::X7, bad64_full_reg: Reg::X7, bits: 64 },
    AArch64Register { name: "x8", bad64_reg: Reg::X8, bad64_full_reg: Reg::X8, bits: 64 },
    AArch64Register { name: "x9", bad64_reg: Reg::X9, bad64_full_reg: Reg::X9, bits: 64 },
    AArch64Register { name: "x10", bad64_reg: Reg::X10, bad64_full_reg: Reg::X10, bits: 64 },
    AArch64Register { name: "x11", bad64_reg: Reg::X11, bad64_full_reg: Reg::X11, bits: 64 },
    AArch64Register { name: "x12", bad64_reg: Reg::X12, bad64_full_reg: Reg::X12, bits: 64 },
    AArch64Register { name: "x13", bad64_reg: Reg::X13, bad64_full_reg: Reg::X13, bits: 64 },
    AArch64Register { name: "x14", bad64_reg: Reg::X14, bad64_full_reg: Reg::X14, bits: 64 },
    AArch64Register { name: "x15", bad64_reg: Reg::X15, bad64_full_reg: Reg::X15, bits: 64 },
    AArch64Register { name: "x16", bad64_reg: Reg::X16, bad64_full_reg: Reg::X16, bits: 64 },
    AArch64Register { name: "x17", bad64_reg: Reg::X17, bad64_full_reg: Reg::X17, bits: 64 },
    AArch64Register { name: "x18", bad64_reg: Reg::X18, bad64_full_reg: Reg::X18, bits: 64 },
    AArch64Register { name: "x19", bad64_reg: Reg::X19, bad64_full_reg: Reg::X19, bits: 64 },
    AArch64Register { name: "x20", bad64_reg: Reg::X20, bad64_full_reg: Reg::X20, bits: 64 },
    AArch64Register { name: "x21", bad64_reg: Reg::X21, bad64_full_reg: Reg::X21, bits: 64 },
    AArch64Register { name: "x22", bad64_reg: Reg::X22, bad64_full_reg: Reg::X22, bits: 64 },
    AArch64Register { name: "x23", bad64_reg: Reg::X23, bad64_full_reg: Reg::X23, bits: 64 },
    AArch64Register { name: "x24", bad64_reg: Reg::X24, bad64_full_reg: Reg::X24, bits: 64 },
    AArch64Register { name: "x25", bad64_reg: Reg::X25, bad64_full_reg: Reg::X25, bits: 64 },
    AArch64Register { name: "x26", bad64_reg: Reg::X26, bad64_full_reg: Reg::X26, bits: 64 },
    AArch64Register { name: "x27", bad64_reg: Reg::X27, bad64_full_reg: Reg::X27, bits: 64 },
    AArch64Register { name: "x28", bad64_reg: Reg::X28, bad64_full_reg: Reg::X28, bits: 64 },
    AArch64Register { name: "x29", bad64_reg: Reg::X29, bad64_full_reg: Reg::X29, bits: 64 },
    AArch64Register { name: "x30", bad64_reg: Reg::X30, bad64_full_reg: Reg::X30, bits: 64 },
    AArch64Register { name: "xzr", bad64_reg: Reg::XZR, bad64_full_reg: Reg::XZR, bits: 64 },
    AArch64Register { name: "sp", bad64_reg: Reg::SP, bad64_full_reg: Reg::SP, bits: 64 },
    AArch64Register { name: "v0", bad64_reg: Reg::V0, bad64_full_reg: Reg::V0, bits: 128 },
    AArch64Register { name: "v1", bad64_reg: Reg::V1, bad64_full_reg: Reg::V1, bits: 128 },
    AArch64Register { name: "v2", bad64_reg: Reg::V2, bad64_full_reg: Reg::V2, bits: 128 },
    AArch64Register { name: "v3", bad64_reg: Reg::V3, bad64_full_reg: Reg::V3, bits: 128 },
    AArch64Register { name: "v4", bad64_reg: Reg::V4, bad64_full_reg: Reg::V4, bits: 128 },
    AArch64Register { name: "v5", bad64_reg: Reg::V5, bad64_full_reg: Reg::V5, bits: 128 },
    AArch64Register { name: "v6", bad64_reg: Reg::V6, bad64_full_reg: Reg::V6, bits: 128 },
    AArch64Register { name: "v7", bad64_reg: Reg::V7, bad64_full_reg: Reg::V7, bits: 128 },
    AArch64Register { name: "v8", bad64_reg: Reg::V8, bad64_full_reg: Reg::V8, bits: 128 },
    AArch64Register { name: "v9", bad64_reg: Reg::V9, bad64_full_reg: Reg::V9, bits: 128 },
    AArch64Register { name: "v10", bad64_reg: Reg::V10, bad64_full_reg: Reg::V10, bits: 128 },
    AArch64Register { name: "v11", bad64_reg: Reg::V11, bad64_full_reg: Reg::V11, bits: 128 },
    AArch64Register { name: "v12", bad64_reg: Reg::V12, bad64_full_reg: Reg::V12, bits: 128 },
    AArch64Register { name: "v13", bad64_reg: Reg::V13, bad64_full_reg: Reg::V13, bits: 128 },
    AArch64Register { name: "v14", bad64_reg: Reg::V14, bad64_full_reg: Reg::V14, bits: 128 },
    AArch64Register { name: "v15", bad64_reg: Reg::V15, bad64_full_reg: Reg::V15, bits: 128 },
    AArch64Register { name: "v16", bad64_reg: Reg::V16, bad64_full_reg: Reg::V16, bits: 128 },
    AArch64Register { name: "v17", bad64_reg: Reg::V17, bad64_full_reg: Reg::V17, bits: 128 },
    AArch64Register { name: "v18", bad64_reg: Reg::V18, bad64_full_reg: Reg::V18, bits: 128 },
    AArch64Register { name: "v19", bad64_reg: Reg::V19, bad64_full_reg: Reg::V19, bits: 128 },
    AArch64Register { name: "v20", bad64_reg: Reg::V20, bad64_full_reg: Reg::V20, bits: 128 },
    AArch64Register { name: "v21", bad64_reg: Reg::V21, bad64_full_reg: Reg::V21, bits: 128 },
    AArch64Register { name: "v22", bad64_reg: Reg::V22, bad64_full_reg: Reg::V22, bits: 128 },
    AArch64Register { name: "v23", bad64_reg: Reg::V23, bad64_full_reg: Reg::V23, bits: 128 },
    AArch64Register { name: "v24", bad64_reg: Reg::V24, bad64_full_reg: Reg::V24, bits: 128 },
    AArch64Register { name: "v25", bad64_reg: Reg::V25, bad64_full_reg: Reg::V25, bits: 128 },
    AArch64Register { name: "v26", bad64_reg: Reg::V26, bad64_full_reg: Reg::V26, bits: 128 },
    AArch64Register { name: "v27", bad64_reg: Reg::V27, bad64_full_reg: Reg::V27, bits: 128 },
    AArch64Register { name: "v28", bad64_reg: Reg::V28, bad64_full_reg: Reg::V28, bits: 128 },
    AArch64Register { name: "v29", bad64_reg: Reg::V29, bad64_full_reg: Reg::V29, bits: 128 },
    AArch64Register { name: "v30", bad64_reg: Reg::V30, bad64_full_reg: Reg::V30, bits: 128 },
    AArch64Register { name: "vzr", bad64_reg: Reg::VZR, bad64_full_reg: Reg::VZR, bits: 128 },
    AArch64Register { name: "v31", bad64_reg: Reg::V31, bad64_full_reg: Reg::V31, bits: 128 },
    AArch64Register { name: "b0", bad64_reg: Reg::B0, bad64_full_reg: Reg::V0, bits: 8 },
    AArch64Register { name: "b1", bad64_reg: Reg::B1, bad64_full_reg: Reg::V1, bits: 8 },
    AArch64Register { name: "b2", bad64_reg: Reg::B2, bad64_full_reg: Reg::V2, bits: 8 },
    AArch64Register { name: "b3", bad64_reg: Reg::B3, bad64_full_reg: Reg::V3, bits: 8 },
    AArch64Register { name: "b4", bad64_reg: Reg::B4, bad64_full_reg: Reg::V4, bits: 8 },
    AArch64Register { name: "b5", bad64_reg: Reg::B5, bad64_full_reg: Reg::V5, bits: 8 },
    AArch64Register { name: "b6", bad64_reg: Reg::B6, bad64_full_reg: Reg::V6, bits: 8 },
    AArch64Register { name: "b7", bad64_reg: Reg::B7, bad64_full_reg: Reg::V7, bits: 8 },
    AArch64Register { name: "b8", bad64_reg: Reg::B8, bad64_full_reg: Reg::V8, bits: 8 },
    AArch64Register { name: "b9", bad64_reg: Reg::B9, bad64_full_reg: Reg::V9, bits: 8 },
    AArch64Register { name: "b10", bad64_reg: Reg::B10, bad64_full_reg: Reg::V10, bits: 8 },
    AArch64Register { name: "b11", bad64_reg: Reg::B11, bad64_full_reg: Reg::V11, bits: 8 },
    AArch64Register { name: "b12", bad64_reg: Reg::B12, bad64_full_reg: Reg::V12, bits: 8 },
    AArch64Register { name: "b13", bad64_reg: Reg::B13, bad64_full_reg: Reg::V13, bits: 8 },
    AArch64Register { name: "b14", bad64_reg: Reg::B14, bad64_full_reg: Reg::V14, bits: 8 },
    AArch64Register { name: "b15", bad64_reg: Reg::B15, bad64_full_reg: Reg::V15, bits: 8 },
    AArch64Register { name: "b16", bad64_reg: Reg::B16, bad64_full_reg: Reg::V16, bits: 8 },
    AArch64Register { name: "b17", bad64_reg: Reg::B17, bad64_full_reg: Reg::V17, bits: 8 },
    AArch64Register { name: "b18", bad64_reg: Reg::B18, bad64_full_reg: Reg::V18, bits: 8 },
    AArch64Register { name: "b19", bad64_reg: Reg::B19, bad64_full_reg: Reg::V19, bits: 8 },
    AArch64Register { name: "b20", bad64_reg: Reg::B20, bad64_full_reg: Reg::V20, bits: 8 },
    AArch64Register { name: "b21", bad64_reg: Reg::B21, bad64_full_reg: Reg::V21, bits: 8 },
    AArch64Register { name: "b22", bad64_reg: Reg::B22, bad64_full_reg: Reg::V22, bits: 8 },
    AArch64Register { name: "b23", bad64_reg: Reg::B23, bad64_full_reg: Reg::V23, bits: 8 },
    AArch64Register { name: "b24", bad64_reg: Reg::B24, bad64_full_reg: Reg::V24, bits: 8 },
    AArch64Register { name: "b25", bad64_reg: Reg::B25, bad64_full_reg: Reg::V25, bits: 8 },
    AArch64Register { name: "b26", bad64_reg: Reg::B26, bad64_full_reg: Reg::V26, bits: 8 },
    AArch64Register { name: "b27", bad64_reg: Reg::B27, bad64_full_reg: Reg::V27, bits: 8 },
    AArch64Register { name: "b28", bad64_reg: Reg::B28, bad64_full_reg: Reg::V28, bits: 8 },
    AArch64Register { name: "b29", bad64_reg: Reg::B29, bad64_full_reg: Reg::V29, bits: 8 },
    AArch64Register { name: "b30", bad64_reg: Reg::B30, bad64_full_reg: Reg::V30, bits: 8 },
    AArch64Register { name: "bzr", bad64_reg: Reg::BZR, bad64_full_reg: Reg::VZR, bits: 8 },
    AArch64Register { name: "b31", bad64_reg: Reg::B31, bad64_full_reg: Reg::V31, bits: 8 },
    AArch64Register { name: "h0", bad64_reg: Reg::H0, bad64_full_reg: Reg::V0, bits: 16 },
    AArch64Register { name: "h1", bad64_reg: Reg::H1, bad64_full_reg: Reg::V1, bits: 16 },
    AArch64Register { name: "h2", bad64_reg: Reg::H2, bad64_full_reg: Reg::V2, bits: 16 },
    AArch64Register { name: "h3", bad64_reg: Reg::H3, bad64_full_reg: Reg::V3, bits: 16 },
    AArch64Register { name: "h4", bad64_reg: Reg::H4, bad64_full_reg: Reg::V4, bits: 16 },
    AArch64Register { name: "h5", bad64_reg: Reg::H5, bad64_full_reg: Reg::V5, bits: 16 },
    AArch64Register { name: "h6", bad64_reg: Reg::H6, bad64_full_reg: Reg::V6, bits: 16 },
    AArch64Register { name: "h7", bad64_reg: Reg::H7, bad64_full_reg: Reg::V7, bits: 16 },
    AArch64Register { name: "h8", bad64_reg: Reg::H8, bad64_full_reg: Reg::V8, bits: 16 },
    AArch64Register { name: "h9", bad64_reg: Reg::H9, bad64_full_reg: Reg::V9, bits: 16 },
    AArch64Register { name: "h10", bad64_reg: Reg::H10, bad64_full_reg: Reg::V10, bits: 16 },
    AArch64Register { name: "h11", bad64_reg: Reg::H11, bad64_full_reg: Reg::V11, bits: 16 },
    AArch64Register { name: "h12", bad64_reg: Reg::H12, bad64_full_reg: Reg::V12, bits: 16 },
    AArch64Register { name: "h13", bad64_reg: Reg::H13, bad64_full_reg: Reg::V13, bits: 16 },
    AArch64Register { name: "h14", bad64_reg: Reg::H14, bad64_full_reg: Reg::V14, bits: 16 },
    AArch64Register { name: "h15", bad64_reg: Reg::H15, bad64_full_reg: Reg::V15, bits: 16 },
    AArch64Register { name: "h16", bad64_reg: Reg::H16, bad64_full_reg: Reg::V16, bits: 16 },
    AArch64Register { name: "h17", bad64_reg: Reg::H17, bad64_full_reg: Reg::V17, bits: 16 },
    AArch64Register { name: "h18", bad64_reg: Reg::H18, bad64_full_reg: Reg::V18, bits: 16 },
    AArch64Register { name: "h19", bad64_reg: Reg::H19, bad64_full_reg: Reg::V19, bits: 16 },
    AArch64Register { name: "h20", bad64_reg: Reg::H20, bad64_full_reg: Reg::V20, bits: 16 },
    AArch64Register { name: "h21", bad64_reg: Reg::H21, bad64_full_reg: Reg::V21, bits: 16 },
    AArch64Register { name: "h22", bad64_reg: Reg::H22, bad64_full_reg: Reg::V22, bits: 16 },
    AArch64Register { name: "h23", bad64_reg: Reg::H23, bad64_full_reg: Reg::V23, bits: 16 },
    AArch64Register { name: "h24", bad64_reg: Reg::H24, bad64_full_reg: Reg::V24, bits: 16 },
    AArch64Register { name: "h25", bad64_reg: Reg::H25, bad64_full_reg: Reg::V25, bits: 16 },
    AArch64Register { name: "h26", bad64_reg: Reg::H26, bad64_full_reg: Reg::V26, bits: 16 },
    AArch64Register { name: "h27", bad64_reg: Reg::H27, bad64_full_reg: Reg::V27, bits: 16 },
    AArch64Register { name: "h28", bad64_reg: Reg::H28, bad64_full_reg: Reg::V28, bits: 16 },
    AArch64Register { name: "h29", bad64_reg: Reg::H29, bad64_full_reg: Reg::V29, bits: 16 },
    AArch64Register { name: "h30", bad64_reg: Reg::H30, bad64_full_reg: Reg::V30, bits: 16 },
    AArch64Register { name: "hzr", bad64_reg: Reg::HZR, bad64_full_reg: Reg::VZR, bits: 16 },
    AArch64Register { name: "h31", bad64_reg: Reg::H31, bad64_full_reg: Reg::V31, bits: 16 },
    AArch64Register { name: "s0", bad64_reg: Reg::S0, bad64_full_reg: Reg::V0, bits: 32 },
    AArch64Register { name: "s1", bad64_reg: Reg::S1, bad64_full_reg: Reg::V1, bits: 32 },
    AArch64Register { name: "s2", bad64_reg: Reg::S2, bad64_full_reg: Reg::V2, bits: 32 },
    AArch64Register { name: "s3", bad64_reg: Reg::S3, bad64_full_reg: Reg::V3, bits: 32 },
    AArch64Register { name: "s4", bad64_reg: Reg::S4, bad64_full_reg: Reg::V4, bits: 32 },
    AArch64Register { name: "s5", bad64_reg: Reg::S5, bad64_full_reg: Reg::V5, bits: 32 },
    AArch64Register { name: "s6", bad64_reg: Reg::S6, bad64_full_reg: Reg::V6, bits: 32 },
    AArch64Register { name: "s7", bad64_reg: Reg::S7, bad64_full_reg: Reg::V7, bits: 32 },
    AArch64Register { name: "s8", bad64_reg: Reg::S8, bad64_full_reg: Reg::V8, bits: 32 },
    AArch64Register { name: "s9", bad64_reg: Reg::S9, bad64_full_reg: Reg::V9, bits: 32 },
    AArch64Register { name: "s10", bad64_reg: Reg::S10, bad64_full_reg: Reg::V10, bits: 32 },
    AArch64Register { name: "s11", bad64_reg: Reg::S11, bad64_full_reg: Reg::V11, bits: 32 },
    AArch64Register { name: "s12", bad64_reg: Reg::S12, bad64_full_reg: Reg::V12, bits: 32 },
    AArch64Register { name: "s13", bad64_reg: Reg::S13, bad64_full_reg: Reg::V13, bits: 32 },
    AArch64Register { name: "s14", bad64_reg: Reg::S14, bad64_full_reg: Reg::V14, bits: 32 },
    AArch64Register { name: "s15", bad64_reg: Reg::S15, bad64_full_reg: Reg::V15, bits: 32 },
    AArch64Register { name: "s16", bad64_reg: Reg::S16, bad64_full_reg: Reg::V16, bits: 32 },
    AArch64Register { name: "s17", bad64_reg: Reg::S17, bad64_full_reg: Reg::V17, bits: 32 },
    AArch64Register { name: "s18", bad64_reg: Reg::S18, bad64_full_reg: Reg::V18, bits: 32 },
    AArch64Register { name: "s19", bad64_reg: Reg::S19, bad64_full_reg: Reg::V19, bits: 32 },
    AArch64Register { name: "s20", bad64_reg: Reg::S20, bad64_full_reg: Reg::V20, bits: 32 },
    AArch64Register { name: "s21", bad64_reg: Reg::S21, bad64_full_reg: Reg::V21, bits: 32 },
    AArch64Register { name: "s22", bad64_reg: Reg::S22, bad64_full_reg: Reg::V22, bits: 32 },
    AArch64Register { name: "s23", bad64_reg: Reg::S23, bad64_full_reg: Reg::V23, bits: 32 },
    AArch64Register { name: "s24", bad64_reg: Reg::S24, bad64_full_reg: Reg::V24, bits: 32 },
    AArch64Register { name: "s25", bad64_reg: Reg::S25, bad64_full_reg: Reg::V25, bits: 32 },
    AArch64Register { name: "s26", bad64_reg: Reg::S26, bad64_full_reg: Reg::V26, bits: 32 },
    AArch64Register { name: "s27", bad64_reg: Reg::S27, bad64_full_reg: Reg::V27, bits: 32 },
    AArch64Register { name: "s28", bad64_reg: Reg::S28, bad64_full_reg: Reg::V28, bits: 32 },
    AArch64Register { name: "s29", bad64_reg: Reg::S29, bad64_full_reg: Reg::V29, bits: 32 },
    AArch64Register { name: "s30", bad64_reg: Reg::S30, bad64_full_reg: Reg::V30, bits: 32 },
    AArch64Register { name: "szr", bad64_reg: Reg::SZR, bad64_full_reg: Reg::VZR, bits: 32 },
    AArch64Register { name: "s31", bad64_reg: Reg::S31, bad64_full_reg: Reg::V31, bits: 32 },
    AArch64Register { name: "d0", bad64_reg: Reg::D0, bad64_full_reg: Reg::V0, bits: 64 },
    AArch64Register { name: "d1", bad64_reg: Reg::D1, bad64_full_reg: Reg::V1, bits: 64 },
    AArch64Register { name: "d2", bad64_reg: Reg::D2, bad64_full_reg: Reg::V2, bits: 64 },
    AArch64Register { name: "d3", bad64_reg: Reg::D3, bad64_full_reg: Reg::V3, bits: 64 },
    AArch64Register { name: "d4", bad64_reg: Reg::D4, bad64_full_reg: Reg::V4, bits: 64 },
    AArch64Register { name: "d5", bad64_reg: Reg::D5, bad64_full_reg: Reg::V5, bits: 64 },
    AArch64Register { name: "d6", bad64_reg: Reg::D6, bad64_full_reg: Reg::V6, bits: 64 },
    AArch64Register { name: "d7", bad64_reg: Reg::D7, bad64_full_reg: Reg::V7, bits: 64 },
    AArch64Register { name: "d8", bad64_reg: Reg::D8, bad64_full_reg: Reg::V8, bits: 64 },
    AArch64Register { name: "d9", bad64_reg: Reg::D9, bad64_full_reg: Reg::V9, bits: 64 },
    AArch64Register { name: "d10", bad64_reg: Reg::D10, bad64_full_reg: Reg::V10, bits: 64 },
    AArch64Register { name: "d11", bad64_reg: Reg::D11, bad64_full_reg: Reg::V11, bits: 64 },
    AArch64Register { name: "d12", bad64_reg: Reg::D12, bad64_full_reg: Reg::V12, bits: 64 },
    AArch64Register { name: "d13", bad64_reg: Reg::D13, bad64_full_reg: Reg::V13, bits: 64 },
    AArch64Register { name: "d14", bad64_reg: Reg::D14, bad64_full_reg: Reg::V14, bits: 64 },
    AArch64Register { name: "d15", bad64_reg: Reg::D15, bad64_full_reg: Reg::V15, bits: 64 },
    AArch64Register { name: "d16", bad64_reg: Reg::D16, bad64_full_reg: Reg::V16, bits: 64 },
    AArch64Register { name: "d17", bad64_reg: Reg::D17, bad64_full_reg: Reg::V17, bits: 64 },
    AArch64Register { name: "d18", bad64_reg: Reg::D18, bad64_full_reg: Reg::V18, bits: 64 },
    AArch64Register { name: "d19", bad64_reg: Reg::D19, bad64_full_reg: Reg::V19, bits: 64 },
    AArch64Register { name: "d20", bad64_reg: Reg::D20, bad64_full_reg: Reg::V20, bits: 64 },
    AArch64Register { name: "d21", bad64_reg: Reg::D21, bad64_full_reg: Reg::V21, bits: 64 },
    AArch64Register { name: "d22", bad64_reg: Reg::D22, bad64_full_reg: Reg::V22, bits: 64 },
    AArch64Register { name: "d23", bad64_reg: Reg::D23, bad64_full_reg: Reg::V23, bits: 64 },
    AArch64Register { name: "d24", bad64_reg: Reg::D24, bad64_full_reg: Reg::V24, bits: 64 },
    AArch64Register { name: "d25", bad64_reg: Reg::D25, bad64_full_reg: Reg::V25, bits: 64 },
    AArch64Register { name: "d26", bad64_reg: Reg::D26, bad64_full_reg: Reg::V26, bits: 64 },
    AArch64Register { name: "d27", bad64_reg: Reg::D27, bad64_full_reg: Reg::V27, bits: 64 },
    AArch64Register { name: "d28", bad64_reg: Reg::D28, bad64_full_reg: Reg::V28, bits: 64 },
    AArch64Register { name: "d29", bad64_reg: Reg::D29, bad64_full_reg: Reg::V29, bits: 64 },
    AArch64Register { name: "d30", bad64_reg: Reg::D30, bad64_full_reg: Reg::V30, bits: 64 },
    AArch64Register { name: "dzr", bad64_reg: Reg::DZR, bad64_full_reg: Reg::VZR, bits: 64 },
    AArch64Register { name: "d31", bad64_reg: Reg::D31, bad64_full_reg: Reg::V31, bits: 64 },
    AArch64Register { name: "q0", bad64_reg: Reg::Q0, bad64_full_reg: Reg::V0, bits: 128 },
    AArch64Register { name: "q1", bad64_reg: Reg::Q1, bad64_full_reg: Reg::V1, bits: 128 },
    AArch64Register { name: "q2", bad64_reg: Reg::Q2, bad64_full_reg: Reg::V2, bits: 128 },
    AArch64Register { name: "q3", bad64_reg: Reg::Q3, bad64_full_reg: Reg::V3, bits: 128 },
    AArch64Register { name: "q4", bad64_reg: Reg::Q4, bad64_full_reg: Reg::V4, bits: 128 },
    AArch64Register { name: "q5", bad64_reg: Reg::Q5, bad64_full_reg: Reg::V5, bits: 128 },
    AArch64Register { name: "q6", bad64_reg: Reg::Q6, bad64_full_reg: Reg::V6, bits: 128 },
    AArch64Register { name: "q7", bad64_reg: Reg::Q7, bad64_full_reg: Reg::V7, bits: 128 },
    AArch64Register { name: "q8", bad64_reg: Reg::Q8, bad64_full_reg: Reg::V8, bits: 128 },
    AArch64Register { name: "q9", bad64_reg: Reg::Q9, bad64_full_reg: Reg::V9, bits: 128 },
    AArch64Register { name: "q10", bad64_reg: Reg::Q10, bad64_full_reg: Reg::V10, bits: 128 },
    AArch64Register { name: "q11", bad64_reg: Reg::Q11, bad64_full_reg: Reg::V11, bits: 128 },
    AArch64Register { name: "q12", bad64_reg: Reg::Q12, bad64_full_reg: Reg::V12, bits: 128 },
    AArch64Register { name: "q13", bad64_reg: Reg::Q13, bad64_full_reg: Reg::V13, bits: 128 },
    AArch64Register { name: "q14", bad64_reg: Reg::Q14, bad64_full_reg: Reg::V14, bits: 128 },
    AArch64Register { name: "q15", bad64_reg: Reg::Q15, bad64_full_reg: Reg::V15, bits: 128 },
    AArch64Register { name: "q16", bad64_reg: Reg::Q16, bad64_full_reg: Reg::V16, bits: 128 },
    AArch64Register { name: "q17", bad64_reg: Reg::Q17, bad64_full_reg: Reg::V17, bits: 128 },
    AArch64Register { name: "q18", bad64_reg: Reg::Q18, bad64_full_reg: Reg::V18, bits: 128 },
    AArch64Register { name: "q19", bad64_reg: Reg::Q19, bad64_full_reg: Reg::V19, bits: 128 },
    AArch64Register { name: "q20", bad64_reg: Reg::Q20, bad64_full_reg: Reg::V20, bits: 128 },
    AArch64Register { name: "q21", bad64_reg: Reg::Q21, bad64_full_reg: Reg::V21, bits: 128 },
    AArch64Register { name: "q22", bad64_reg: Reg::Q22, bad64_full_reg: Reg::V22, bits: 128 },
    AArch64Register { name: "q23", bad64_reg: Reg::Q23, bad64_full_reg: Reg::V23, bits: 128 },
    AArch64Register { name: "q24", bad64_reg: Reg::Q24, bad64_full_reg: Reg::V24, bits: 128 },
    AArch64Register { name: "q25", bad64_reg: Reg::Q25, bad64_full_reg: Reg::V25, bits: 128 },
    AArch64Register { name: "q26", bad64_reg: Reg::Q26, bad64_full_reg: Reg::V26, bits: 128 },
    AArch64Register { name: "q27", bad64_reg: Reg::Q27, bad64_full_reg: Reg::V27, bits: 128 },
    AArch64Register { name: "q28", bad64_reg: Reg::Q28, bad64_full_reg: Reg::V28, bits: 128 },
    AArch64Register { name: "q29", bad64_reg: Reg::Q29, bad64_full_reg: Reg::V29, bits: 128 },
    AArch64Register { name: "q30", bad64_reg: Reg::Q30, bad64_full_reg: Reg::V30, bits: 128 },
    AArch64Register { name: "qzr", bad64_reg: Reg::QZR, bad64_full_reg: Reg::VZR, bits: 128 },
    AArch64Register { name: "q31", bad64_reg: Reg::Q31, bad64_full_reg: Reg::V31, bits: 128 },
    // FIXME: SVE registers have an implementation-defined width
    AArch64Register { name: "z0", bad64_reg: Reg::Z0, bad64_full_reg: Reg::Z0, bits: 128 },
    AArch64Register { name: "z1", bad64_reg: Reg::Z1, bad64_full_reg: Reg::Z1, bits: 128 },
    AArch64Register { name: "z2", bad64_reg: Reg::Z2, bad64_full_reg: Reg::Z2, bits: 128 },
    AArch64Register { name: "z3", bad64_reg: Reg::Z3, bad64_full_reg: Reg::Z3, bits: 128 },
    AArch64Register { name: "z4", bad64_reg: Reg::Z4, bad64_full_reg: Reg::Z4, bits: 128 },
    AArch64Register { name: "z5", bad64_reg: Reg::Z5, bad64_full_reg: Reg::Z5, bits: 128 },
    AArch64Register { name: "z6", bad64_reg: Reg::Z6, bad64_full_reg: Reg::Z6, bits: 128 },
    AArch64Register { name: "z7", bad64_reg: Reg::Z7, bad64_full_reg: Reg::Z7, bits: 128 },
    AArch64Register { name: "z8", bad64_reg: Reg::Z8, bad64_full_reg: Reg::Z8, bits: 128 },
    AArch64Register { name: "z9", bad64_reg: Reg::Z9, bad64_full_reg: Reg::Z9, bits: 128 },
    AArch64Register { name: "z10", bad64_reg: Reg::Z10, bad64_full_reg: Reg::Z10, bits: 128 },
    AArch64Register { name: "z11", bad64_reg: Reg::Z11, bad64_full_reg: Reg::Z11, bits: 128 },
    AArch64Register { name: "z12", bad64_reg: Reg::Z12, bad64_full_reg: Reg::Z12, bits: 128 },
    AArch64Register { name: "z13", bad64_reg: Reg::Z13, bad64_full_reg: Reg::Z13, bits: 128 },
    AArch64Register { name: "z14", bad64_reg: Reg::Z14, bad64_full_reg: Reg::Z14, bits: 128 },
    AArch64Register { name: "z15", bad64_reg: Reg::Z15, bad64_full_reg: Reg::Z15, bits: 128 },
    AArch64Register { name: "z16", bad64_reg: Reg::Z16, bad64_full_reg: Reg::Z16, bits: 128 },
    AArch64Register { name: "z17", bad64_reg: Reg::Z17, bad64_full_reg: Reg::Z17, bits: 128 },
    AArch64Register { name: "z18", bad64_reg: Reg::Z18, bad64_full_reg: Reg::Z18, bits: 128 },
    AArch64Register { name: "z19", bad64_reg: Reg::Z19, bad64_full_reg: Reg::Z19, bits: 128 },
    AArch64Register { name: "z20", bad64_reg: Reg::Z20, bad64_full_reg: Reg::Z20, bits: 128 },
    AArch64Register { name: "z21", bad64_reg: Reg::Z21, bad64_full_reg: Reg::Z21, bits: 128 },
    AArch64Register { name: "z22", bad64_reg: Reg::Z22, bad64_full_reg: Reg::Z22, bits: 128 },
    AArch64Register { name: "z23", bad64_reg: Reg::Z23, bad64_full_reg: Reg::Z23, bits: 128 },
    AArch64Register { name: "z24", bad64_reg: Reg::Z24, bad64_full_reg: Reg::Z24, bits: 128 },
    AArch64Register { name: "z25", bad64_reg: Reg::Z25, bad64_full_reg: Reg::Z25, bits: 128 },
    AArch64Register { name: "z26", bad64_reg: Reg::Z26, bad64_full_reg: Reg::Z26, bits: 128 },
    AArch64Register { name: "z27", bad64_reg: Reg::Z27, bad64_full_reg: Reg::Z27, bits: 128 },
    AArch64Register { name: "z28", bad64_reg: Reg::Z28, bad64_full_reg: Reg::Z28, bits: 128 },
    AArch64Register { name: "z29", bad64_reg: Reg::Z29, bad64_full_reg: Reg::Z29, bits: 128 },
    AArch64Register { name: "z30", bad64_reg: Reg::Z30, bad64_full_reg: Reg::Z30, bits: 128 },
    AArch64Register { name: "zzr", bad64_reg: Reg::ZZR, bad64_full_reg: Reg::ZZR, bits: 128 },
    AArch64Register { name: "z31", bad64_reg: Reg::Z31, bad64_full_reg: Reg::Z31, bits: 128 },
    AArch64Register { name: "p0", bad64_reg: Reg::P0, bad64_full_reg: Reg::P0, bits: 16 },
    AArch64Register { name: "p1", bad64_reg: Reg::P1, bad64_full_reg: Reg::P1, bits: 16 },
    AArch64Register { name: "p2", bad64_reg: Reg::P2, bad64_full_reg: Reg::P2, bits: 16 },
    AArch64Register { name: "p3", bad64_reg: Reg::P3, bad64_full_reg: Reg::P3, bits: 16 },
    AArch64Register { name: "p4", bad64_reg: Reg::P4, bad64_full_reg: Reg::P4, bits: 16 },
    AArch64Register { name: "p5", bad64_reg: Reg::P5, bad64_full_reg: Reg::P5, bits: 16 },
    AArch64Register { name: "p6", bad64_reg: Reg::P6, bad64_full_reg: Reg::P6, bits: 16 },
    AArch64Register { name: "p7", bad64_reg: Reg::P7, bad64_full_reg: Reg::P7, bits: 16 },
    AArch64Register { name: "p8", bad64_reg: Reg::P8, bad64_full_reg: Reg::P8, bits: 16 },
    AArch64Register { name: "p9", bad64_reg: Reg::P9, bad64_full_reg: Reg::P9, bits: 16 },
    AArch64Register { name: "p10", bad64_reg: Reg::P10, bad64_full_reg: Reg::P10, bits: 16 },
    AArch64Register { name: "p11", bad64_reg: Reg::P11, bad64_full_reg: Reg::P11, bits: 16 },
    AArch64Register { name: "p12", bad64_reg: Reg::P12, bad64_full_reg: Reg::P12, bits: 16 },
    AArch64Register { name: "p13", bad64_reg: Reg::P13, bad64_full_reg: Reg::P13, bits: 16 },
    AArch64Register { name: "p14", bad64_reg: Reg::P14, bad64_full_reg: Reg::P14, bits: 16 },
    AArch64Register { name: "p15", bad64_reg: Reg::P15, bad64_full_reg: Reg::P15, bits: 16 },
    AArch64Register { name: "p16", bad64_reg: Reg::P16, bad64_full_reg: Reg::P16, bits: 16 },
    AArch64Register { name: "p17", bad64_reg: Reg::P17, bad64_full_reg: Reg::P17, bits: 16 },
    AArch64Register { name: "p18", bad64_reg: Reg::P18, bad64_full_reg: Reg::P18, bits: 16 },
    AArch64Register { name: "p19", bad64_reg: Reg::P19, bad64_full_reg: Reg::P19, bits: 16 },
    AArch64Register { name: "p20", bad64_reg: Reg::P20, bad64_full_reg: Reg::P20, bits: 16 },
    AArch64Register { name: "p21", bad64_reg: Reg::P21, bad64_full_reg: Reg::P21, bits: 16 },
    AArch64Register { name: "p22", bad64_reg: Reg::P22, bad64_full_reg: Reg::P22, bits: 16 },
    AArch64Register { name: "p23", bad64_reg: Reg::P23, bad64_full_reg: Reg::P23, bits: 16 },
    AArch64Register { name: "p24", bad64_reg: Reg::P24, bad64_full_reg: Reg::P24, bits: 16 },
    AArch64Register { name: "p25", bad64_reg: Reg::P25, bad64_full_reg: Reg::P25, bits: 16 },
    AArch64Register { name: "p26", bad64_reg: Reg::P26, bad64_full_reg: Reg::P26, bits: 16 },
    AArch64Register { name: "p27", bad64_reg: Reg::P27, bad64_full_reg: Reg::P27, bits: 16 },
    AArch64Register { name: "p28", bad64_reg: Reg::P28, bad64_full_reg: Reg::P28, bits: 16 },
    AArch64Register { name: "p29", bad64_reg: Reg::P29, bad64_full_reg: Reg::P29, bits: 16 },
    AArch64Register { name: "p30", bad64_reg: Reg::P30, bad64_full_reg: Reg::P30, bits: 16 },
    AArch64Register { name: "p31", bad64_reg: Reg::P31, bad64_full_reg: Reg::P31, bits: 16 },
];

/// Takes a capstone register enum and returns a `AArch64Register`
pub fn get_register(bad64_reg: Reg) -> Result<&'static AArch64Register> {
    for register in AARCH64_REGISTERS.iter() {
        if register.bad64_reg == bad64_reg {
            return Ok(&register);
        }
    }
    Err("Could not find register".into())
}
