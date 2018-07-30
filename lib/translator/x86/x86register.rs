use falcon_capstone::capstone_sys::x86_reg;
use error::*;
use il::*;
use il::Expression as Expr;
use translator::x86::mode::Mode;


const X86REGISTERS : &'static [X86Register] = &[
    X86Register { name: "ah",  capstone_reg: x86_reg::X86_REG_AH,  full_reg: x86_reg::X86_REG_EAX, offset: 8, bits: 8,  mode: Mode::X86 },
    X86Register { name: "al",  capstone_reg: x86_reg::X86_REG_AL,  full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 8,  mode: Mode::X86 },
    X86Register { name: "ax",  capstone_reg: x86_reg::X86_REG_AX,  full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "eax", capstone_reg: x86_reg::X86_REG_EAX, full_reg: x86_reg::X86_REG_EAX, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "bh",  capstone_reg: x86_reg::X86_REG_BH,  full_reg: x86_reg::X86_REG_EBX, offset: 8, bits: 8,  mode: Mode::X86 },
    X86Register { name: "bl",  capstone_reg: x86_reg::X86_REG_BL,  full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 8,  mode: Mode::X86 },
    X86Register { name: "bx",  capstone_reg: x86_reg::X86_REG_BX,  full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "ebx", capstone_reg: x86_reg::X86_REG_EBX, full_reg: x86_reg::X86_REG_EBX, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "ch",  capstone_reg: x86_reg::X86_REG_CH,  full_reg: x86_reg::X86_REG_ECX, offset: 8, bits: 8,  mode: Mode::X86 },
    X86Register { name: "cl",  capstone_reg: x86_reg::X86_REG_CL,  full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 8,  mode: Mode::X86 },
    X86Register { name: "cx",  capstone_reg: x86_reg::X86_REG_CX,  full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "ecx", capstone_reg: x86_reg::X86_REG_ECX, full_reg: x86_reg::X86_REG_ECX, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "dh",  capstone_reg: x86_reg::X86_REG_DH,  full_reg: x86_reg::X86_REG_EDX, offset: 8, bits: 8,  mode: Mode::X86 },
    X86Register { name: "dl",  capstone_reg: x86_reg::X86_REG_DL,  full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 8,  mode: Mode::X86 },
    X86Register { name: "dx",  capstone_reg: x86_reg::X86_REG_DX,  full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "edx", capstone_reg: x86_reg::X86_REG_EDX, full_reg: x86_reg::X86_REG_EDX, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "si",  capstone_reg: x86_reg::X86_REG_SI,  full_reg: x86_reg::X86_REG_ESI, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "esi", capstone_reg: x86_reg::X86_REG_ESI, full_reg: x86_reg::X86_REG_ESI, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "di",  capstone_reg: x86_reg::X86_REG_DI,  full_reg: x86_reg::X86_REG_EDI, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "edi", capstone_reg: x86_reg::X86_REG_EDI, full_reg: x86_reg::X86_REG_EDI, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "sp",  capstone_reg: x86_reg::X86_REG_SP,  full_reg: x86_reg::X86_REG_ESP, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "esp", capstone_reg: x86_reg::X86_REG_ESP, full_reg: x86_reg::X86_REG_ESP, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "bp",  capstone_reg: x86_reg::X86_REG_BP,  full_reg: x86_reg::X86_REG_EBP, offset: 0, bits: 16, mode: Mode::X86 },
    X86Register { name: "ebp", capstone_reg: x86_reg::X86_REG_EBP, full_reg: x86_reg::X86_REG_EBP, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "fs_base", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_FS, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "gs_base", capstone_reg: x86_reg::X86_REG_GS, full_reg: x86_reg::X86_REG_GS, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "ds_base", capstone_reg: x86_reg::X86_REG_DS, full_reg: x86_reg::X86_REG_DS, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "es_base", capstone_reg: x86_reg::X86_REG_ES, full_reg: x86_reg::X86_REG_ES, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "cs_base", capstone_reg: x86_reg::X86_REG_CS, full_reg: x86_reg::X86_REG_CS, offset: 0, bits: 32, mode: Mode::X86 },
    X86Register { name: "ss_base", capstone_reg: x86_reg::X86_REG_SS, full_reg: x86_reg::X86_REG_SS, offset: 0, bits: 32, mode: Mode::X86 },
];


const AMD64REGISTERS : &'static [X86Register] = &[
    X86Register { name: "ah",  capstone_reg: x86_reg::X86_REG_AH,  full_reg: x86_reg::X86_REG_RAX, offset: 8, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "al",  capstone_reg: x86_reg::X86_REG_AL,  full_reg: x86_reg::X86_REG_RAX, offset: 0, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "ax",  capstone_reg: x86_reg::X86_REG_AX,  full_reg: x86_reg::X86_REG_RAX, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "eax", capstone_reg: x86_reg::X86_REG_EAX, full_reg: x86_reg::X86_REG_RAX, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rax", capstone_reg: x86_reg::X86_REG_RAX, full_reg: x86_reg::X86_REG_RAX, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "bh",  capstone_reg: x86_reg::X86_REG_BH,  full_reg: x86_reg::X86_REG_RBX, offset: 8, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "bl",  capstone_reg: x86_reg::X86_REG_BL,  full_reg: x86_reg::X86_REG_RBX, offset: 0, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "bx",  capstone_reg: x86_reg::X86_REG_BX,  full_reg: x86_reg::X86_REG_RBX, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "ebx", capstone_reg: x86_reg::X86_REG_EBX, full_reg: x86_reg::X86_REG_RBX, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rbx", capstone_reg: x86_reg::X86_REG_RBX, full_reg: x86_reg::X86_REG_RBX, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "ch",  capstone_reg: x86_reg::X86_REG_CH,  full_reg: x86_reg::X86_REG_RCX, offset: 8, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "cl",  capstone_reg: x86_reg::X86_REG_CL,  full_reg: x86_reg::X86_REG_RCX, offset: 0, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "cx",  capstone_reg: x86_reg::X86_REG_CX,  full_reg: x86_reg::X86_REG_RCX, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "ecx", capstone_reg: x86_reg::X86_REG_ECX, full_reg: x86_reg::X86_REG_RCX, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rcx", capstone_reg: x86_reg::X86_REG_RCX, full_reg: x86_reg::X86_REG_RCX, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "dh",  capstone_reg: x86_reg::X86_REG_DH,  full_reg: x86_reg::X86_REG_RDX, offset: 8, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "dl",  capstone_reg: x86_reg::X86_REG_DL,  full_reg: x86_reg::X86_REG_RDX, offset: 0, bits: 8,  mode: Mode::Amd64 },
    X86Register { name: "dx",  capstone_reg: x86_reg::X86_REG_DX,  full_reg: x86_reg::X86_REG_RDX, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "edx", capstone_reg: x86_reg::X86_REG_EDX, full_reg: x86_reg::X86_REG_RDX, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rdx", capstone_reg: x86_reg::X86_REG_RDX, full_reg: x86_reg::X86_REG_RDX, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "si",  capstone_reg: x86_reg::X86_REG_SI,  full_reg: x86_reg::X86_REG_RSI, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "esi", capstone_reg: x86_reg::X86_REG_ESI, full_reg: x86_reg::X86_REG_RSI, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rsi", capstone_reg: x86_reg::X86_REG_RSI, full_reg: x86_reg::X86_REG_RSI, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "di",  capstone_reg: x86_reg::X86_REG_DI,  full_reg: x86_reg::X86_REG_RDI, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "edi", capstone_reg: x86_reg::X86_REG_EDI, full_reg: x86_reg::X86_REG_RDI, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rdi", capstone_reg: x86_reg::X86_REG_RDI, full_reg: x86_reg::X86_REG_RDI, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "sp",  capstone_reg: x86_reg::X86_REG_SP,  full_reg: x86_reg::X86_REG_RSP, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "esp", capstone_reg: x86_reg::X86_REG_ESP, full_reg: x86_reg::X86_REG_RSP, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rsp", capstone_reg: x86_reg::X86_REG_RSP, full_reg: x86_reg::X86_REG_RSP, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "bp",  capstone_reg: x86_reg::X86_REG_BP,  full_reg: x86_reg::X86_REG_RBP, offset: 0, bits: 16, mode: Mode::Amd64 },
    X86Register { name: "ebp", capstone_reg: x86_reg::X86_REG_EBP, full_reg: x86_reg::X86_REG_RBP, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "rbp", capstone_reg: x86_reg::X86_REG_RBP, full_reg: x86_reg::X86_REG_RBP, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r8d", capstone_reg: x86_reg::X86_REG_R8D, full_reg: x86_reg::X86_REG_R8 , offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r8",  capstone_reg: x86_reg::X86_REG_R8,  full_reg: x86_reg::X86_REG_R8,  offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r9d", capstone_reg: x86_reg::X86_REG_R9D, full_reg: x86_reg::X86_REG_R9,  offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r9",  capstone_reg: x86_reg::X86_REG_R9,  full_reg: x86_reg::X86_REG_R9,  offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r10d",capstone_reg: x86_reg::X86_REG_R10D, full_reg: x86_reg::X86_REG_R10, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r10", capstone_reg: x86_reg::X86_REG_R10,  full_reg: x86_reg::X86_REG_R10, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r11d",capstone_reg: x86_reg::X86_REG_R11D, full_reg: x86_reg::X86_REG_R11, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r11", capstone_reg: x86_reg::X86_REG_R11,  full_reg: x86_reg::X86_REG_R11, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r12d",capstone_reg: x86_reg::X86_REG_R12D, full_reg: x86_reg::X86_REG_R12, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r12", capstone_reg: x86_reg::X86_REG_R12,  full_reg: x86_reg::X86_REG_R12, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r13d",capstone_reg: x86_reg::X86_REG_R13D, full_reg: x86_reg::X86_REG_R13, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r13", capstone_reg: x86_reg::X86_REG_R13,  full_reg: x86_reg::X86_REG_R13, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r14d",capstone_reg: x86_reg::X86_REG_R14D, full_reg: x86_reg::X86_REG_R14, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r14", capstone_reg: x86_reg::X86_REG_R14,  full_reg: x86_reg::X86_REG_R14, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "r15d",capstone_reg: x86_reg::X86_REG_R15D, full_reg: x86_reg::X86_REG_R15, offset: 0, bits: 32, mode: Mode::Amd64 },
    X86Register { name: "r15", capstone_reg: x86_reg::X86_REG_R15,  full_reg: x86_reg::X86_REG_R15, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "fs_base", capstone_reg: x86_reg::X86_REG_FS, full_reg: x86_reg::X86_REG_FS, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "gs_base", capstone_reg: x86_reg::X86_REG_GS, full_reg: x86_reg::X86_REG_GS, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "ds_base", capstone_reg: x86_reg::X86_REG_DS, full_reg: x86_reg::X86_REG_DS, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "es_base", capstone_reg: x86_reg::X86_REG_ES, full_reg: x86_reg::X86_REG_ES, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "cs_base", capstone_reg: x86_reg::X86_REG_CS, full_reg: x86_reg::X86_REG_CS, offset: 0, bits: 64, mode: Mode::Amd64 },
    X86Register { name: "ss_base", capstone_reg: x86_reg::X86_REG_SS, full_reg: x86_reg::X86_REG_SS, offset: 0, bits: 64, mode: Mode::Amd64 },
];


/// Struct for dealing with x86 registers
pub(crate) struct X86Register {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: x86_reg,
    /// The full register. For example, eax is the full register for al.
    full_reg: x86_reg,
    /// The offset of this register. For example, ah is offset 8 bit into eax.
    offset: usize,
    /// The size of this register in bits
    bits: usize,
    /// The mode for this register
    mode: Mode
}


impl X86Register {
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Returns true if this is a full-width register (i.e. eax, ebx, etc)
    pub fn is_full(&self) -> bool {
        if self.capstone_reg == self.full_reg {
            true
        }
        else {
            false
        }
    }

    /// Returns the full-width register for this register
    pub fn get_full(&self) -> Result<&'static X86Register> {
        get_register(&self.mode, self.full_reg)
    }

    /// Returns an expression which evaluates to the value of the register.
    ///
    /// This handles things like al/ah/ax/eax
    pub fn get(&self) -> Result<Expression> {
        if self.is_full() {
            Ok(expr_scalar(self.name, self.bits))
        }
        else if self.offset == 0 {
            Expr::trun(self.bits, self.get_full()?.get()?)
        }
        else {
            let full_reg = self.get_full()?;
            let expr = Expr::shr(full_reg.get()?, expr_const(self.offset as u64, full_reg.bits))?;
            Expr::trun(self.bits, expr)
        }
    }

    /// Sets the value of this register.
    ///
    /// This handles things like al/ah/ax/eax
    pub fn set(&self, block: &mut Block, value: Expression) -> Result<()> {
        if self.is_full() {
            block.assign(scalar(self.name, self.bits), value);
            Ok(())
        }
        else if self.offset == 0 {
            let full_reg = self.get_full()?;
            let mask = !0 << self.bits;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.bits))?;
            let expr = Expr::or(expr, Expr::zext(full_reg.bits, value)?)?;
            full_reg.set(block, expr)
        }
        else {
            let full_reg = self.get_full()?;
            let mask = ((1 << self.bits) - 1) << self.offset;
            let expr = Expr::and(full_reg.get()?, expr_const(mask, full_reg.bits))?;
            let value = Expr::zext(full_reg.bits, value)?;
            let expr = Expr::or(expr, Expr::shl(value, expr_const(self.offset as u64, full_reg.bits))?)?;
            full_reg.set(block, expr)
        }
    }
}


/// Takes a capstone register enum and returns an `X86Register`
pub(crate) fn get_register(mode: &Mode, capstone_id: x86_reg)
    -> Result<&'static X86Register> {
        
    let registers: &[X86Register] = match *mode {
        Mode::X86 => X86REGISTERS,
        Mode::Amd64 => AMD64REGISTERS
    };

    for register in registers.iter() {
        if register.capstone_reg == capstone_id {
            return Ok(&register);
        }
    }
    Err(format!("Could not find register {:?}", capstone_id).into())
}