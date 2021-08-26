//! Information about varying calling conventions.

use crate::il;
use std::collections::HashSet;

/// Available type of calling conventions
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallingConventionType {
    AArch64,
    Amd64SystemV,
    Cdecl,
    MipsSystemV,
    MipselSystemV,
    PpcSystemV,
}

/// The return type for a function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReturnAddressType {
    /// Functions return by loading an address from a register.
    Register(il::Scalar),
    /// Functions return by loading an address from the stack.
    ///
    /// The offset to the return address at function call/entry is given.
    Stack(usize),
}

impl ReturnAddressType {
    pub fn register(&self) -> Option<&il::Scalar> {
        match self {
            ReturnAddressType::Register(scalar) => Some(scalar),
            ReturnAddressType::Stack(_) => None,
        }
    }

    pub fn stack(&self) -> Option<usize> {
        match self {
            ReturnAddressType::Stack(offset) => Some(*offset),
            ReturnAddressType::Register(_) => None,
        }
    }
}

/// The type of an argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentType {
    /// The argument is held in a register.
    Register(il::Scalar),

    /// The argument is held in a stack offset.
    ///
    /// The stack offset is given at function call/entry.
    Stack(usize),
}

impl ArgumentType {
    pub fn register(&self) -> Option<&il::Scalar> {
        match self {
            ArgumentType::Register(scalar) => Some(scalar),
            ArgumentType::Stack(_) => None,
        }
    }

    pub fn stack(&self) -> Option<usize> {
        match self {
            ArgumentType::Stack(offset) => Some(*offset),
            ArgumentType::Register(_) => None,
        }
    }
}

/// Represents the calling convention of a particular platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallingConvention {
    /// arguments passed in registers.
    argument_registers: Vec<il::Scalar>,

    /// These registers are preserved across function calls.
    preserved_registers: HashSet<il::Scalar>,

    /// These registers are not preserved across function calls.
    trashed_registers: HashSet<il::Scalar>,

    /// Offset from function start where first argument on stack is found.
    ///
    /// After register arguments are exhausted, analysis will begin looking
    /// here.
    stack_argument_offset: usize,

    /// Length of an argument on the stack in bytes.
    stack_argument_length: usize,

    /// The return address is given in the following type.
    return_address_type: ReturnAddressType,

    /// The register the returned value is given in.
    return_register: il::Scalar,
}

/*
    Mips System V:
        $16-$23 and $29-$31 are saved. This is $s0-S8, $sp and $ra.
        Result is in $v0.
        Everything else is trashed.
*/

impl CallingConvention {
    /// Create a new `CallingConvention` based on the given
    /// `CallingConventionType`.
    pub fn new(typ: CallingConventionType) -> CallingConvention {
        match typ {
            CallingConventionType::AArch64 => {
                // <https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#general-purpose-registers>
                let argument_registers = vec![
                    il::scalar("x0", 64),
                    il::scalar("x1", 64),
                    il::scalar("x2", 64),
                    il::scalar("x3", 64),
                    il::scalar("x4", 64),
                    il::scalar("x5", 64),
                    il::scalar("x6", 64),
                    il::scalar("x7", 64),
                    il::scalar("v0", 64),
                    il::scalar("v1", 64),
                    il::scalar("v2", 64),
                    il::scalar("v3", 64),
                    il::scalar("v4", 64),
                    il::scalar("v5", 64),
                    il::scalar("v6", 64),
                    il::scalar("v7", 64),
                ];
                let mut preserved_registers = HashSet::new();
                preserved_registers.insert(il::scalar("x19", 64));
                preserved_registers.insert(il::scalar("x20", 64));
                preserved_registers.insert(il::scalar("x21", 64));
                preserved_registers.insert(il::scalar("x22", 64));
                preserved_registers.insert(il::scalar("x23", 64));
                preserved_registers.insert(il::scalar("x24", 64));
                preserved_registers.insert(il::scalar("x25", 64));
                preserved_registers.insert(il::scalar("x26", 64));
                preserved_registers.insert(il::scalar("x27", 64));
                preserved_registers.insert(il::scalar("x28", 64));

                preserved_registers.insert(il::scalar("v8", 128));
                preserved_registers.insert(il::scalar("v9", 128));
                preserved_registers.insert(il::scalar("v10", 128));
                preserved_registers.insert(il::scalar("v11", 128));
                preserved_registers.insert(il::scalar("v12", 128));
                preserved_registers.insert(il::scalar("v13", 128));
                preserved_registers.insert(il::scalar("v14", 128));
                preserved_registers.insert(il::scalar("v15", 128));

                let mut trashed_registers = HashSet::new();
                trashed_registers.insert(il::scalar("x0", 64));
                trashed_registers.insert(il::scalar("x1", 64));
                trashed_registers.insert(il::scalar("x2", 64));
                trashed_registers.insert(il::scalar("x3", 64));
                trashed_registers.insert(il::scalar("x4", 64));
                trashed_registers.insert(il::scalar("x5", 64));
                trashed_registers.insert(il::scalar("x6", 64));
                trashed_registers.insert(il::scalar("x7", 64));
                trashed_registers.insert(il::scalar("x8", 64));
                trashed_registers.insert(il::scalar("x9", 64));
                trashed_registers.insert(il::scalar("x10", 64));
                trashed_registers.insert(il::scalar("x11", 64));
                trashed_registers.insert(il::scalar("x12", 64));
                trashed_registers.insert(il::scalar("x13", 64));
                trashed_registers.insert(il::scalar("x14", 64));
                trashed_registers.insert(il::scalar("x15", 64));
                trashed_registers.insert(il::scalar("x16", 64));
                trashed_registers.insert(il::scalar("x17", 64));
                // trashed_registers.insert(il::scalar("x18", 64)); // platform-dependent

                trashed_registers.insert(il::scalar("x0", 128));
                trashed_registers.insert(il::scalar("x1", 128));
                trashed_registers.insert(il::scalar("x2", 128));
                trashed_registers.insert(il::scalar("x3", 128));
                trashed_registers.insert(il::scalar("x4", 128));
                trashed_registers.insert(il::scalar("x5", 128));
                trashed_registers.insert(il::scalar("x6", 128));
                trashed_registers.insert(il::scalar("x7", 128));
                trashed_registers.insert(il::scalar("x16", 128));
                trashed_registers.insert(il::scalar("x17", 128));
                trashed_registers.insert(il::scalar("x18", 128));
                trashed_registers.insert(il::scalar("x19", 128));
                trashed_registers.insert(il::scalar("x20", 128));
                trashed_registers.insert(il::scalar("x21", 128));
                trashed_registers.insert(il::scalar("x22", 128));
                trashed_registers.insert(il::scalar("x23", 128));
                trashed_registers.insert(il::scalar("x24", 128));
                trashed_registers.insert(il::scalar("x25", 128));
                trashed_registers.insert(il::scalar("x26", 128));
                trashed_registers.insert(il::scalar("x27", 128));
                trashed_registers.insert(il::scalar("x28", 128));
                trashed_registers.insert(il::scalar("x29", 128));
                trashed_registers.insert(il::scalar("x30", 128));
                trashed_registers.insert(il::scalar("x31", 128));

                // TODO: FPSR, NZCV, SVE

                let return_type = ReturnAddressType::Register(il::scalar("x30", 64));

                CallingConvention {
                    argument_registers,
                    preserved_registers,
                    trashed_registers,
                    stack_argument_offset: 0,
                    stack_argument_length: 4,
                    return_address_type: return_type,
                    return_register: il::scalar("x0", 64),
                }
            }
            CallingConventionType::Amd64SystemV => {
                let argument_registers = vec![
                    il::scalar("rdi", 64),
                    il::scalar("rsi", 64),
                    il::scalar("rdx", 64),
                    il::scalar("rcx", 64),
                    il::scalar("r8", 64),
                    il::scalar("r9", 64),
                ];
                let mut preserved_registers = HashSet::new();
                preserved_registers.insert(il::scalar("rbx", 64));
                preserved_registers.insert(il::scalar("r12", 64));
                preserved_registers.insert(il::scalar("r13", 64));
                preserved_registers.insert(il::scalar("r14", 64));
                preserved_registers.insert(il::scalar("r15", 64));
                preserved_registers.insert(il::scalar("rbp", 64));
                preserved_registers.insert(il::scalar("rsp", 64));

                let mut trashed_registers = HashSet::new();
                trashed_registers.insert(il::scalar("rax", 64));
                trashed_registers.insert(il::scalar("rcx", 64));
                trashed_registers.insert(il::scalar("rdx", 64));
                trashed_registers.insert(il::scalar("rdi", 64));
                trashed_registers.insert(il::scalar("rsi", 64));
                trashed_registers.insert(il::scalar("r8", 64));
                trashed_registers.insert(il::scalar("r9", 64));
                trashed_registers.insert(il::scalar("r10", 64));
                trashed_registers.insert(il::scalar("r11", 64));

                let return_type = ReturnAddressType::Stack(0);

                CallingConvention {
                    argument_registers,
                    preserved_registers,
                    trashed_registers,
                    stack_argument_offset: 8,
                    stack_argument_length: 8,
                    return_address_type: return_type,
                    return_register: il::scalar("rax", 64),
                }
            }
            CallingConventionType::Cdecl => {
                let mut preserved_registers = HashSet::new();
                preserved_registers.insert(il::scalar("ebx", 32));
                preserved_registers.insert(il::scalar("edi", 32));
                preserved_registers.insert(il::scalar("esi", 32));
                preserved_registers.insert(il::scalar("ebp", 32));
                preserved_registers.insert(il::scalar("esp", 32));

                let mut trashed_registers = HashSet::new();
                trashed_registers.insert(il::scalar("eax", 32));
                trashed_registers.insert(il::scalar("ecx", 32));
                trashed_registers.insert(il::scalar("edx", 32));

                let return_type = ReturnAddressType::Stack(0);

                CallingConvention {
                    argument_registers: Vec::new(),
                    preserved_registers,
                    trashed_registers,
                    stack_argument_offset: 4,
                    stack_argument_length: 4,
                    return_address_type: return_type,
                    return_register: il::scalar("eax", 32),
                }
            }
            CallingConventionType::MipsSystemV | CallingConventionType::MipselSystemV => {
                let argument_registers = vec![
                    il::scalar("$a0", 32),
                    il::scalar("$a1", 32),
                    il::scalar("$a2", 32),
                    il::scalar("$a3", 32),
                ];

                let mut preserved_registers = HashSet::new();
                preserved_registers.insert(il::scalar("$s0", 32));
                preserved_registers.insert(il::scalar("$s1", 32));
                preserved_registers.insert(il::scalar("$s2", 32));
                preserved_registers.insert(il::scalar("$s3", 32));
                preserved_registers.insert(il::scalar("$s4", 32));
                preserved_registers.insert(il::scalar("$s5", 32));
                preserved_registers.insert(il::scalar("$s6", 32));
                preserved_registers.insert(il::scalar("$s7", 32));
                preserved_registers.insert(il::scalar("$s8", 32));
                preserved_registers.insert(il::scalar("$sp", 32));
                preserved_registers.insert(il::scalar("$ra", 32));

                let mut trashed_registers = HashSet::new();
                trashed_registers.insert(il::scalar("$at", 32));
                trashed_registers.insert(il::scalar("$v0", 32));
                trashed_registers.insert(il::scalar("$v1", 32));
                trashed_registers.insert(il::scalar("$a0", 32));
                trashed_registers.insert(il::scalar("$a1", 32));
                trashed_registers.insert(il::scalar("$a2", 32));
                trashed_registers.insert(il::scalar("$a3", 32));
                trashed_registers.insert(il::scalar("$t0", 32));
                trashed_registers.insert(il::scalar("$t1", 32));
                trashed_registers.insert(il::scalar("$t2", 32));
                trashed_registers.insert(il::scalar("$t3", 32));
                trashed_registers.insert(il::scalar("$t4", 32));
                trashed_registers.insert(il::scalar("$t5", 32));
                trashed_registers.insert(il::scalar("$t6", 32));
                trashed_registers.insert(il::scalar("$t7", 32));
                trashed_registers.insert(il::scalar("$t8", 32));
                trashed_registers.insert(il::scalar("$t9", 32));
                trashed_registers.insert(il::scalar("$gp", 32));

                let return_type = ReturnAddressType::Register(il::scalar("$ra", 32));

                CallingConvention {
                    argument_registers,
                    preserved_registers,
                    trashed_registers,
                    stack_argument_offset: 16,
                    stack_argument_length: 4,
                    return_address_type: return_type,
                    return_register: il::scalar("$v0", 32),
                }
            }
            CallingConventionType::PpcSystemV => {
                let argument_registers = vec![
                    il::scalar("r3", 32),
                    il::scalar("r4", 32),
                    il::scalar("r5", 32),
                    il::scalar("r6", 32),
                    il::scalar("r7", 32),
                    il::scalar("r8", 32),
                    il::scalar("r9", 32),
                    il::scalar("r10", 32),
                ];

                let mut preserved_registers = HashSet::new();
                preserved_registers.insert(il::scalar("r1", 32));
                preserved_registers.insert(il::scalar("r2", 32));
                preserved_registers.insert(il::scalar("r14", 32));
                preserved_registers.insert(il::scalar("r15", 32));
                preserved_registers.insert(il::scalar("r16", 32));
                preserved_registers.insert(il::scalar("r17", 32));
                preserved_registers.insert(il::scalar("r18", 32));
                preserved_registers.insert(il::scalar("r19", 32));
                preserved_registers.insert(il::scalar("r20", 32));
                preserved_registers.insert(il::scalar("r21", 32));
                preserved_registers.insert(il::scalar("r22", 32));
                preserved_registers.insert(il::scalar("r23", 32));
                preserved_registers.insert(il::scalar("r24", 32));
                preserved_registers.insert(il::scalar("r25", 32));
                preserved_registers.insert(il::scalar("r26", 32));
                preserved_registers.insert(il::scalar("r27", 32));
                preserved_registers.insert(il::scalar("r28", 32));
                preserved_registers.insert(il::scalar("r29", 32));
                preserved_registers.insert(il::scalar("r30", 32));
                preserved_registers.insert(il::scalar("r31", 32));

                let mut trashed_registers = HashSet::new();
                trashed_registers.insert(il::scalar("r0", 32));
                trashed_registers.insert(il::scalar("r3", 32));
                trashed_registers.insert(il::scalar("r4", 32));
                trashed_registers.insert(il::scalar("r5", 32));
                trashed_registers.insert(il::scalar("r6", 32));
                trashed_registers.insert(il::scalar("r7", 32));
                trashed_registers.insert(il::scalar("r8", 32));
                trashed_registers.insert(il::scalar("r9", 32));
                trashed_registers.insert(il::scalar("r10", 32));
                trashed_registers.insert(il::scalar("r11", 32));
                trashed_registers.insert(il::scalar("r12", 32));
                trashed_registers.insert(il::scalar("r13", 32));

                let return_type = ReturnAddressType::Register(il::scalar("r3", 32));

                CallingConvention {
                    argument_registers,
                    preserved_registers,
                    trashed_registers,
                    stack_argument_offset: 4,
                    stack_argument_length: 4,
                    return_address_type: return_type,
                    return_register: il::scalar("lr", 32),
                }
            }
        }
    }

    /// Get the registers the first n arguments are passed in.
    pub fn argument_registers(&self) -> &[il::Scalar] {
        &self.argument_registers
    }

    /// Get the registers preserved across function calls.
    pub fn preserved_registers(&self) -> &HashSet<il::Scalar> {
        &self.preserved_registers
    }

    /// Get the registers trashed across function calls.
    pub fn trashed_registers(&self) -> &HashSet<il::Scalar> {
        &self.trashed_registers
    }

    /// Get the length of an argument on the stack in _bytes, not bits_.
    ///
    /// We would expect this to be natural register-width of the architecture.
    pub fn stack_argument_length(&self) -> usize {
        self.stack_argument_length
    }

    /// Get the stack offset to the first argument passed on the stack in
    /// _bytes, not bits_.
    ///
    /// We would expect this to be immediately above the return address, if the
    /// return address is stored on the stack.
    pub fn stack_argument_offset(&self) -> usize {
        self.stack_argument_offset
    }

    /// How the return address is specified for function calls.
    pub fn return_address_type(&self) -> &ReturnAddressType {
        &self.return_address_type
    }

    /// The register returned values is given in.
    pub fn return_register(&self) -> &il::Scalar {
        &self.return_register
    }

    /// Get the type for the given argument, starting with 0 index.
    pub fn argument_type(&self, argument_number: usize) -> ArgumentType {
        if argument_number >= self.argument_registers.len() {
            let n = argument_number - self.argument_registers.len();
            let offset = self.stack_argument_offset + (self.stack_argument_length * n);
            ArgumentType::Stack(offset)
        } else {
            ArgumentType::Register(self.argument_registers[argument_number].clone())
        }
    }

    /// Is the given register preserved.
    pub fn is_preserved(&self, scalar: &il::Scalar) -> Option<bool> {
        if self.preserved_registers.contains(scalar) {
            Some(true)
        } else if self.trashed_registers.contains(scalar) {
            Some(false)
        } else {
            None
        }
    }

    /// Is the given register trashed.
    pub fn is_trashed(&self, scalar: &il::Scalar) -> Option<bool> {
        if self.trashed_registers.contains(scalar) {
            Some(true)
        } else if self.preserved_registers.contains(scalar) {
            Some(false)
        } else {
            None
        }
    }
}
