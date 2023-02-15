use crate::il::Expression as Expr;
use crate::il::*;
use crate::translator::x86::x86register::{get_register, X86Register};
use crate::Error;
use falcon_capstone::capstone;
use falcon_capstone::capstone::cs_x86_op;
use falcon_capstone::capstone_sys::{x86_op_type, x86_reg};
use std::cmp::Ordering;

/// Mode used by translators to pick the correct registers/operations
#[derive(Clone, Debug)]
pub(crate) enum Mode {
    X86,
    Amd64,
}

impl Mode {
    pub(crate) fn get_register(&self, capstone_id: x86_reg) -> Result<&'static X86Register, Error> {
        get_register(self, capstone_id)
    }

    pub(crate) fn bits(&self) -> usize {
        match *self {
            Mode::X86 => 32,
            Mode::Amd64 => 64,
        }
    }

    pub(crate) fn sp(&self) -> Scalar {
        match *self {
            Mode::X86 => scalar("esp", 32),
            Mode::Amd64 => scalar("rsp", 64),
        }
    }

    pub(crate) fn get_register_expression(
        &self,
        register: capstone::x86_reg,
        instruction: &capstone::Instr,
    ) -> Result<Expression, Error> {
        Ok(match register {
            x86_reg::X86_REG_RIP => {
                let value = instruction.address + instruction.size as u64;
                expr_const(value, 64)
            }
            _ => get_register(self, register)?.get()?,
        })
    }

    /// Gets the value of an operand as an IL expression
    pub(crate) fn operand_value(
        &self,
        operand: &cs_x86_op,
        instruction: &capstone::Instr,
    ) -> Result<Expression, Error> {
        match operand.type_ {
            x86_op_type::X86_OP_INVALID => Err("Invalid operand".into()),
            x86_op_type::X86_OP_REG => {
                // Get the register value
                get_register(self, operand.reg())?.get()
            }
            x86_op_type::X86_OP_MEM => {
                let mem = operand.mem();
                let base_capstone_reg = mem.base;
                let index_capstone_reg = mem.index;

                let base = match base_capstone_reg {
                    x86_reg::X86_REG_INVALID => None,
                    reg => Some(self.get_register_expression(reg, instruction)?),
                };

                let index = match index_capstone_reg {
                    x86_reg::X86_REG_INVALID => None,
                    reg => Some(self.get_register_expression(reg, instruction)?),
                };

                let scale = Expr::constant(Constant::new(mem.scale as i64 as u64, self.bits()));

                let si = match index {
                    Some(index) => Some(Expr::mul(index, scale)?),
                    None => None,
                };

                // Handle base and scale/index
                let op: Option<Expression> = if base.is_some() {
                    if si.is_some() {
                        Some(Expr::add(base.unwrap(), si.unwrap())?)
                    } else {
                        base
                    }
                } else if si.is_some() {
                    si
                } else {
                    None
                };

                // handle disp
                let op = if let Some(op) = op {
                    match mem.disp.cmp(&0) {
                        Ordering::Greater => {
                            Expr::add(op, expr_const(mem.disp as u64, self.bits()))?
                        }
                        Ordering::Less => {
                            Expr::sub(op, expr_const(mem.disp.unsigned_abs(), self.bits()))?
                        }
                        Ordering::Equal => op,
                    }
                } else {
                    expr_const(mem.disp as u64, self.bits())
                };

                match mem.segment {
                    x86_reg::X86_REG_INVALID => Ok(op),
                    x86_reg::X86_REG_CS
                    | x86_reg::X86_REG_DS
                    | x86_reg::X86_REG_ES
                    | x86_reg::X86_REG_FS
                    | x86_reg::X86_REG_GS
                    | x86_reg::X86_REG_SS => {
                        let segment_register = self.get_register(mem.segment)?.get()?;
                        Ok(Expr::add(segment_register, op)?)
                    }
                    _ => Err(Error::Custom("invalid segment register".to_string())),
                }
            }
            x86_op_type::X86_OP_IMM => {
                // https://github.com/aquynh/capstone/issues/1586
                let operand_size = if operand.size == 0 {
                    8
                } else {
                    operand.size as usize * 8
                };
                Ok(expr_const(operand.imm() as u64, operand_size))
            }
            #[cfg(not(feature = "capstone4"))]
            x86_op_type::X86_OP_FP => Err("Unhandled operand".into()),
        }
    }

    /// Gets the value of an operand as an IL expression, performing any required loads as needed.
    pub fn operand_load(
        &self,
        block: &mut Block,
        operand: &cs_x86_op,
        instruction: &capstone::Instr,
    ) -> Result<Expression, Error> {
        let op = self.operand_value(operand, instruction)?;

        if operand.type_ == x86_op_type::X86_OP_MEM {
            let temp = Scalar::temp(instruction.address, operand.size as usize * 8);
            block.load(temp.clone(), op);
            return Ok(temp.into());
        }
        Ok(op)
    }

    /// Stores a value in an operand, performing any stores as necessary.
    pub fn operand_store(
        &self,
        block: &mut Block,
        operand: &cs_x86_op,
        value: Expression,
        instruction: &capstone::Instr,
    ) -> Result<(), Error> {
        match operand.type_ {
            x86_op_type::X86_OP_INVALID => Err("operand_store called on invalid operand".into()),
            x86_op_type::X86_OP_IMM => Err("operand_store called on immediate operand".into()),
            x86_op_type::X86_OP_REG => {
                let dst_register = self.get_register(operand.reg())?;
                dst_register.set(block, value)
            }
            x86_op_type::X86_OP_MEM => {
                let address = self.operand_value(operand, instruction)?;
                block.store(address, value);
                Ok(())
            }
            #[cfg(not(feature = "capstone4"))]
            x86_op_type::X86_OP_FP => Err("operand_store called on fp operand".into()),
        }
    }

    /// Convenience function to pop a value off the stack
    pub fn pop_value(
        &self,
        block: &mut Block,
        bits: usize,
        instruction: &capstone::Instr,
    ) -> Result<Expression, Error> {
        let temp = Scalar::temp(instruction.address, bits);

        block.load(temp.clone(), self.sp().into());
        block.assign(
            self.sp(),
            Expr::add(self.sp().into(), expr_const((bits / 8) as u64, self.bits()))?,
        );

        Ok(temp.into())
    }

    /// Convenience function to push a value onto the stack
    pub fn push_value(&self, block: &mut Block, value: Expression) -> Result<(), Error> {
        match self {
            Mode::X86 => block.assign(self.sp(), Expr::sub(self.sp().into(), expr_const(4, 32))?),
            Mode::Amd64 => block.assign(self.sp(), Expr::sub(self.sp().into(), expr_const(8, 64))?),
        };

        block.store(self.sp().into(), value);
        Ok(())
    }
}
