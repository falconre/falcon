use falcon_capstone::capstone;
use falcon_capstone::capstone::cs_x86_op;
use falcon_capstone::capstone_sys::{x86_op_type, x86_reg};
use error::*;
use il::*;
use il::Expression as Expr;
use translator::x86::x86register::{get_register, X86Register};


/// Mode used by translators to pick the correct registers/operations
#[derive(Clone, Debug)]
pub(crate) enum Mode {
    X86,
    Amd64
}


impl Mode {
    pub(crate) fn get_register(&self, capstone_id: x86_reg)
        -> Result<&'static X86Register> {

        get_register(self, capstone_id)
    }


    pub(crate) fn bits(&self) -> usize {
        match *self {
            Mode::X86 => 32,
            Mode::Amd64 => 64
        }
    }


    pub(crate) fn sp(&self) -> Scalar {
        match *self {
            Mode::X86 => scalar("esp", 32),
            Mode::Amd64 => scalar("rsp", 64)
        }
    }


    /// Gets the value of an operand as an IL expression
    pub(crate) fn operand_value(&self, operand: &cs_x86_op)
        -> Result<Expression> {

        match operand.type_ {
            x86_op_type::X86_OP_INVALID => Err("Invalid operand".into()),
            x86_op_type::X86_OP_REG => {
                // Get the register value
                get_register(self, operand.reg())?.get()
            }
            x86_op_type::X86_OP_MEM => {
                let mem = operand.mem();
                let base_capstone_reg = capstone::x86_reg::from(mem.base);
                let index_capstone_reg = capstone::x86_reg::from(mem.index);

                let base = match base_capstone_reg {
                    x86_reg::X86_REG_INVALID => None,
                    reg => Some(get_register(self, reg)?.get()?)
                };

                let index = match index_capstone_reg {
                    x86_reg::X86_REG_INVALID => None,
                    reg => Some(get_register(self, reg)?.get()?)
                };

                let scale = Expr::constant(
                    Constant::new(mem.scale as i64 as u64, self.bits()));

                let si = match index {
                    Some(index) => Some(Expr::mul(index, scale)?),
                    None => None
                };

                // Handle base and scale/index
                let op : Option<Expression> = if base.is_some() {
                    if si.is_some() {
                        Some(Expr::add(base.unwrap(), si.unwrap())?)
                    }
                    else {
                        base
                    }
                }
                else if si.is_some() {
                    si
                }
                else {
                    None
                };

                // handle disp
                let op = if op.is_some() {
                    if mem.disp > 0 {
                        Expr::add(op.unwrap(),
                                  expr_const(mem.disp as u64, self.bits()))?
                    }
                    else if mem.disp < 0 {
                        Expr::sub(op.unwrap(),
                                  expr_const(mem.disp.abs() as u64, self.bits()))?
                    }
                    else {
                        op.unwrap()
                    }
                }
                else {
                    expr_const(mem.disp as u64, self.bits())
                };

                match x86_reg::from(mem.segment) {
                    x86_reg::X86_REG_INVALID =>
                        Ok(op),
                    x86_reg::X86_REG_CS |
                    x86_reg::X86_REG_DS |
                    x86_reg::X86_REG_ES |
                    x86_reg::X86_REG_FS |
                    x86_reg::X86_REG_GS |
                    x86_reg::X86_REG_SS => {
                        let segment_register =
                            self.get_register(x86_reg::from(mem.segment))?
                            .get()?;
                        Ok(Expr::add(segment_register, op)?)
                    },
                    _ => bail!("invalid segment register")
                }
            },
            x86_op_type::X86_OP_IMM => {
                Ok(expr_const(operand.imm() as u64, operand.size as usize * 8))
            }
            x86_op_type::X86_OP_FP => Err("Unhandled operand".into()),
        }
    }


    /// Gets the value of an operand as an IL expression, performing any required loads as needed.
    pub fn operand_load(&self, block: &mut Block, operand: &cs_x86_op)
        -> Result<Expression> {

        let op = self.operand_value(operand)?;

        if operand.type_ == x86_op_type::X86_OP_MEM {
            let temp = block.temp(operand.size as usize * 8);
            block.load(temp.clone(), op);
            return Ok(temp.into());
        }
        Ok(op)
    }


    /// Stores a value in an operand, performing any stores as necessary.
    pub fn operand_store(
        &self,
        mut block: &mut Block,
        operand: &cs_x86_op,
        value: Expression
    ) -> Result<()> {

        match operand.type_ {
            x86_op_type::X86_OP_INVALID =>
                Err("operand_store called on invalid operand".into()),
            x86_op_type::X86_OP_IMM =>
                Err("operand_store called on immediate operand".into()),
            x86_op_type::X86_OP_REG => {
                let dst_register = self.get_register(operand.reg())?;
                dst_register.set(&mut block, value)
            },
            x86_op_type::X86_OP_MEM => {
                let address = self.operand_value(operand)?;
                block.store(address, value);
                Ok(())
            },
            x86_op_type::X86_OP_FP => {
                Err("operand_store called on fp operand".into())
            }
        }
    }


    /// Convenience function to pop a value off the stack
    pub fn pop_value(&self, block: &mut Block, bits: usize)
        -> Result<Expression> {

        let temp = block.temp(bits);

        block.load(temp.clone(), self.sp().into());
        block.assign(
            self.sp(),
            Expr::add(self.sp().into(), expr_const((bits / 8) as u64, 32))?
        );

        Ok(temp.into())
    }


    /// Convenience function to push a value onto the stack
    pub fn push_value(&self, block: &mut Block, value: Expression)
        -> Result<()> {

        block.assign(
            self.sp(),
            Expr::sub(self.sp().into(),
                      expr_const((value.bits() / 8) as u64, 32))?
        );
        block.store(self.sp().into(), value);
        Ok(())
    }
}