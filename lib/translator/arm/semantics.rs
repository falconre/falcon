use error::*;
use falcon_capstone::capstone;
use falcon_capstone::capstone_sys::{arm_op_type, arm_reg, cs_arm_op};
use il::Expression as Expr;
use il::*;

/// Struct for dealing with x86 registers
pub struct ARMRegister {
    name: &'static str,
    // The capstone enum value for this register.
    capstone_reg: arm_reg,
    /// The size of this register in bits
    bits: usize,
}

impl ARMRegister {
    pub fn name(&self) -> &str {
        self.name
    }

    pub fn scalar(&self) -> Scalar {
        scalar(self.name, self.bits)
    }

    pub fn expression(&self) -> Expr {
        expr_scalar(self.name, self.bits)
    }
}

const ARM_REGISTERS: &'static [ARMRegister] = &[
    ARMRegister {
        name: "r0",
        capstone_reg: arm_reg::ARM_REG_R0,
        bits: 32,
    },
    ARMRegister {
        name: "r1",
        capstone_reg: arm_reg::ARM_REG_R1,
        bits: 32,
    },
    ARMRegister {
        name: "r2",
        capstone_reg: arm_reg::ARM_REG_R2,
        bits: 32,
    },
    ARMRegister {
        name: "r3",
        capstone_reg: arm_reg::ARM_REG_R3,
        bits: 32,
    },
    ARMRegister {
        name: "r4",
        capstone_reg: arm_reg::ARM_REG_R4,
        bits: 32,
    },
    ARMRegister {
        name: "r5",
        capstone_reg: arm_reg::ARM_REG_R5,
        bits: 32,
    },
    ARMRegister {
        name: "r6",
        capstone_reg: arm_reg::ARM_REG_R6,
        bits: 32,
    },
    ARMRegister {
        name: "r7",
        capstone_reg: arm_reg::ARM_REG_R7,
        bits: 32,
    },
    ARMRegister {
        name: "r8",
        capstone_reg: arm_reg::ARM_REG_R8,
        bits: 32,
    },
    ARMRegister {
        name: "r9",
        capstone_reg: arm_reg::ARM_REG_R9,
        bits: 32,
    },
    ARMRegister {
        name: "r10",
        capstone_reg: arm_reg::ARM_REG_R10,
        bits: 32,
    },
    ARMRegister {
        name: "r11",
        capstone_reg: arm_reg::ARM_REG_R11,
        bits: 32,
    },
    ARMRegister {
        name: "r12",
        capstone_reg: arm_reg::ARM_REG_R12,
        bits: 32,
    },
    ARMRegister {
        name: "lr",
        capstone_reg: arm_reg::ARM_REG_LR,
        bits: 32,
    },
    ARMRegister {
        name: "sp",
        capstone_reg: arm_reg::ARM_REG_SP,
        bits: 32,
    },
    ARMRegister {
        name: "pc",
        capstone_reg: arm_reg::ARM_REG_PC,
        bits: 32,
    },
];

struct RegisterMaker<'a> {
    instruction: &'a capstone::Instr,
}

impl<'a> RegisterMaker<'a> {
    pub fn new(instruction: &'a capstone::Instr) -> RegisterMaker<'a> {
        RegisterMaker { instruction }
    }

    pub fn scalar(&self, register: arm_reg) -> Result<Scalar> {
        for r in ARM_REGISTERS.iter() {
            if r.capstone_reg == register {
                return Ok(r.scalar());
            }
        }
        Err("Could not find register".into())
    }

    pub fn reg_expression(&self, register: arm_reg) -> Result<Expression> {
        match self.scalar(register) {
            Ok(scalar) => Ok(scalar.into()),
            Err(e) => match register {
                arm_reg::ARM_REG_PC => Ok(expr_const(self.instruction.address, 32)),
                _ => Err(e),
            },
        }
    }

    pub fn expression(&self, operand: &cs_arm_op) -> Result<Expression> {
        match operand.type_ {
            arm_op_type::ARM_OP_REG => self.reg_expression(operand.reg()),
            arm_op_type::ARM_OP_IMM => Ok(const_(operand.imm() as u64, 32).sext(64)?.into()),
            _ => unimplemented!("Unimplemented operand type {:?}", operand.type_),
        }
    }
}

/// Returns the details section of a mips capstone instruction.
pub fn details(instruction: &capstone::Instr) -> Result<capstone::cs_arm> {
    let detail = instruction.detail.as_ref().unwrap();
    match detail.arch {
        capstone::DetailsArch::ARM(x) => Ok(x),
        _ => Err("Could not get instruction details".into()),
    }
}

pub fn binop<F>(
    control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
    f: F,
) -> Result<()>
where
    F: Fn(Expression, Expression) -> Result<Expression>,
{
    let detail = details(instruction)?;

    let register_maker = RegisterMaker::new(instruction);

    // get operands
    let dst = register_maker.scalar(detail.operands[0].reg())?;
    let lhs = register_maker.reg_expression(detail.operands[1].reg())?;
    let rhs = register_maker.expression(&detail.operands[2])?;

    let block_index = {
        let block = control_flow_graph.new_block()?;

        let src = f(lhs, rhs)?;
        block.assign(dst, src);

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

pub fn adc(
    mut control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    binop(&mut control_flow_graph, instruction, |lhs, rhs| {
        Ok(Expression::add(
            Expression::add(lhs, rhs)?,
            Expression::zext(32, expr_scalar("C", 1))?,
        )?)
    })
}

pub fn add(
    mut control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    binop(&mut control_flow_graph, instruction, |lhs, rhs| {
        Ok(Expression::add(lhs, rhs)?)
    })
}

pub fn and(
    mut control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    binop(&mut control_flow_graph, instruction, |lhs, rhs| {
        Ok(Expression::and(lhs, rhs)?)
    })
}

pub fn asr(
    mut control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    binop(&mut control_flow_graph, instruction, |lhs, rhs| {
        // Move the sign bit to the low position
        let sign_bit_location = expr_const((1 << lhs.bits() - 1) as u64, lhs.bits());
        let sign_bit = Expression::shr(lhs.clone(), sign_bit_location)?;
        // Subtract sign_bit from 0, which gives us all 0000 or all ffff
        let mask = Expression::sub(expr_const(0, lhs.bits()), sign_bit)?;
        // shift that mask left
        let mask = Expression::shl(
            mask,
            Expression::sub(expr_const(lhs.bits() as u64, lhs.bits()), rhs.clone())?,
        )?;
        // Do the shift right
        let shr = Expression::shr(lhs, rhs)?;
        // Or with mask
        Ok(Expression::or(shr, mask)?)
    })
}

pub fn orr(
    mut control_flow_graph: &mut ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<()> {
    binop(&mut control_flow_graph, instruction, |lhs, rhs| {
        Ok(Expression::or(lhs, rhs)?)
    })
}
