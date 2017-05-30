use il;
use error::Error;

struct Register {
    name: &'static str,
    encoding: u8
}


const REGISTERS : &'static [Register] = &[
    Register {name: "r0",  encoding: 0x0},
    Register {name: "r1",  encoding: 0x1},
    Register {name: "r2",  encoding: 0x2},
    Register {name: "r3",  encoding: 0x3},
    Register {name: "r4",  encoding: 0x4},
    Register {name: "r5",  encoding: 0x5},
    Register {name: "r6",  encoding: 0x6},
    Register {name: "rip", encoding: 0x7},
    Register {name: "rbp", encoding: 0x8},
    Register {name: "rsp", encoding: 0x9},
    Register {name: "r7",  encoding: 0xA},
];



fn decode_register(byte: u8) -> Result<il::Variable, Error> {
    match byte {
        0 => Ok(il::Variable::new("r0", 16)),
        1 => Ok(il::Variable::new("r1", 16)),
        2 => Ok(il::Variable::new("r2", 16)),
        3 => Ok(il::Variable::new("r3", 16)),
        4 => Ok(il::Variable::new("r4", 16)),
        5 => Ok(il::Variable::new("r5", 16)),
        6 => Ok(il::Variable::new("r6", 16)),
        7 => Ok(il::Variable::new("rip", 16)),
        8 => Ok(il::Variable::new("rbp", 16)),
        9 => Ok(il::Variable::new("rsp", 16)),
        10 => Ok(il::Variable::new("r7", 16)),
        _ => Err("Invalid register encoding".into())
    }
}



fn decode_lval(bytes: &[u8]) -> Result<il::Constant, Error> {
    let lval = ((bytes[2] as u64) << 8) | (bytes[3] as u64);
    Ok(il::Constant::new(lval, 16))
}



fn decode_b(bytes: &[u8]) -> Result<il::Variable, Error> {
    decode_register(bytes[1])
}


fn decode_c(bytes: &[u8]) -> Result<(il::Variable, il::Variable), Error> {
    let var_a = try!(decode_register(bytes[1]));
    let var_b = try!(decode_register(bytes[2]));
    Ok((var_a, var_b))
}


fn decode_d(bytes: &[u8])
    ->
Result<(il::Variable, il::Variable, il::Variable), Error> {
    let var_a = try!(decode_register(bytes[1]));
    let var_b = try!(decode_register(bytes[2]));
    let var_c = try!(decode_register(bytes[3]));
    Ok((var_a, var_b, var_c))
}


fn decode_e(bytes: &[u8]) -> Result<(il::Variable, il::Constant), Error> {
    let var_a = try!(decode_register(bytes[1]));
    let lval = try!(decode_lval(bytes));
    Ok((var_a, lval))
}


fn decode_f(bytes: &[u8]) -> Result<il::Constant, Error> {
    decode_lval(bytes)
}


fn decode_operation(bytes: &[u8]) -> Result<il::Operation, Error> {
    if bytes.len() < 4 {
        return Err("instruction too short".into());
    }

    /*
    // Arithmetic operations
    if bytes[0] >= 0x10 && bytes[0] < 0x20 {
        let dst = decode_register(bytes[1])?;
        let (lhs, rhs) = match bytes[0] & 0x1 {
            0 => {
                (
                    Expression::variable(decode_register(bytes[2])?),
                    Expression::variable(decode_register(bytes[3])?)
                )
            },
            1 => {
                (
                    Expression::variable(decode_register(bytes[1])?),
                    Expression::constant(decode_lval(bytes)?)
                )
            }
            _ => return Err("Error decoding arithmetic operands".into())
        };

        return match bytes[0] & 0xe {
            0 => Ok(Operation::Assign {
                dst: dst,
                src: Expression::Add(Box::new(lhs), Box::new(rhs))
            }),
            2 => Ok(Operation::Assign {
                dst: dst,
                src: Expression::Sub(Box::new(lhs), Box::new(rhs))
            }),
            4 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::Mul(Box::new(lhs), Box::new(rhs))
            }),
            6 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::Divu(Box::new(lhs), Box::new(rhs)),
            }),
            8 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::Modu(Box::new(lhs), Box::new(rhs))
            }),
            10 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::And(Box::new(lhs), Box::new(rhs))
            }),
            12 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::Or(Box::new(lhs), Box::new(rhs))
            }),
            14 => Ok(il::Instruction::Assign {
                dst: dst,
                src: il::Expression::Xor(Box::new(lhs), Box::new(rhs))
            }),
            _ => Err("Error decoding instruction".into())
        }
    }

    let branch = Expression::add(
        Expression::variable(Variable::new("rip", 16)),
        Expression::constant(decode_lval(bytes)?));

    match bytes[0] {
        // JMP
        0x20 => {
            Ok(il::Instruction::Brc {
                dst: branch,
                condition: il::Expression::constant(il::Constant::new(1, 1))
            })
        },

        // JE
        0x21 => {
            Ok(Instruction::Brc {
                dst: branch,
                condition: Expression::cmpeq(
                    Expression::variable(Variable::new("flags", 16)),
                    Expression::constant(Constant::new(0, 16))
                )
            })
        },

        // JNE
        0x22 => {
            Ok(Instruction::Brc {
                dst: branch,
                condition: Expression::cmpltu(
                    Expression::constant(Constant::new(0, 16)),
                    Expression::variable(Variable::new("flags", 16))
                )
            })
        }

        // JL
        0x23 => {
            Ok(Instruction::Brc {
                dst: branch,
                condition: Expression::cmplts(
                    Expression::variable(Variable::new("flags", 16)),
                    Expression::constant(Constant::new(0, 16))
                )
            })
        }


        _ => Err("Error decoding instruction".into())
    }
    */

    Err("".into())
}