//! A Symbolic Execution engine for Falcon IL.
//!
//! `SymbolicEngine` represents one symbolic state in the program. It is not a complete
//! symbolic execution engine, we still need other pieces such as `EngineDriver`. We execute
//! operations over the `SymbolicEngine` to receive a variable number of `SymbolicSuccessor`s
//! in return. Each `SymbolicSuccessor` has a type representing how control flow should
//! behave.

use error::*;
use executor;
use il;


fn simplify_or(expr: &il::Expression) -> Result<il::Expression> {

    fn associate_left(lhs: il::Expression, rhs: il::Expression) -> Result<il::Expression> {
        match (lhs, rhs) {
            (il::Expression::Or(lhs_, rhs_), il::Expression::Constant(rhs_c)) => {
                if let il::Expression::Constant(_) = *lhs_ {
                    il::Expression::or(
                        executor::eval(&il::Expression::or(*lhs_, rhs_c.into())?)?.into(),
                        *rhs_
                    )
                }
                else if let il::Expression::Constant(_) = *rhs_ {
                    il::Expression::or(
                        executor::eval(&il::Expression::or(*rhs_, rhs_c.into())?)?.into(),
                        *lhs_
                    )
                }
                else {
                    il::Expression::or(il::Expression::or(*lhs_, *rhs_)?, rhs_c.into())
                }
            },
            (lhs, rhs) => il::Expression::or(lhs, rhs)
        }
    }

    fn associate_right(lhs: il::Expression, rhs: il::Expression) -> Result<il::Expression> {
        match (lhs, rhs) {
            (il::Expression::Constant(lhs_c), il::Expression::Or(lhs_, rhs_)) => {
                if let il::Expression::Constant(_) = *lhs_ {
                    il::Expression::or(
                        executor::eval(&il::Expression::or(*lhs_, lhs_c.into())?)?.into(),
                        *rhs_
                    )
                }
                else if let il::Expression::Constant(_) = *rhs_ {
                    il::Expression::or(
                        executor::eval(&il::Expression::or(*rhs_, lhs_c.into())?)?.into(),
                        *lhs_
                    )
                }
                else {
                    il::Expression::or(il::Expression::or(*lhs_, *rhs_)?, lhs_c.into())
                }
            },
            (lhs, rhs) => il::Expression::or(lhs, rhs)
        }
    }


    if let il::Expression::Or(ref lhs, ref rhs) = *expr {
        let lhs = simplify_expression(lhs)?;
        let rhs = simplify_expression(rhs)?;

        if let il::Expression::Constant(_) = lhs {
            if let il::Expression::Constant(_) = rhs {
                return Ok(executor::eval(&il::Expression::or(lhs, rhs)?)?.into());
            }
        }

        if let il::Expression::Or(lhs, rhs) = associate_left(lhs, rhs)? {
            return associate_right(*lhs, *rhs)
        }
        else {
            bail!("simplify_or associate_left didn't return il::Expression::Or")
        }
    }
    else {
        bail!("Non-or expression passed to simplify_or")
    }
}


/// Fold all constant expressions, leaving the bare minimum expression needed
/// to evaluate over scalars.
pub fn simplify_expression(expr: &il::Expression) -> Result<il::Expression> {
    Ok(match *expr {
        il::Expression::Constant(ref c) => c.clone().into(),
        il::Expression::Scalar(ref s) => s.clone().into(),
        // Handle Or separately for now, greatly simplifying memory loads/store expressions
        il::Expression::Or(_, _) => simplify_or(expr)?,
        il::Expression::Add(ref lhs, ref rhs) |
        il::Expression::Sub(ref lhs, ref rhs) |
        il::Expression::Mul(ref lhs, ref rhs) |
        il::Expression::Divu(ref lhs, ref rhs) |
        il::Expression::Modu(ref lhs, ref rhs) |
        il::Expression::Divs(ref lhs, ref rhs) |
        il::Expression::Mods(ref lhs, ref rhs) | 
        il::Expression::And(ref lhs, ref rhs) |
        il::Expression::Xor(ref lhs, ref rhs) |
        il::Expression::Shl(ref lhs, ref rhs) |
        il::Expression::Shr(ref lhs, ref rhs) |
        il::Expression::Cmpeq(ref lhs, ref rhs) |
        il::Expression::Cmpneq(ref lhs, ref rhs) |
        il::Expression::Cmplts(ref lhs, ref rhs) |
        il::Expression::Cmpltu(ref lhs, ref rhs) => {
            let lhs = simplify_expression(lhs)?;
            let rhs = simplify_expression(rhs)?;
            if let il::Expression::Constant(_) = lhs {
                if let il::Expression::Constant(_) = rhs {
                    return Ok(match *expr {
                        il::Expression::Add(_, _) => 
                            executor::eval(&il::Expression::add(lhs, rhs)?)?.into(),                        
                        il::Expression::Sub(_, _) => 
                            executor::eval(&il::Expression::sub(lhs, rhs)?)?.into(),
                        il::Expression::Mul(_, _) => 
                            executor::eval(&il::Expression::mul(lhs, rhs)?)?.into(),
                        il::Expression::Divu(_, _) => 
                            executor::eval(&il::Expression::divu(lhs, rhs)?)?.into(),
                        il::Expression::Modu(_, _) => 
                            executor::eval(&il::Expression::modu(lhs, rhs)?)?.into(),
                        il::Expression::Divs(_, _) => 
                            executor::eval(&il::Expression::divs(lhs, rhs)?)?.into(),
                        il::Expression::Mods(_, _) => 
                            executor::eval(&il::Expression::mods(lhs, rhs)?)?.into(),
                        il::Expression::And(_, _) => 
                            executor::eval(&il::Expression::and(lhs, rhs)?)?.into(),
                        il::Expression::Xor(_, _) => 
                            executor::eval(&il::Expression::xor(lhs, rhs)?)?.into(),
                        il::Expression::Shl(_, _) => 
                            executor::eval(&il::Expression::shl(lhs, rhs)?)?.into(),
                        il::Expression::Shr(_, _) => 
                            executor::eval(&il::Expression::shr(lhs, rhs)?)?.into(),
                        il::Expression::Cmpeq(_, _) => 
                            executor::eval(&il::Expression::cmpeq(lhs, rhs)?)?.into(),
                        il::Expression::Cmpneq(_, _) => 
                            executor::eval(&il::Expression::cmpneq(lhs, rhs)?)?.into(),
                        il::Expression::Cmplts(_, _) => 
                            executor::eval(&il::Expression::cmplts(lhs, rhs)?)?.into(),
                        il::Expression::Cmpltu(_, _) => 
                            executor::eval(&il::Expression::cmpltu(lhs, rhs)?)?.into(),
                        _ => bail!("Unreachable in simplify_expression")
                    }) // return match expr
                } // if let il::Expression::Constant(rhs) = rhs
            } // if let il::Expression::Constant(lhs) = lhs
            match *expr {
                il::Expression::Add(_, _) => il::Expression::add(lhs, rhs)?,
                il::Expression::Sub(_, _) => il::Expression::sub(lhs, rhs)?,
                il::Expression::Mul(_, _) => il::Expression::mul(lhs, rhs)?,
                il::Expression::Divu(_, _) => il::Expression::divu(lhs, rhs)?,
                il::Expression::Modu(_, _) => il::Expression::modu(lhs, rhs)?,
                il::Expression::Divs(_, _) => il::Expression::divs(lhs, rhs)?,
                il::Expression::Mods(_, _) => il::Expression::mods(lhs, rhs)?,
                il::Expression::And(_, _) => il::Expression::and(lhs, rhs)?,
                il::Expression::Xor(_, _) => il::Expression::xor(lhs, rhs)?,
                il::Expression::Shl(_, _) => il::Expression::shl(lhs, rhs)?,
                il::Expression::Shr(_, _) => il::Expression::shr(lhs, rhs)?,
                il::Expression::Cmpeq(_, _) => il::Expression::cmpeq(lhs, rhs)?,
                il::Expression::Cmpneq(_, _) => il::Expression::cmpneq(lhs, rhs)?,
                il::Expression::Cmplts(_, _) => il::Expression::cmplts(lhs, rhs)?,
                il::Expression::Cmpltu(_, _) => il::Expression::cmpltu(lhs, rhs)?,
                _ => bail!("Unreachable in simplify_expression")
            } // match expr
        },
        il::Expression::Zext(bits, ref rhs) |
        il::Expression::Sext(bits, ref rhs) |
        il::Expression::Trun(bits, ref rhs) => {
            let rhs = simplify_expression(rhs)?;
            if let il::Expression::Constant(_) = rhs {
                match *expr {
                    il::Expression::Zext(_, _) =>
                        executor::eval(&il::Expression::zext(bits, rhs)?)?.into(),
                    il::Expression::Sext(_, _) =>
                        executor::eval(&il::Expression::sext(bits, rhs)?)?.into(),
                    il::Expression::Trun(_, _) =>
                        executor::eval(&il::Expression::trun(bits, rhs)?)?.into(),
                    _ => bail!("Unreachable in simplify_expression")
                }
            }
            else {
                match *expr {
                    il::Expression::Zext(bits, ref rhs) => il::Expression::zext(bits, simplify_expression(rhs)?)?,
                    il::Expression::Sext(bits, ref rhs) => il::Expression::sext(bits, simplify_expression(rhs)?)?,
                    il::Expression::Trun(bits, ref rhs) => il::Expression::trun(bits, simplify_expression(rhs)?)?,
                    _ => bail!("Unreachable in simplify_expression")
                }
            }
        }
    })// match expr
}


/// Convert a falcon expression to its `smtlib2` equivalent.
pub fn expr_to_smtlib2(expr: &il::Expression) -> String {
    match *expr {
        il::Expression::Constant(ref c) => {
            if c.bits() == 1 {
                format!("#b{}", c.value())
            }
            else {
                format!("#x{:01$x}", c.value(), c.bits() / 4)
            }
        },
        il::Expression::Scalar(ref s) => {
            s.name().to_string()
        }
        il::Expression::Add ( ref lhs, ref rhs ) =>
            format!("(bvadd {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Sub ( ref lhs, ref rhs ) =>
            format!("(bvsub {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Mul ( ref lhs, ref rhs ) =>
            format!("(bvmul {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Divu ( ref lhs, ref rhs ) =>
            format!("(bvudiv {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Modu ( ref lhs, ref rhs ) =>
            format!("(bvumod {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Divs ( ref lhs, ref rhs ) =>
            format!("(bvsdiv {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Mods ( ref lhs, ref rhs ) =>
            format!("(bvsmod {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::And ( ref lhs, ref rhs ) =>
            format!("(bvand {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Or ( ref lhs, ref rhs ) =>
            format!("(bvor {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Xor ( ref lhs, ref rhs ) =>
            format!("(bvxor {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Shl ( ref lhs, ref rhs ) =>
            format!("(bvshl {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Shr ( ref lhs, ref rhs ) =>
            format!("(bvlshr {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Cmpeq ( ref lhs, ref rhs ) =>
            format!("(ite (= {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmpneq ( ref lhs, ref rhs ) =>
            format!("(ite (!= {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmplts ( ref lhs, ref rhs ) =>
            format!("(ite (bvslt {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmpltu ( ref lhs, ref rhs ) =>
            format!("(ite (bvult {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Zext ( bits, ref rhs ) =>
            format!("(concat (_ bv0 {}) {})",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Sext ( bits, ref rhs ) =>
            format!("((_ sign_extend {}) {})",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Trun ( bits, ref rhs ) =>
            format!("((_ extract {} 0) {})", bits - 1, expr_to_smtlib2(rhs))
    }
}