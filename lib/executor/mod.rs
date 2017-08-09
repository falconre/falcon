//! Various methods of executing over Falcon IL

use error::*;
use il;


/// Swaps the bytes of an expression (swaps endianness)
pub fn swap_bytes(expr: &il::Expression) -> Result<il::Expression> {
    match expr.bits() {
        8 => Ok(expr.clone()),
        16 => {
            // isolate bytes
            let b0 = il::Expression::trun(8, expr.clone())?;
            let b1 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(8, 16))?)?;
            // move to swapped locations
            let b0 = il::Expression::shl(
                il::Expression::zext(16, b0)?,
                il::expr_const(8, 16)
            )?;
            let b1 = il::Expression::zext(16, b1)?;
            Ok(il::Expression::or(b0, b1)?)
        }
        32 => {
            // isolate bytes
            let b0 = il::Expression::trun(8, expr.clone())?;
            let b1 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(8, 32))?)?;
            let b2 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(16, 32))?)?;
            let b3 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(24, 32))?)?;

            // move to swapped locations
            let b0 = il::Expression::shl(
                il::Expression::zext(32, b0)?,
                il::expr_const(24, 32)
            )?;
            let b1 = il::Expression::shl(
                il::Expression::zext(32, b1)?,
                il::expr_const(16, 32)
            )?;
            let b2 = il::Expression::shl(
                il::Expression::zext(32, b2)?,
                il::expr_const(8, 32)
            )?;
            let b3 = il::Expression::zext(32, b3)?;

            Ok(il::Expression::or(
                il::Expression::or(b0, b1)?,
                il::Expression::or(b2, b3)?
            )?)
        }
        64 => {
            // isolate bytes
            let b0 = il::Expression::trun(8, expr.clone())?;
            let b1 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(8, 64))?)?;
            let b2 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(16, 64))?)?;
            let b3 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(24, 64))?)?;
            let b4 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(32, 64))?)?;
            let b5 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(40, 64))?)?;
            let b6 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(48, 64))?)?;
            let b7 = il::Expression::trun(8,
                il::Expression::shr(expr.clone(), il::expr_const(56, 64))?)?;

            // move to swapped locations
            let b0 = il::Expression::shl(
                il::Expression::zext(64, b0)?,
                il::expr_const(56, 64)
            )?;
            let b1 = il::Expression::shl(
                il::Expression::zext(64, b1)?,
                il::expr_const(48, 64)
            )?;
            let b2 = il::Expression::shl(
                il::Expression::zext(64, b2)?,
                il::expr_const(40, 64)
            )?;
            let b3 = il::Expression::shl(
                il::Expression::zext(64, b3)?,
                il::expr_const(32, 64)
            )?;
            let b4 = il::Expression::shl(
                il::Expression::zext(64, b4)?,
                il::expr_const(24, 64)
            )?;
            let b5 = il::Expression::shl(
                il::Expression::zext(64, b5)?,
                il::expr_const(16, 64)
            )?;
            let b6 = il::Expression::shl(
                il::Expression::zext(64, b6)?,
                il::expr_const(8, 64)
            )?;
            let b7 = il::Expression::zext(64, b7)?;

            Ok(il::Expression::or(
                il::Expression::or(
                    il::Expression::or(b0, b1)?,
                    il::Expression::or(b2, b3)?
                )?,
                il::Expression::or(
                    il::Expression::or(b4, b5)?,
                    il::Expression::or(b6, b7)?
                )?
            )?)
        },
        _ => bail!("invalid bit-length {} for byte_swap", expr.bits())
    }
}


/// Takes an `il::Expression` where all terminals are `il::Constants`, and
/// returns an `il::Constant` with the result of the expression.
pub fn constants_expression(expr: &il::Expression) -> Result<il::Constant> {

    // shorthand for this function, for internal recursive use
    fn ece(expr: &il::Expression) -> Result<il::Constant> {
        constants_expression(expr)
    }

    match *expr {
        il::Expression::Scalar(_) => {
            bail!("constants_expression called with Scalar terminal")
        },

        il::Expression::Constant(ref constant) => Ok(constant.clone()),

        il::Expression::Add(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() + ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Sub(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value().wrapping_sub(ece(rhs)?.value());
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Mul(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() * ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Divu(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = ece(lhs)?.value() / rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Modu(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = ece(lhs)?.value() % rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Divs(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = (ece(lhs)?.value() as i64) / (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        il::Expression::Mods(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = (ece(lhs)?.value() as i64) % (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        il::Expression::And(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() & ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Or(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() | ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Xor(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() ^ ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Shl(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() << ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Shr(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() >> ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Cmpeq(ref lhs, ref rhs) => {
            if ece(lhs)?.value() == ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmpneq(ref lhs, ref rhs) => {
            if ece(lhs)?.value() != ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmplts(ref lhs, ref rhs) => {
            if (ece(lhs)?.value() as i64) < (ece(rhs)?.value() as i64) {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmpltu(ref lhs, ref rhs) => {
            if ece(lhs)?.value() < ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Zext(bits, ref rhs) |
        il::Expression::Trun(bits, ref rhs) => {
            Ok(il::Constant::new(ece(rhs)?.value(), bits))
        },

        il::Expression::Sext(bits, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() >> (rhs.bits() - 1) == 1 {
                let mask = !((1 << rhs.bits()) - 1);
                Ok(il::Constant::new(rhs.value() | mask, bits))
            }
            else {
                Ok(il::Constant::new(rhs.value(), bits))
            }
        }
    }
}