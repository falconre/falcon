//! Various ways of executing over Falcon IL

use error::*;
use il;


/// Takes an `il::Expression` where all terminals are `il::Constants`, and
/// returns an `il::Constant` with the result of the expression.
pub fn constants_expression(expr: &il::Expression) -> Result<il::Constant> {

    // shorthand for this function, for internal recursive use
    fn ece(expr: &il::Expression) -> Result<il::Constant> {
        constants_expression(expr)
    }

    match expr {
        &il::Expression::Variable(ref v) => {
            bail!("execute_constants_expression called with Variable terminal")
        },

        &il::Expression::Constant(ref constant) => Ok(constant.clone()),

        &il::Expression::Add(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() + ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Sub(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value().wrapping_sub(ece(rhs)?.value());
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Mulu(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() * ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Divu(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic.into());
            }
            let r = ece(lhs)?.value() / rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Modu(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic.into());
            }
            let r = ece(lhs)?.value() % rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Muls(ref lhs, ref rhs) => {
            let r = (ece(lhs)?.value() as i64) * (ece(rhs)?.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        &il::Expression::Divs(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic.into());
            }
            let r = (ece(lhs)?.value() as i64) / (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        &il::Expression::Mods(ref lhs, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic.into());
            }
            let r = (ece(lhs)?.value() as i64) % (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        &il::Expression::And(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() & ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Or(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() | ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Xor(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() ^ ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Shl(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() << ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Shr(ref lhs, ref rhs) => {
            let r = ece(lhs)?.value() >> ece(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        &il::Expression::Cmpeq(ref lhs, ref rhs) => {
            if ece(lhs)?.value() == ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        &il::Expression::Cmpneq(ref lhs, ref rhs) => {
            if ece(lhs)?.value() != ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        &il::Expression::Cmplts(ref lhs, ref rhs) => {
            if (ece(lhs)?.value() as i64) < (ece(rhs)?.value() as i64) {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        &il::Expression::Cmpltu(ref lhs, ref rhs) => {
            if ece(lhs)?.value() < ece(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        &il::Expression::Zext(bits, ref rhs) => {
            Ok(il::Constant::new(ece(rhs)?.value(), bits))
        },

        &il::Expression::Sext(bits, ref rhs) => {
            let rhs = ece(rhs)?;
            if rhs.value() >> rhs.bits() - 1 == 1 {
                let mask = !((1 << rhs.bits()) - 1);
                Ok(il::Constant::new(rhs.value() | mask, bits))
            }
            else {
                Ok(il::Constant::new(rhs.value(), bits))
            }
        },

        &il::Expression::Trun(bits, ref rhs) => {
            Ok(il::Constant::new(ece(rhs)?.value(), bits))
        }
    }
}