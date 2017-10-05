use error::*;
use il;

fn sign_extend(constant: &il::Constant) -> i64 {
    let value: u64 = constant.value();
    let mut mask: u64 = 0xffffffffffffffff;
    mask <<= constant.bits();
    if constant.value() & (1 << (constant.bits() - 1)) != 0 {
        (value | mask) as i64
    }
    else {
        value as i64
    }
}

pub fn eval(expr: &il::Expression) -> Result<il::Constant> {

    match *expr {
        il::Expression::Scalar(ref scalar) => {
            return Err(ErrorKind::ExecutorScalar(scalar.name().to_string()).into());
        },

        il::Expression::Constant(ref constant) => Ok(constant.clone()),

        il::Expression::Add(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() + eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Sub(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value().wrapping_sub(eval(rhs)?.value());
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Mul(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() * eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Divu(ref lhs, ref rhs) => {
            let rhs = eval(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = eval(lhs)?.value() / rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Modu(ref lhs, ref rhs) => {
            let rhs = eval(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = eval(lhs)?.value() % rhs.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Divs(ref lhs, ref rhs) => {
            let rhs = eval(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = (eval(lhs)?.value() as i64) / (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        il::Expression::Mods(ref lhs, ref rhs) => {
            let rhs = eval(rhs)?;
            if rhs.value() == 0 {
                return Err(ErrorKind::Arithmetic("Division by zero".to_string()).into());
            }
            let r = (eval(lhs)?.value() as i64) % (rhs.value() as i64);
            Ok(il::Constant::new(r as u64, lhs.bits()))
        },

        il::Expression::And(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() & eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Or(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() | eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Xor(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() ^ eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Shl(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() << eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Shr(ref lhs, ref rhs) => {
            let r = eval(lhs)?.value() >> eval(rhs)?.value();
            Ok(il::Constant::new(r, lhs.bits()))
        },

        il::Expression::Cmpeq(ref lhs, ref rhs) => {
            if eval(lhs)?.value() == eval(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmpneq(ref lhs, ref rhs) => {
            if eval(lhs)?.value() != eval(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmplts(ref lhs, ref rhs) => {
            if sign_extend(&eval(lhs)?) < sign_extend(&eval(rhs)?) {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Cmpltu(ref lhs, ref rhs) => {
            if eval(lhs)?.value() < eval(rhs)?.value() {
                Ok(il::Constant::new(1, 1))
            }
            else {
                Ok(il::Constant::new(0, 1))
            }
        },

        il::Expression::Zext(bits, ref rhs) |
        il::Expression::Trun(bits, ref rhs) => {
            Ok(il::Constant::new(eval(rhs)?.value(), bits))
        },

        il::Expression::Sext(bits, ref rhs) => {
            let rhs = eval(rhs)?;
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