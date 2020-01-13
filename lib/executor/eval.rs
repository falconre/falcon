use crate::error::*;
use crate::il;

/// Evaluate an `il::Expression` where all terminals are `il::Constant`, and
/// return the resulting `il::Constant`.
pub fn eval(expr: &il::Expression) -> Result<il::Constant> {
    Ok(match *expr {
        il::Expression::Scalar(ref scalar) => {
            return Err(ErrorKind::ExecutorScalar(scalar.name().to_string()).into());
        }
        il::Expression::Constant(ref constant) => constant.clone(),
        il::Expression::Add(ref lhs, ref rhs) => eval(lhs)?.add(&eval(rhs)?)?,
        il::Expression::Sub(ref lhs, ref rhs) => eval(lhs)?.sub(&eval(rhs)?)?,
        il::Expression::Mul(ref lhs, ref rhs) => eval(lhs)?.mul(&eval(rhs)?)?,
        il::Expression::Divu(ref lhs, ref rhs) => eval(lhs)?.divu(&eval(rhs)?)?,
        il::Expression::Modu(ref lhs, ref rhs) => eval(lhs)?.modu(&eval(rhs)?)?,
        il::Expression::Divs(ref lhs, ref rhs) => eval(lhs)?.divs(&eval(rhs)?)?,
        il::Expression::Mods(ref lhs, ref rhs) => eval(lhs)?.mods(&eval(rhs)?)?,
        il::Expression::And(ref lhs, ref rhs) => eval(lhs)?.and(&eval(rhs)?)?,
        il::Expression::Or(ref lhs, ref rhs) => eval(lhs)?.or(&eval(rhs)?)?,
        il::Expression::Xor(ref lhs, ref rhs) => eval(lhs)?.xor(&eval(rhs)?)?,
        il::Expression::Shl(ref lhs, ref rhs) => eval(lhs)?.shl(&eval(rhs)?)?,
        il::Expression::Shr(ref lhs, ref rhs) => eval(lhs)?.shr(&eval(rhs)?)?,
        il::Expression::Cmpeq(ref lhs, ref rhs) => eval(lhs)?.cmpeq(&eval(rhs)?)?,
        il::Expression::Cmpneq(ref lhs, ref rhs) => eval(lhs)?.cmpneq(&eval(rhs)?)?,
        il::Expression::Cmplts(ref lhs, ref rhs) => eval(lhs)?.cmplts(&eval(rhs)?)?,
        il::Expression::Cmpltu(ref lhs, ref rhs) => eval(lhs)?.cmpltu(&eval(rhs)?)?,
        il::Expression::Zext(bits, ref rhs) => eval(rhs)?.zext(bits)?,
        il::Expression::Trun(bits, ref rhs) => eval(rhs)?.trun(bits)?,
        il::Expression::Sext(bits, ref rhs) => eval(rhs)?.sext(bits)?,
        il::Expression::Ite(ref cond, ref then, ref else_) => {
            if eval(cond)?.is_one() {
                eval(then)?
            } else {
                eval(else_)?
            }
        }
    })
}

#[test]
fn add() {
    let lhs = il::expr_const(0x570000, 32);
    let rhs = il::expr_const(0x703c, 32);
    let expr = il::Expression::add(lhs, rhs).unwrap();
    assert_eq!(eval(&expr).unwrap(), il::const_(0x57703c, 32));

    let lhs = il::expr_const(0xffffffff, 32);
    let rhs = il::expr_const(0x1, 32);
    let expr = il::Expression::add(lhs, rhs).unwrap();
    assert_eq!(eval(&expr).unwrap(), il::const_(0, 32));
}

#[test]
fn cmplts() {
    let lhs = il::expr_const(0xffffffff, 32);
    let rhs = il::expr_const(0, 32);
    let expr = il::Expression::cmplts(lhs, rhs).unwrap();
    assert_eq!(eval(&expr).unwrap(), il::const_(1, 1));

    let lhs = il::expr_const(0, 32);
    let rhs = il::expr_const(0xffffffff, 32);
    let expr = il::Expression::cmplts(lhs, rhs).unwrap();
    assert_eq!(eval(&expr).unwrap(), il::const_(0, 1));
}
