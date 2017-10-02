//! Various methods of executing over Falcon IL

use error::*;
use il;

pub mod engine;
pub mod eval;
pub mod driver;
pub mod memory;
pub mod successor;

pub use self::eval::eval;


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
