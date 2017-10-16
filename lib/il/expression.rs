//! An `Expression`.
//!
//! # Expression Rules
//! ## Bitness
//! We refer to the number of bits in the result of an `Expression` as its _bitness_.
//!
//! Expressions must always have the same bitness. For example, you cannot add an 8-bit and a
//! 16-bit expression. You must extern or truncate one of these operands until the bitness
//! matches. The bitness of all comparison expressions is always 1.
//!
//! # Expression Breakdown
//! ## Terminals
//! `scalar`, `constant`
//!
//! ## Binary Arithmetic
//! `add`, `sub`, `divu`, `modu`, `divs`, `mods`, `and`, `or`, `xor`, `shl`, `shr`
//!
//! ## Comparison
//! `cmpeq`, `cmpneq`, `cmplts`, `cmpltu`
//!
//! ## Extension/Truncation
//! `zext`, `sext`, `trun`

use std::fmt;

use il::*;

/// An IL Expression.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Expression {
    Scalar(Scalar),
    Constant(Constant),

    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mul(Box<Expression>, Box<Expression>),
    Divu(Box<Expression>, Box<Expression>),
    Modu(Box<Expression>, Box<Expression>),
    Divs(Box<Expression>, Box<Expression>),
    Mods(Box<Expression>, Box<Expression>),
    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Xor(Box<Expression>, Box<Expression>),
    Shl(Box<Expression>, Box<Expression>),
    Shr(Box<Expression>, Box<Expression>),

    Cmpeq(Box<Expression>, Box<Expression>),
    Cmpneq(Box<Expression>, Box<Expression>),
    Cmplts(Box<Expression>, Box<Expression>),
    Cmpltu(Box<Expression>, Box<Expression>),

    Zext(usize, Box<Expression>),
    Sext(usize, Box<Expression>),
    Trun(usize, Box<Expression>),
}


impl Expression {
    /// Return the bitness of this expression.
    pub fn bits(&self) -> usize {
        match *self {
            Expression::Scalar(ref scalar) => scalar.bits(),
            Expression::Constant(ref constant) => constant.bits(),
            Expression::Add(ref lhs, _) |
            Expression::Sub(ref lhs, _) |
            Expression::Mul(ref lhs, _) |
            Expression::Divu(ref lhs, _) |
            Expression::Modu(ref lhs, _) |
            Expression::Divs(ref lhs, _) |
            Expression::Mods(ref lhs, _) |
            Expression::And(ref lhs, _) |
            Expression::Or(ref lhs, _) |
            Expression::Xor(ref lhs, _) |
            Expression::Shl(ref lhs, _) |
            Expression::Shr(ref lhs, _) => lhs.bits(),
            Expression::Cmpeq(_, _) |
            Expression::Cmpneq(_, _) |
            Expression::Cmplts(_, _) |
            Expression::Cmpltu(_, _) => 1,
            Expression::Zext(bits, _) |
            Expression::Sext(bits, _) |
            Expression::Trun(bits, _) => bits
        }
    }


    /// Ensures the bits of both lhs and rhs are the same. If no_flags is true,
    /// Also ensures this expression doesn't include flags (which have a sort
    /// of 0)
    fn ensure_sort(lhs: &Expression, rhs: &Expression, no_flags: bool) -> Result<()> {
        if    lhs.bits() != rhs.bits() 
           || (no_flags && lhs.bits() == 0) {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(())
        }
    }

    /// Returns all `Scalars` used in this `Expression`
    pub fn scalars(&self) -> Vec<&Scalar> {
        let mut scalars: Vec<&Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref scalar) => {
                scalars.push(scalar)
            }
            Expression::Constant(_) => {}
            Expression::Add(ref lhs, ref rhs) |
            Expression::Sub(ref lhs, ref rhs) |
            Expression::Mul(ref lhs, ref rhs) |
            Expression::Divu(ref lhs, ref rhs) |
            Expression::Modu(ref lhs, ref rhs) |
            Expression::Divs(ref lhs, ref rhs) |
            Expression::Mods(ref lhs, ref rhs) |
            Expression::And(ref lhs, ref rhs) |
            Expression::Or(ref lhs, ref rhs) |
            Expression::Xor(ref lhs, ref rhs) |
            Expression::Shl(ref lhs, ref rhs) |
            Expression::Shr(ref lhs, ref rhs) |
            Expression::Cmpeq(ref lhs, ref rhs) |
            Expression::Cmpneq(ref lhs, ref rhs) |
            Expression::Cmplts(ref lhs, ref rhs) |
            Expression::Cmpltu(ref lhs, ref rhs) => {
                scalars.append(&mut lhs.scalars());
                scalars.append(&mut rhs.scalars());
            },
            Expression::Zext(_, ref rhs) |
            Expression::Sext(_, ref rhs) |
            Expression::Trun(_, ref rhs) => {
                scalars.append(&mut rhs.scalars());
            }
        }
        scalars
    }

    /// Return mutable references to all `Scalars` in this `Expression`.
    pub fn scalars_mut(&mut self) -> Vec<&mut Scalar> {
        let mut scalars: Vec<&mut Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref mut scalar) => {
                scalars.push(scalar)
            }
            Expression::Constant(_) => {}
            Expression::Add(ref mut lhs, ref mut rhs) |
            Expression::Sub(ref mut lhs, ref mut rhs) |
            Expression::Mul(ref mut lhs, ref mut rhs) |
            Expression::Divu(ref mut lhs, ref mut rhs) |
            Expression::Modu(ref mut lhs, ref mut rhs) |
            Expression::Divs(ref mut lhs, ref mut rhs) |
            Expression::Mods(ref mut lhs, ref mut rhs) |
            Expression::And(ref mut lhs, ref mut rhs) |
            Expression::Or(ref mut lhs, ref mut rhs) |
            Expression::Xor(ref mut lhs, ref mut rhs) |
            Expression::Shl(ref mut lhs, ref mut rhs) |
            Expression::Shr(ref mut lhs, ref mut rhs) |
            Expression::Cmpeq(ref mut lhs, ref mut rhs) |
            Expression::Cmpneq(ref mut lhs, ref mut rhs) |
            Expression::Cmplts(ref mut lhs, ref mut rhs) |
            Expression::Cmpltu(ref mut lhs, ref mut rhs) => {
                scalars.append(&mut lhs.scalars_mut());
                scalars.append(&mut rhs.scalars_mut());
            },
            Expression::Zext(_, ref mut rhs) |
            Expression::Sext(_, ref mut rhs) |
            Expression::Trun(_, ref mut rhs) => {
                scalars.append(&mut rhs.scalars_mut());
            }
        }
        scalars
    }

    /// Create a new `Expression` from a `Scalar`.
    pub fn scalar(scalar: Scalar) -> Expression {
        Expression::Scalar(scalar)
    }

    /// Create a new `Expression` from a `Constant`.
    pub fn constant(constant: Constant) -> Expression {
        Expression::Constant(constant)
    }

    /// Create an addition `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same
    pub fn add(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Add(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a subtraction `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn sub(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Sub(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned multiplication `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mul(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Mul(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned division `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Divu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned modulus `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn modu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Modu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed division `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divs(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Divs(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed modulus `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mods(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Mods(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary and `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn and(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::And(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary or `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn or(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Or(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary xor `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn xor(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Xor(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-left `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shl(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Shl(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-right `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shr(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Shr(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an equals comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpeq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpeq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an not equals comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpneq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpneq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned less-than comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpltu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpltu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed less-than comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmplts(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmplts(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an expression to zero-extend src to the number of bits specified
    /// in bits.
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn zext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Zext(bits, Box::new(src)))
    }

    /// Create an expression to sign-extend src to the number of bits specified
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn sext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Sext(bits, Box::new(src)))
    }

    /// Create an expression to truncate the number of bits in src to the number
    /// of bits given.
    /// # Error
    /// src has less-than or equal bits than bits
    pub fn trun(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() <= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Trun(bits, Box::new(src)))
    }
}


impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Expression::Scalar(ref s) => s.fmt(f),
            Expression::Constant(ref c) => c.fmt(f),
            Expression::Add(ref lhs, ref rhs) => 
                write!(f, "({} + {})", lhs, rhs),
            Expression::Sub(ref lhs, ref rhs) =>
                write!(f, "({} - {})", lhs, rhs),
            Expression::Mul(ref lhs, ref rhs) =>
                write!(f, "({} * {})", lhs, rhs),
            Expression::Divu(ref lhs, ref rhs) =>
                write!(f, "({} /u {})", lhs, rhs),
            Expression::Modu(ref lhs, ref rhs) =>
                write!(f, "({} %u {})", lhs, rhs),
            Expression::Divs(ref lhs, ref rhs) =>
                write!(f, "({} /s {})", lhs, rhs),
            Expression::Mods(ref lhs, ref rhs) =>
                write!(f, "({} %s {})", lhs, rhs),
            Expression::And(ref lhs, ref rhs) =>
                write!(f, "({} & {})", lhs, rhs),
            Expression::Or(ref lhs, ref rhs) =>
                write!(f, "({} | {})", lhs, rhs),
            Expression::Xor(ref lhs, ref rhs) =>
                write!(f, "({} ^ {})", lhs, rhs),
            Expression::Shl(ref lhs, ref rhs) =>
                write!(f, "({} << {})", lhs, rhs),
            Expression::Shr(ref lhs, ref rhs) =>
                write!(f, "({} >> {})", lhs, rhs),
            Expression::Cmpeq(ref lhs, ref rhs) =>
                write!(f, "({} == {})", lhs, rhs),
            Expression::Cmpneq(ref lhs, ref rhs) =>
                write!(f, "({} != {})", lhs, rhs),
            Expression::Cmplts(ref lhs, ref rhs) =>
                write!(f, "({} <s {})", lhs, rhs),
            Expression::Cmpltu(ref lhs, ref rhs) =>
                write!(f, "({} <u {})", lhs, rhs),
            Expression::Zext(ref bits, ref src) =>
                write!(f, "zext.{}({})", bits, src),
            Expression::Sext(ref bits, ref src) =>
                write!(f, "sext.{}({})", bits, src),
            Expression::Trun(ref bits, ref src) =>
                write!(f, "trun.{}({})", bits, src),
        }
    }
}
