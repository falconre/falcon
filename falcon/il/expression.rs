use std::fmt;

use il::*;

/// An IL Expression.
/// Expressions form the building blocks of instructions, and always evaluate
/// some value.
#[derive(Debug, Clone)]
pub enum Expression {
    Variable(Variable),
    Constant(Constant),
    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mulu(Box<Expression>, Box<Expression>),
    Divu(Box<Expression>, Box<Expression>),
    Modu(Box<Expression>, Box<Expression>),
    Muls(Box<Expression>, Box<Expression>),
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
    Trun(usize, Box<Expression>)
}


impl Expression {
    /// Return the bit-sort of this expression.
    pub fn bits(&self) -> usize {
        match self {
            &Expression::Variable(ref variable) => variable.bits(),
            &Expression::Constant(ref constant) => constant.bits(),
            &Expression::Add(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Sub(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Mulu(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Divu(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Modu(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Muls(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Divs(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Mods(ref lhs, ref rhs) => lhs.bits(),
            &Expression::And(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Or(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Xor(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Shl(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Shr(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Cmpeq(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Cmpneq(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Cmplts(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Cmpltu(ref lhs, ref rhs) => lhs.bits(),
            &Expression::Zext(bits, ref rhs) => bits,
            &Expression::Sext(bits, ref rhs) => bits,
            &Expression::Trun(bits, ref rhs) => bits
        }
    }


    fn ensure_sort(lhs: &Expression, rhs: &Expression) -> Result<()> {
        if lhs.bits() != rhs.bits() {
            return Err(ErrorKind::Sort.into());
        }
        return Ok(());
    }

    /// Returns all variables used in the expression
    pub fn collect_variables(&self) -> Vec<&Variable> {
        let mut variables: Vec<&Variable> = Vec::new();
        match self {
            &Expression::Variable(ref variable) => {
                variables.push(&variable)
            },
            &Expression::Constant(ref constant) => {},
            &Expression::Add(ref lhs, ref rhs) |
            &Expression::Sub(ref lhs, ref rhs) |
            &Expression::Mulu(ref lhs, ref rhs) |
            &Expression::Divu(ref lhs, ref rhs) |
            &Expression::Modu(ref lhs, ref rhs) |
            &Expression::Muls(ref lhs, ref rhs) |
            &Expression::Divs(ref lhs, ref rhs) |
            &Expression::Mods(ref lhs, ref rhs) |
            &Expression::And(ref lhs, ref rhs) |
            &Expression::Or(ref lhs, ref rhs) |
            &Expression::Xor(ref lhs, ref rhs) |
            &Expression::Shl(ref lhs, ref rhs) |
            &Expression::Shr(ref lhs, ref rhs) |
            &Expression::Cmpeq(ref lhs, ref rhs) |
            &Expression::Cmpneq(ref lhs, ref rhs) |
            &Expression::Cmplts(ref lhs, ref rhs) |
            &Expression::Cmpltu(ref lhs, ref rhs) => {
                variables.append(&mut lhs.collect_variables());
                variables.append(&mut rhs.collect_variables());
            },
            &Expression::Zext(bits, ref rhs) |
            &Expression::Sext(bits, ref rhs) |
            &Expression::Trun(bits, ref rhs) => {
                variables.append(&mut rhs.collect_variables());
            }
        }
        variables
    }

    /// Create a new expression from a variable.
    pub fn variable(variable: Variable) -> Expression {
        Expression::Variable(variable)
    }

    /// Create a new expression from a constant.
    pub fn constant(constant: Constant) -> Expression {
        Expression::Constant(constant)
    }

    /// Create an addition expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn add(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Add(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a subtraction expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn sub(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Sub(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned multiplication expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mulu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Mulu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned division expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Divu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned modulus expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn modu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Modu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed multiplication expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn muls(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Muls(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed division expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divs(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Divs(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed modulus expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mods(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Mods(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary and expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn and(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::And(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary or expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn or(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Or(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary xor expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn xor(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Xor(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-left expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shl(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Shl(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-right expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shr(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Shr(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an equals comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpeq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Cmpeq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an not equals comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpneq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Cmpneq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned less-than comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpltu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Cmpltu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed less-than comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmplts(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs));
        Ok(Expression::Cmplts(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an expression to zero-extend src to the number of bits specified
    /// in bits.
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn zext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Zext(bits, Box::new(src)))
    }

    /// Create an expression to sign-extend src to the number of bits specified
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn sext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Sext(bits, Box::new(src)))
    }

    /// Create an expression to truncate the number of bits in src to the number
    /// of bits given.
    /// # Error
    /// src has less-than or equal bits than bits
    pub fn trun(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() <= bits {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Trun(bits, Box::new(src)))
    }
}


impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Expression::Variable(ref v) =>
                v.fmt(f),
            &Expression::Constant(ref c) =>
                c.fmt(f),
            &Expression::Add(ref lhs, ref rhs) => 
                write!(f, "({} + {})", lhs, rhs),
            &Expression::Sub(ref lhs, ref rhs) =>
                write!(f, "({} - {})", lhs, rhs),
            &Expression::Mulu(ref lhs, ref rhs) =>
                write!(f, "({} *u {})", lhs, rhs),
            &Expression::Divu(ref lhs, ref rhs) =>
                write!(f, "({} /u {})", lhs, rhs),
            &Expression::Modu(ref lhs, ref rhs) =>
                write!(f, "({} %u {})", lhs, rhs),
            &Expression::Muls(ref lhs, ref rhs) =>
                write!(f, "({} *s {})", lhs, rhs),
            &Expression::Divs(ref lhs, ref rhs) =>
                write!(f, "({} /s {})", lhs, rhs),
            &Expression::Mods(ref lhs, ref rhs) =>
                write!(f, "({} %s {})", lhs, rhs),
            &Expression::And(ref lhs, ref rhs) =>
                write!(f, "({} & {})", lhs, rhs),
            &Expression::Or(ref lhs, ref rhs) =>
                write!(f, "({} | {})", lhs, rhs),
            &Expression::Xor(ref lhs, ref rhs) =>
                write!(f, "({} ^ {})", lhs, rhs),
            &Expression::Shl(ref lhs, ref rhs) =>
                write!(f, "({} << {})", lhs, rhs),
            &Expression::Shr(ref lhs, ref rhs) =>
                write!(f, "({} >> {})", lhs, rhs),
            &Expression::Cmpeq(ref lhs, ref rhs) =>
                write!(f, "({} == {})", lhs, rhs),
            &Expression::Cmpneq(ref lhs, ref rhs) =>
                write!(f, "({} != {})", lhs, rhs),
            &Expression::Cmplts(ref lhs, ref rhs) =>
                write!(f, "({} <s {})", lhs, rhs),
            &Expression::Cmpltu(ref lhs, ref rhs) =>
                write!(f, "({} <u {})", lhs, rhs),
            &Expression::Zext(ref bits, ref src) =>
                write!(f, "zext.{}({})", bits, src),
            &Expression::Sext(ref bits, ref src) =>
                write!(f, "sext.{}({})", bits, src),
            &Expression::Trun(ref bits, ref src) =>
                write!(f, "trun.{}({})", bits, src),
        }
    }
}
