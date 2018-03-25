//! A `Constant` holds a single value.

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use il::*;
use num_bigint::{BigUint, ToBigInt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt;
use std::io::Cursor;

/// A constant value for Falcon IL
///
/// IL Constants in Falcon are backed by both rust's `u64` primitive, and
/// `BigUint` from the `num-bigint` crate. This allows modelling and simulation
/// of instructions which must operate on values >64 bits in size. When a
/// Constant has 64 or less bits, the `u64` will be used, incurring minimal
/// performance overhead.
///
/// The Falcon IL Expression operations are provided as methods over `Constant`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Constant {
    U64(u64, usize),
    BigUint(BigUint)
}


impl Constant {
    /// Create a new `Constant` with the given value and bitness.
    pub fn new(value: u64, bits: usize) -> Constant {
        if bits > 64 {            
            let mut bytes: Vec<u8> = Vec::new();
            bytes.write_u64::<BigEndian>(value).unwrap();
            for _ in (8)..(bits / 8) {
                bytes.push(0);
            }
            Constant::BigUint(BigUint::from_bytes_be(&bytes))
        }
        else {
            Constant::U64(Constant::trim_value(value, bits), bits)
        }
    }

    /// Create a new `Constant` from the given `BigUint`.
    pub fn new_big(value: BigUint) -> Constant {
        if value.bits() <= 64 {
            Constant::U64(value.to_u64().unwrap(), value.bits())
        }
        else {
            Constant::BigUint(value)
        }
    }

    /// Crates a constant from a decimal string of the value
    pub fn from_decimal_string(s: &String, bits: usize) -> Result<Constant> {
        Ok(if bits <= 64 {
            Constant::U64(s.parse()?, bits)
        }
        else {
            let constant = Constant::new_big(s.parse()?);
            if constant.bits() < bits {
                constant.zext(bits)?
            }
            else if constant.bits() > bits {
                constant.trun(bits)?
            }
            else {
                constant
            }
        })
    }

    /// Create a new `Constant` with the given bits and a value of zero
    pub fn new_zero(bits: usize) -> Result<Constant> {
        if bits <= 64 {
            Ok(Constant::U64(0, bits))
        }
        else if (bits & 0x7) > 0 {
            Err(ErrorKind::Sort.into())
        }
        else {
            let mut v = Vec::new();
            for _ in 0..(bits / 8) {
                v.push(0);
            }
            Ok(Constant::BigUint(BigUint::new(v)))
        }
    }

    fn trim_value(value: u64, bits: usize) -> u64 {
        if bits == 64 {
            value
        }
        else {
            value & ((1 << bits) - 1)
        }
    }

    /// Get the value of this `Constant` if it is a `u64`.
    pub fn value_u64(&self) -> Option<u64> {
        match *self {
            Constant::U64(value, _) => Some(value),
            Constant::BigUint(_) => None
        }
    }


    /// Get the value of this `Constant` if it is a `BigUint`.
    pub fn value_big(&self) -> Option<&BigUint> {
        match *self {
            Constant::U64(_, _) => None,
            Constant::BigUint(ref bu) => Some(bu)
        }
    }

    /// Get the number of bits for this `Constant`.
    pub fn bits(&self) -> usize {
        match *self {
            Constant::U64(_, bits) => bits,
            Constant::BigUint(ref big_uint) => big_uint.bits()
        }
    }

    /// Returns true if the value in this Constant is 0, false otherwise.
    pub fn is_zero(&self) -> bool {
        match *self {
            Constant::U64(value, _) => value == 0,
            Constant::BigUint(ref big_uint) =>
                *big_uint == BigUint::from_usize(0).unwrap()
        }
    }

    /// Returns true if the value in this constant is 1, false otherwise.
    pub fn is_one(&self) -> bool {
        match *self {
            Constant::U64(value, _) => value == 1,
            Constant::BigUint(ref big_uint) =>
                *big_uint == BigUint::from_usize(1).unwrap()
        }
    }

    pub fn add(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs.wrapping_add(rhs.value_u64().unwrap()),
                                  bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs + rhs.value_big().unwrap())
            })
        }
    }

    pub fn sub(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs.wrapping_sub(rhs.value_u64().unwrap()),
                                  bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs - rhs.value_big().unwrap())
            })
        }
    }

    pub fn mul(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs.wrapping_mul(rhs.value_u64().unwrap()),
                                  bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs * rhs.value_big().unwrap())
            })
        }
    }

    pub fn divu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs / rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs / rhs.value_big().unwrap())
            })
        }
    }

    pub fn modu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs % rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs % rhs.value_big().unwrap())
            })
        }
    }

    pub fn divs(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) => {
                    let mask = 0xffffffffffffffff << bits;
                    let lhs =
                        if (lhs >> (bits - 1)) > 0 {
                            (lhs | mask) as i64
                        }
                        else {
                            lhs as i64
                        };
                    let rhs = rhs.value_u64().unwrap();
                    let rhs =
                        if (rhs >> (bits - 1)) > 0 {
                            (rhs | mask) as i64
                        }
                        else {
                            rhs as i64
                        };
                    Constant::new((lhs / rhs) as u64, bits)
                }
                Constant::BigUint(ref lhs) => {
                    let lhs = lhs.to_bigint().unwrap();
                    let rhs = lhs.to_bigint().unwrap();
                    let r = lhs / rhs;
                    Constant::new_big(r.to_biguint().unwrap())
                }
            })
        }
    }

    pub fn mods(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) => {
                    let mask = 0xffffffffffffffff << bits;
                    let lhs =
                        if (lhs >> (bits - 1)) > 0 {
                            (lhs | mask) as i64
                        }
                        else {
                            lhs as i64
                        };
                    let rhs = rhs.value_u64().unwrap();
                    let rhs =
                        if (rhs >> (bits - 1)) > 0 {
                            (rhs | mask) as i64
                        }
                        else {
                            rhs as i64
                        };
                    Constant::new((lhs % rhs) as u64, bits)
                }
                Constant::BigUint(ref lhs) => {
                    let lhs = lhs.to_bigint().unwrap();
                    let rhs = lhs.to_bigint().unwrap();
                    let r = lhs % rhs;
                    Constant::new_big(r.to_biguint().unwrap())
                }
            })
        }
    }

    pub fn and(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs & rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs & rhs.value_big().unwrap())
            })
        }
    }

    pub fn or(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs | rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs | rhs.value_big().unwrap())
            })
        }
    }

    pub fn xor(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs ^ rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) =>
                    Constant::new_big(lhs ^ rhs.value_big().unwrap())
            })
        }
    }

    pub fn shl(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs << rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) => {
                    let bits = BigUint::from_usize(lhs.bits())
                        .ok_or("Failed to make BigUint from bits in shl")?;
                    if rhs.value_big().unwrap() >= &bits {
                        Constant::new_zero(lhs.bits())?
                    }
                    else {
                        Constant::new_big(
                            lhs << rhs.value_u64()
                                      .ok_or("Failed to get rhs as value_u64")?
                                      .to_usize()
                                      .ok_or("Failed to get usize for rhs")?)
                    }
                }
            })
        }
    }

    pub fn shr(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) =>
                    Constant::new(lhs >> rhs.value_u64().unwrap(), bits),
                Constant::BigUint(ref lhs) => {
                    let bits = BigUint::from_usize(lhs.bits())
                        .ok_or("Failed to make BigUint from bits in shl")?;
                    if rhs.value_big().unwrap() >= &bits {
                        Constant::new_zero(lhs.bits())?
                    }
                    else {
                        Constant::new_big(
                            lhs >> rhs.value_u64()
                                      .ok_or("Failed to get rhs as value_u64")?
                                      .to_usize()
                                      .ok_or("Failed to get usize for rhs")?)
                    }
                }
            })
        }
    }

    pub fn cmpeq(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, _) =>
                    if lhs == rhs.value_u64().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
                Constant::BigUint(ref lhs) =>
                    if lhs == rhs.value_big().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
            })
        }
    }

    pub fn cmpneq(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, _) =>
                    if lhs != rhs.value_u64().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
                Constant::BigUint(ref lhs) =>
                    if lhs != rhs.value_big().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
            })
        }
    }

    pub fn cmplts(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, bits) => {
                    let mask = 0xffffffffffffffff << bits;
                    let lhs: i64 =
                        if (lhs >> (bits - 1)) > 0 {
                            (lhs | mask) as i64
                        }
                        else {
                            lhs as i64
                        };
                    let rhs = rhs.value_u64().unwrap();
                    let rhs: i64 =
                        if (rhs >> (bits - 1)) > 0 {
                            (rhs | mask) as i64
                        }
                        else {
                            rhs as i64
                        };
                    if lhs < rhs {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
                },
                Constant::BigUint(ref lhs) => {
                    let lhs = lhs.to_bigint();
                    let rhs = rhs.value_big().unwrap().to_bigint();
                    if lhs < rhs {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
                }
            })
        }
    }

    pub fn cmpltu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, _) =>
                    if lhs < rhs.value_u64().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
                Constant::BigUint(ref lhs) =>
                    if lhs < rhs.value_big().unwrap() {
                        Constant::new(1, 1)
                    }
                    else {
                        Constant::new(0, 1)
                    }
            })
        }
    }

    pub fn trun(&self, bits: usize) -> Result<Constant> {
        if bits >= self.bits() {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, _) => Constant::new(lhs, bits),
                Constant::BigUint(ref big_uint) => {
                    if bits <= 64 {
                        let value: u64 =
                            Cursor::new(big_uint.to_bytes_be())
                                .read_u64::<BigEndian>()?;
                        Constant::new(value, bits)
                    }
                    else {
                        let mut value = big_uint.to_bytes_be();
                        value.truncate(bits / 8);
                        Constant::new_big(BigUint::from_bytes_be(&value))
                    }
                }
            })
        }
    }

    pub fn zext(&self, bits: usize) -> Result<Constant> {
        if bits <= self.bits() || bits % 8 > 0 {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, lbits) =>
                    if bits <= 64 {
                        Constant::new(lhs, bits)
                    }
                    else {
                        let mut bytes: Vec<u8> = Vec::new();
                        bytes.write_u64::<BigEndian>(lhs)?;
                        for _ in (lbits / 8)..(bits / 8) {
                            bytes.push(0);
                        }
                        Constant::new_big(BigUint::from_bytes_be(&bytes))
                    }
                Constant::BigUint(ref big_uint) => {
                    let mut bytes = big_uint.to_bytes_be();
                    for _ in (big_uint.bits() / 8)..(bits / 8) {
                        bytes.push(0);
                    }
                    Constant::new_big(BigUint::from_bytes_be(&bytes))
                }
            })
        }
    }

    pub fn sext(&self, bits: usize) -> Result<Constant> {
        if bits <= self.bits() || bits % 8 > 0 {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(match *self {
                Constant::U64(lhs, ubits) => {
                    // we need to start by at least sign-extending to full u64
                    let mask = 0xffffffffffffffff << ubits;
                    let lhs =
                        if (lhs >> (ubits - 1)) > 0 {
                            (lhs | mask)
                        }
                        else {
                            lhs
                        };
                    // If it will all fit in a u64, we're done
                    if bits <= 64 {
                        Constant::new(lhs, bits)
                    }
                    // Otherwise we need to create a BigUint
                    else {
                        let mut bytes = Vec::new();
                        bytes.write_u64::<BigEndian>(lhs)?;
                        for _ in 8..(ubits / 8) {
                            if (lhs >> (ubits - 1)) > 0 {
                                bytes.push(0xff);
                            }
                            else {
                                bytes.push(0x00);
                            }
                        }
                        Constant::new_big(BigUint::from_bytes_be(&bytes))
                    }
                },
                Constant::BigUint(ref big_uint) => {
                    let sign_bit = big_uint >> (bits - 1);
                    let sign_bit = sign_bit & BigUint::from_u64(1).unwrap();
                    let negative = if sign_bit == BigUint::from_u64(1).unwrap() { 
                        true
                    } else {
                        false
                    };
                    let mut bytes = big_uint.to_bytes_be();
                    for _ in (big_uint.bits() / 8)..(bits / 8) {
                        if negative {
                            bytes.push(0xff);
                        }
                        else {
                            bytes.push(0);
                        }
                    }
                    Constant::new_big(BigUint::from_bytes_be(&bytes))
                }
            })
        }
    }
}


impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Constant::U64(value, bits) =>
                write!(f, "0x:{:X}:{}", value, bits),
            Constant::BigUint(ref big_uint) =>
                write!(f, "0x:{:X}:{}", big_uint, big_uint.bits())
        }
    }
}


impl Into<Expression> for Constant {
    fn into(self) -> Expression {
        Expression::constant(self)
    }
}