//! A `Scalar` is a variable which holds a single value.

use std::fmt;
use il::*;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Scalar {
    name: String,
    bits: usize
}


/// A scalar value for Falcon IL.
impl Scalar {
    /// Create a new `Scalar` with the given name and bitness.
    pub fn new<S>(name: S, bits: usize) -> Scalar where S: Into<String> {
        Scalar {
            name: name.into(),
            bits: bits
        }
    }

    /// Gets the bitness of the `Scalar`.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Gets the name of the `Scalar`.
    pub fn name(&self) -> &str {
        &self.name
    }
}


impl Variable for Scalar {
    fn name(&self) -> &str {
        self.name()
    }

    fn identifier(&self) -> String {
        format!("{}:{}", self.name, self.bits)
    }

    fn multi_var_clone(&self) -> MultiVar {
        MultiVar::Scalar(self.clone())
    }
}


impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}


impl Into<Expression> for Scalar {
    fn into(self) -> Expression {
        Expression::scalar(self)
    }
}