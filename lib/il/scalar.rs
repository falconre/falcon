use std::fmt;
use il::*;


/// An IL variable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Scalar {
    name: String,
    bits: usize,
    ssa: Option<u32>
}


impl Scalar {
    pub fn new<S>(name: S, bits: usize) -> Scalar where S: Into<String> {
        Scalar {
            name: name.into(),
            bits: bits,
            ssa: None
        }
    }

    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// An identifier uniquely identifies the variable in the form `<name>:<bits>#<ssa>`
    pub fn identifier(&self) -> String {
        format!(
            "{}:{}{}",
            self.name,
            self.bits,
            match self.ssa {
                Some(ssa) => format!("#{}", ssa),
                None => String::new()
        })
    }

    pub fn ssa(&self) -> Option<u32> {
        self.ssa
    }

    pub fn set_ssa(&mut self, ssa: Option<u32>) {
        self.ssa = ssa;
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