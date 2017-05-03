use std::fmt;
use il::*;



/// An IL variable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Variable {
    name: String,
    bits: usize,
    ssa: Option<u32>
}


impl Variable {
    pub fn new<S>(name: S, bits: usize) -> Variable where S: Into<String> {
        Variable {
            name: name.into(),
            bits: bits,
            ssa: None
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// A variable uniquely identifies the variable in the form `<name>:<bits>#<ssa>`
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


impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}


impl Into<Expression> for Variable {
    fn into(self) -> Expression {
        Expression::variable(self)
    }
}