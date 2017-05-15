use std::fmt;
use il::*;



/// An IL flag.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Flag {
    name: String,
    ssa: Option<u32>
}


impl Flag {
    pub fn new<S>(name: S) -> Flag where S: Into<String> {
        Flag {
            name: name.into(),
            ssa: None
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// A variable uniquely identifies the variable in the form `<name>:<bits>#<ssa>`
    pub fn identifier(&self) -> String {
        format!(
            "{}:{}",
            self.name,
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


impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}


impl Into<Expression> for Flag {
    fn into(self) -> Expression {
        Expression::flag(self)
    }
}