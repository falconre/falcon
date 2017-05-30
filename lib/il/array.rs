use std::fmt;


/// An IL variable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Array {
    name: String,
    size: u64,
    ssa: Option<u32>
}


impl Array {
    pub fn new<S>(name: S, size: u64) -> Array where S: Into<String> {
        Array {
            name: name.into(),
            size: size,
            ssa: None
        }
    }

    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// An identifier uniquely identifies the variable in the form `<name>[]#<ssa>`
    pub fn identifier(&self) -> String {
        format!(
            "{}[]{}",
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



impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}