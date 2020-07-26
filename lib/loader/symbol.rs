#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Symbol {
    address: u64,
    name: String,
}

impl Symbol {
    pub fn new<S: Into<String>>(name: S, address: u64) -> Symbol {
        Symbol {
            name: name.into(),
            address,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> u64 {
        self.address
    }
}
