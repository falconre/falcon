#[derive(Clone, Debug)]
pub(crate)struct Symbol {
    name: String,
    address: u64
}


impl Symbol {
    pub(crate) fn new<S: Into<String>>(name: S, address: u64) -> Symbol {
        Symbol {
            name: name.into(),
            address: address
        }
    }


    pub(crate) fn name(&self) -> &str {
        &self.name
    }


    pub(crate) fn address(&self) -> u64 {
        self.address
    }
}