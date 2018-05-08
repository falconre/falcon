#[derive(Clone, Debug)]
pub struct Symbol {
    name: String,
    address: u64
}


impl Symbol {
    pub fn new<S: Into<String>>(name: S, address: u64) -> Symbol {
        Symbol {
            name: name.into(),
            address: address
        }
    }


    pub fn name(&self) -> &str {
        &self.name
    }


    pub fn address(&self) -> u64 {
        self.address
    }
}