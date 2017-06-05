use il::*;
use std::collections::BTreeMap;
use std::fmt;

/// A representation of a program by `il::Function`
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Program {
    functions: BTreeMap<u64, Function>,
    // The next index to assign to a function when added to the program.
    next_index: u64
}


impl Program {
    pub fn new() -> Program {
        Program {
            functions: BTreeMap::new(),
            next_index: 0
        }
    }


    pub fn functions(&self) -> Vec<&Function> {
        self.functions.values().collect::<Vec<&Function>>()
    }


    /// Retrieve a function by an index (normally the function's address)
    pub fn function(&self, index: u64) -> Option<&Function> {
        self.functions.get(&index)
    }


    /// Sets a function entry in the program
    pub fn set_function(&mut self, mut function: Function) {
        function.set_index(Some(self.next_index));
        self.next_index += 1;
        self.functions.insert(function.address(), function);
    }
}


impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for function in &self.functions {
            writeln!(f, "{}@{:08X}", function.1.name(), function.0)?
        }
        Ok(())
    }
}