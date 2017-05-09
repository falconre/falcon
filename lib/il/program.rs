use il::*;
use std::collections::BTreeMap;
use std::fmt;

/// A representation of a program by il::Function
#[derive(Clone, Debug)]
pub struct Program {
    functions: BTreeMap<u64, Function>
}


impl Program {
    pub fn new(functions: BTreeMap<u64, Function>) -> Program {
        Program {
            functions: functions
        }
    }


    pub fn functions(&self) -> Vec<&Function> {
        self.functions.values().map(|v| v).collect::<Vec<&Function>>()
    }


    /// Retrieve a function by an index (normally the function's address)
    pub fn function(&self, index: u64) -> Option<&Function> {
        self.functions.get(&index)
    }


    /// Sets a function entry in the program
    pub fn set_function(&mut self, function: Function) {
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