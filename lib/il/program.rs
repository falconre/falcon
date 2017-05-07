use il::*;
use std::collections::BTreeMap;
use std::fmt;

pub struct Program {
    functions: BTreeMap<u64, Function>
}


impl Program {
    pub fn new(functions: BTreeMap<u64, Function>) -> Program {
        Program {
            functions: functions
        }
    }


    pub fn function(&self, index: u64) -> Option<&Function> {
        self.functions.get(&index)
    }
}


impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for function in &self.functions {
            write!(f, "{}@{:08X}", function.1.name(), function.0)?
        }
        Ok(())
    }
}