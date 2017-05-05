use il::*;
use std::collections::BTreeMap;

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