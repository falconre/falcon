use il::*;
use std::fmt;


#[derive(Clone, Debug)]
pub struct Instruction {
    operation: Operation,
    index: u64
}


impl Instruction {
    pub fn assign(index: u64, dst: Variable, src: Expression) -> Instruction {
        Instruction {
            operation: Operation::Assign { dst: dst, src: src },
            index: index
        }
    }

    pub fn store(index: u64, address: Expression, src: Expression) -> Instruction {
        Instruction {
            operation: Operation::Store { address: address, src: src },
            index: index
        }
    }

    pub fn load(index: u64, dst: Variable, address: Expression) -> Instruction {
        Instruction {
            operation: Operation::Load { dst: dst, address: address },
            index: index
        }
    }

    pub fn brc(index: u64, dst: Expression, condition: Expression) -> Instruction {
        Instruction {
            operation: Operation::Brc { dst: dst, condition: condition },
            index: index
        }
    }

    pub fn phi(index: u64, dst: Variable, src: Vec<Variable>) -> Instruction {
        Instruction {
            operation: Operation::Phi { dst: dst, src: src },
            index: index
        }
    }


    pub fn operation(&self) -> &Operation {
        &self.operation
    }


    pub fn index(&self) -> u64 {
        self.index
    }


    pub fn clone_new_index(&self, index: u64) -> Instruction {
        Instruction {
            operation: self.operation.clone(),
            index: index
        }
    }


    pub fn variables_written(&self) -> Vec<&Variable> {
        self.operation.variables_written()
    }


    pub fn variables_read(&self) -> Vec<&Variable> {
        self.operation.variables_read()
    }
}



impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02X} {}", self.index, self.operation)
    }
}