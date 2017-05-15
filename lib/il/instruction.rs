use il::*;
use std::fmt;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Instruction {
    operation: Operation,
    index: u64,
    comment: Option<String>
}


impl Instruction {
    pub fn assign(index: u64, dst: Variable, src: Expression) -> Instruction {
        Instruction {
            operation: Operation::Assign { dst: dst, src: src },
            index: index,
            comment: None
        }
    }

    pub fn store(index: u64, address: Expression, src: Expression) -> Instruction {
        Instruction {
            operation: Operation::Store { address: address, src: src },
            index: index,
            comment: None
        }
    }

    pub fn load(index: u64, dst: Variable, address: Expression) -> Instruction {
        Instruction {
            operation: Operation::Load { dst: dst, address: address },
            index: index,
            comment: None
        }
    }

    pub fn brc(index: u64, dst: Expression, condition: Expression) -> Instruction {
        Instruction {
            operation: Operation::Brc { dst: dst, condition: condition },
            index: index,
            comment: None
        }
    }

    pub fn phi(index: u64, dst: Variable, src: Vec<Variable>) -> Instruction {
        Instruction {
            operation: Operation::Phi { dst: dst, src: src },
            index: index,
            comment: None
        }
    }


    pub fn is_assign(&self) -> bool {
        if let Operation::Assign{..} = self.operation {
            true
        }
        else {
            false
        }
    }


    pub fn is_store(&self) -> bool {
        if let Operation::Store{..} = self.operation {
            true
        }
        else {
            false
        }
    }


    pub fn is_load(&self) -> bool {
        if let Operation::Load{..} = self.operation {
            true
        }
        else {
            false
        }
    }


    pub fn is_brc(&self) -> bool {
        if let Operation::Brc{..} = self.operation {
            true
        }
        else {
            false
        }
    }


    pub fn is_phi(&self) -> bool {
        if let Operation::Phi{..} = self.operation {
            true
        }
        else {
            false
        }
    }


    pub fn operation(&self) -> &Operation {
        &self.operation
    }


    pub fn operation_mut(&mut self) -> &mut Operation {
        &mut self.operation
    }


    pub fn index(&self) -> u64 {
        self.index
    }


    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }


    pub fn clone_new_index(&self, index: u64) -> Instruction {
        Instruction {
            operation: self.operation.clone(),
            index: index,
            comment: self.comment.clone()
        }
    }


    pub fn variable_written(&self) -> Option<&Variable> {
        self.operation.variable_written()
    }


    pub fn variable_written_mut(&mut self) -> Option<&mut Variable> {
        self.operation.variable_written_mut()
    }


    pub fn variables_read(&self) -> Vec<&Variable> {
        self.operation.variables_read()
    }


    pub fn variables_read_mut(&mut self) -> Vec<&mut Variable> {
        self.operation.variables_read_mut()
    }
}



impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref comment) = self.comment {
            write!(
                f,
                "{:02X} {} // {}",
                self.index,
                self.operation,
                comment
            )
        }
        else {
            write!(f, "{:02X} {}", self.index, self.operation)
        }
    }
}