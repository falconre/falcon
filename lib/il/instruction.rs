use il::*;
use std::fmt;


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Instruction {
    operation: Operation,
    index: u64,
    comment: Option<String>,
    address: Option<u64>
}


impl Instruction {
    pub fn new(index: u64, operation: Operation) -> Instruction {
        Instruction {
            operation: operation,
            index: index,
            comment: None,
            address: None
        }
    }
    pub fn assign(index: u64, dst: Variable, src: Expression) -> Instruction {
        Instruction::new(index, Operation::Assign { dst: dst, src: src })
    }

    pub fn store(index: u64, address: Expression, src: Expression) -> Instruction {
        Instruction::new(index, Operation::Store { address: address, src: src })
    }

    pub fn load(index: u64, dst: Variable, address: Expression) -> Instruction {
        Instruction::new(index, Operation::Load { dst: dst, address: address })
    }

    pub fn brc(index: u64, dst: Expression, condition: Expression) -> Instruction {
        Instruction::new(index, Operation::Brc { dst: dst, condition: condition })
    }

    pub fn phi(index: u64, dst: Variable, src: Vec<Variable>) -> Instruction {
        Instruction::new(index, Operation::Phi { dst: dst, src: src })
    }

    pub fn raise(index: u64, expr: Expression) -> Instruction {
        Instruction::new(index, Operation::Raise { expr: expr })
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


    pub fn comment(&self) -> &Option<String> {
        &self.comment
    }


    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }


    pub fn address(&self) -> &Option<u64> {
        &self.address
    }


    pub fn set_address(&mut self, address: Option<u64>) {
        self.address = address;
    }


    pub fn clone_new_index(&self, index: u64) -> Instruction {
        Instruction {
            operation: self.operation.clone(),
            index: index,
            comment: self.comment.clone(),
            address: self.address.clone()
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
        let prefix = match self.address {
            Some(address) => 
                format!("{:X} {:02X} {}", address, self.index, self.operation),
            None =>
                format!("{:02X} {}", self.index, self.operation)
        };
        if let Some(ref comment) = self.comment {
            write!(f, "{} // {}", prefix, comment)
        }
        else {
            write!(f, "{}", prefix)
        }
    }
}