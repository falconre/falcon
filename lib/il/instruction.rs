use il::*;
use std::fmt;


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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


    pub fn assign(index: u64, dst: Scalar, src: Expression) -> Instruction {
        Instruction::new(index, Operation::assign(dst, src))
    }


    pub fn store(
        instruction_index: u64,
        dst: Array,
        dst_index: Expression,
        src: Expression
    ) -> Instruction {

        Instruction::new(instruction_index, Operation::store(dst, dst_index, src))
    }


    pub fn load(
        instruction_index: u64,
        dst: Scalar,
        src_index: Expression,
        src: Array
    ) -> Instruction {

        Instruction::new(instruction_index, Operation::load(dst, src_index, src))
    }


    pub fn brc(index: u64, target: Expression, condition: Expression)
    -> Instruction {

        Instruction::new(index, Operation::brc(target, condition))
    }


    pub fn phi(index: u64, dst: Variable, src: Vec<Variable>)
    -> Instruction {

        Instruction::new(index, Operation::phi(dst, src))
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


    pub fn variable_written(&self) -> Option<Variable> {
        self.operation.variable_written()
    }


    pub fn variables_read(&self) -> Vec<Variable> {
        self.operation.variables_read()
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