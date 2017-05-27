use std::fmt;
use il::*;


/// A basic block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Block {
    /// The index of the block.
    index: u64,
    /// an internal counter for the next block-unique instruction.
    next_instruction_index: u64,
    /// An internal counter for the next block-unique temporary variable.
    next_temp_index: u64,
    /// The instructions for this block.
    instructions: Vec<Instruction>,
}


impl Block {
    pub fn new(index: u64) -> Block {
        Block {
            index: index,
            next_instruction_index: 0,
            next_temp_index: 0,
            instructions: Vec::new()
        }
    }


    fn new_instruction_index(&mut self) -> u64 {
        let instruction_index = self.next_instruction_index;
        self.next_instruction_index = instruction_index + 1;
        instruction_index
    }


    fn push(&mut self, instruction: Instruction) {
        self.instructions.push(instruction);
    }


    /// Appends the contents of another block to this block.
    pub fn append(&mut self, other: &Block) {
        for instruction in other.instructions().iter() {
            let instruction = instruction.clone_new_index(self.new_instruction_index());
            self.instructions.push(instruction);
        }
    }


    /// Returns the index of this block
    pub fn index(&self) -> u64 {
        self.index
    }


    /// Returns this block's instructions
    pub fn instructions(&self) -> &Vec<Instruction> {
        &self.instructions
    }


    pub fn instructions_mut(&mut self) -> &mut Vec<Instruction> {
        &mut self.instructions
    }


    /// Returns a copy of an instruction by index
    pub fn instruction(&self, index: u64) -> Result<&Instruction> {
        for instruction in &self.instructions {
            if instruction.index() == index {
                return Ok(&instruction);
            }
        }
        bail!("No instruction with index of {}", index);
    }


    pub fn instruction_mut<'a>(&'a mut self, index: u64) -> Result<&'a mut Instruction> {
        let mut location = None;
        for i in 0..self.instructions.len() {
            if self.instructions[i].index() == index {
                location = Some(i);
                break;
            }
        }
        match location {
            Some(i) => Ok(self.instructions.get_mut(i).unwrap()),
            None => bail!("No instruction with index of {}", index)
        }
    }


    /// Deletes an operation by its index
    pub fn remove_instruction(&mut self, index: u64) -> Result<()> {
        let mut vec_index = None;
        for i in 0..self.instructions.len() {
            if self.instructions[i].index() == index {
                vec_index = Some(i);
                break;
            }
        }
        match vec_index {
            Some(index) => {
                self.instructions.remove(index);
                Ok(())
            },
            None => Err(format!("No instruction with index {} found", index).into()),
        }
    }


    /// Clone this block and set a new index.
    pub fn clone_new_index(&self, index: u64) -> Block {
        let mut clone = self.clone();
        clone.index = index;
        clone
    }


    /// Generates a temporary variable unique to this block.
    pub fn temp(&mut self, bits: usize) -> Variable {
        let next_index = self.next_temp_index;
        self.next_temp_index = next_index + 1;
        Variable::new(format!("temp_{}.{}", self.index, next_index), bits)
    }

    /// Adds an assign operation to the end of this block.
    pub fn assign(&mut self, dst: Variable, src: Expression) {
        let index = self.new_instruction_index();
        self.push(Instruction::assign(index, dst, src));
    }

    /// Adds a store operation to the end of this block.
    pub fn store(&mut self, address: Expression, src: Expression) {
        let index = self.new_instruction_index();
        self.push(Instruction::store(index, address, src))
    }

    /// Adds a load operation to the end of this block.
    pub fn load(&mut self, dst: Variable, address: Expression) {
        let index = self.new_instruction_index();
        self.push(Instruction::load(index, dst, address));
    }

    /// Adds a conditional branch operation to the end of this block.
    pub fn brc(&mut self, dst: Expression, condition: Expression) {
        let index = self.new_instruction_index();
        self.push(Instruction::brc(index, dst, condition));
    }

    /// Adds a phi operation to the end of this block.
    pub fn phi(&mut self, dst: Variable, src: Vec<Variable>) {
        let index = self.new_instruction_index();
        self.push(Instruction::phi(index, dst, src));
    }

    /// Adds a raise operation to the end of this block.
    pub fn raise(&mut self, expr: Expression) {
        let index = self.new_instruction_index();
        self.push(Instruction::raise(index, expr));
    }

    /// Prepends an operation to the beginning of this block
    pub fn prepend_phi(&mut self, dst: Variable, src: Vec<Variable>) {
        let index = self.new_instruction_index();
        let phi = Instruction::phi(index, dst, src);
        self.instructions.insert(0, phi);
    }
}


impl graph::Vertex for Block {
    fn index (&self) -> u64 { self.index }
    fn dot_label(&self) -> String { format!("{}", self) }
}


impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(f, "[ Block: 0x{:X} ]", self.index));
        for instruction in self.instructions() {
            try!(writeln!(f, "{}", instruction));
        }
        Ok(())
    }
}