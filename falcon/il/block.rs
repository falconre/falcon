use std::fmt;
use il::*;


/// A basic block.
#[derive(Debug, Clone)]
pub struct Block {
    /// The index of the block.
    index: u64,
    /// an internal counter for the next block-unique instruction.
    next_instruction_index: RefCell<u64>,
    /// An internal counter for the next block-unique temporary variable.
    next_temp_index: RefCell<u64>,
    /// The instructions for this block.
    instructions: RefCell<Vec<Instruction>>,
}


impl Block {
    pub fn new(index: u64) -> Block {
        Block {
            index: index,
            next_instruction_index: RefCell::new(0),
            next_temp_index: RefCell::new(0),
            instructions: RefCell::new(Vec::new())
        }
    }


    fn new_instruction_index(&self) -> u64 {
        let instruction_index = self.next_instruction_index.borrow().clone();
        *self.next_instruction_index.borrow_mut() = instruction_index + 1;
        return instruction_index;
    }


    fn push(&self, instruction: Instruction) {
        self.instructions.borrow_mut().push(instruction);
    }


    /// Appends the contents of another block to this block.
    pub fn append(&self, other: &Block) {
        for instruction in other.instructions().borrow().iter() {
            let instruction = instruction.clone_new_index(self.new_instruction_index());
            self.instructions.borrow_mut().push(instruction);
        }
    }


    /// Returns the index of this block
    pub fn index(&self) -> u64 {
        self.index
    }


    /// Returns this block's instructions
    pub fn instructions(&self) -> &RefCell<Vec<Instruction>> {
        &self.instructions
    }


    /// Returns an instruction by index
    pub fn instruction_by_index(&self, index: u64) -> Result<&Instruction> {
        for instruction in self.instructions.borrow().iter() {
            if instruction.index() == index {
                return Ok(instruction);
            }
        }
        bail!("No instruction with index of {}", index);
    }


    /// Deletes an operation by its index
    pub fn delete_by_index(&self, index: usize) -> Result<()> {
        if self.instructions.borrow().len() >= index {
            bail!("delete_by_index out of bounds");
        }
        self.instructions.borrow_mut().remove(index);
        Ok(())
    }


    /// Clone this block and set a new index.
    pub fn clone_new_index(&self, index: u64) -> Block {
        let mut clone = self.clone();
        clone.index = index;
        return clone;
    }


    /// Generates a temporary variable unique to this block.
    pub fn temp(&self, bits: usize) -> Variable {
        let next_index = self.next_temp_index.borrow().clone();
        let mut next_index_mut = self.next_temp_index.borrow_mut();
        *next_index_mut = next_index + 1;
        return Variable::new(format!("temp_{}.{}", self.index, next_index), bits);
    }

    /// Adds an assign operation to the end of this block.
    pub fn assign(&self, dst: Variable, src: Expression) {
        self.push(Instruction::assign(self.new_instruction_index(), dst, src));
    }

    /// Adds a store operation to the end of this block.
    pub fn store(&self, address: Expression, src: Expression) {
        self.push(Instruction::store(self.new_instruction_index(), address, src))
    }

    /// Adds a load operation to the end of this block.
    pub fn load(&self, dst: Variable, address: Expression) {
        self.push(Instruction::load(self.new_instruction_index(), dst, address));
    }

    /// Adds a conditional branch operation to the end of this block.
    pub fn brc(&self, dst: Expression, condition: Expression) {
        self.push(Instruction::brc(self.new_instruction_index(), dst, condition));
    }

    /// Adds a phi operation to the end of this block.
    pub fn phi(&self, dst: Variable, src: Vec<Variable>) {
        self.push(Instruction::phi(self.new_instruction_index(), dst, src));
    }

    /// Prepends an operation to the beginning of this block
    pub fn prepend_phi(&self, dst: Variable, src: Vec<Variable>) {
        let phi = Instruction::phi(self.new_instruction_index(), dst, src);
        self.instructions.borrow_mut().insert(0, phi);
    }
}


impl graph::Vertex for Block {
    fn index (&self) -> u64 { self.index }
    fn dot_label(&self) -> String { format!("{}", self) }
}


impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(writeln!(f, "[ Block: {} ]", self.index));
        for instruction in self.instructions().borrow().iter() {
            try!(writeln!(f, "{}", instruction));
        }
        Ok(())
    }
}