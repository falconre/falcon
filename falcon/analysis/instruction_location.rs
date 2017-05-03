use error::*;
use il::*;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InstructionLocation {
    block_index: u64,
    instruction_index: u64
}

impl Ord for InstructionLocation {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.block_index < other.block_index {
            return Ordering::Less
        }
        else if self.block_index > other.block_index {
            return Ordering::Greater
        }
        else if self.instruction_index < other.instruction_index {
            return Ordering::Less
        }
        else if self.instruction_index > other.instruction_index {
            return Ordering::Greater
        }
        return Ordering::Equal
    }
}

impl PartialOrd for InstructionLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl InstructionLocation {
    pub fn new(block_index: u64, instruction_index: u64) -> InstructionLocation {
        InstructionLocation {
            block_index: block_index,
            instruction_index: instruction_index
        }
    }


    pub fn block_index(&self) -> u64 {
        self.block_index
    }


    pub fn instruction_index(&self) -> u64 {
        self.instruction_index
    }


    pub fn find<'f>(&self, control_flow_graph: &'f ControlFlowGraph)
    -> Result<&'f Instruction> {
        control_flow_graph.block(self.block_index)?
                          .instruction(self.instruction_index)
    }


    pub fn find_mut<'f>(&self, control_flow_graph: &'f mut ControlFlowGraph)
    -> Result<&'f mut Instruction> {
        control_flow_graph.block_mut(self.block_index)?
                          .instruction_mut(self.instruction_index)
    }
}


pub fn block_last_instruction_location(block: &Block) -> Option<InstructionLocation> {
    if block.instructions().len() == 0 {
        None
    }
    else {
        Some(InstructionLocation::new(
            block.index(),
            block.instructions().last().unwrap().index()
        ))
    }
}


impl fmt::Display for InstructionLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "0x{:X}.{:0X}",
            self.block_index,
            self.instruction_index
        )
    }
}