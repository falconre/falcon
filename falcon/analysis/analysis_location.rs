//! Provides a means of pinpointing a location in a ControlFlowGraph.
//!
//! Ideally, all analysis should be conducted over an AnalysisLocation. This
//! ensures the analysis accounts for edges and instruction locations.

use error::*;
use il;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::BTreeSet;
use std::fmt;

use analysis::analysis_location::AnalysisLocation::*;

/// Holds a location in the ControlFlowGraph for either an instruction or an
/// edge.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum AnalysisLocation {
    Edge(EdgeLocation),
    Instruction(InstructionLocation),
    EmptyBlock(EmptyBlockLocation)
}

impl Ord for AnalysisLocation {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            &Edge(ref edge_self) => match other {
                &Edge(ref edge_other) => edge_self.cmp(edge_other),
                &Instruction(_) => Ordering::Greater,
                &EmptyBlock(_) => Ordering::Less
            },
            &Instruction(ref ins_self) => match other {
                &Edge(_) => Ordering::Less,
                &Instruction(ref ins_other) => ins_self.cmp(ins_other),
                &EmptyBlock(_) => Ordering::Less
            },
            &EmptyBlock(ref eb_self) => match other {
                &Edge(_) => Ordering::Greater,
                &Instruction(_) => Ordering::Greater,
                &EmptyBlock(ref eb_other) => eb_self.cmp(eb_other)
            }
        }
    }
}

impl PartialOrd for AnalysisLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl AnalysisLocation {
    // Create a new InstructionLocation
    pub fn instruction(block_index: u64, instruction_index: u64) -> AnalysisLocation {
        let ii = InstructionLocation::new(block_index, instruction_index);
        AnalysisLocation::Instruction(ii)
    }

    // Create a new EdgeLocation
    pub fn edge(head: u64, tail: u64) -> AnalysisLocation {
        AnalysisLocation::Edge(EdgeLocation::new(head, tail))
    }

    // Create a new EmptyBlockLocation
    pub fn empty_block(block_index: u64) -> AnalysisLocation {
        AnalysisLocation::EmptyBlock(EmptyBlockLocation::new(block_index))
    }
}


impl fmt::Display for AnalysisLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Edge(ref edge) => write!(f, "E({})", edge),
            &Instruction(ref ins) => write!(f, "I({})", ins),
            &EmptyBlock(ref eb) => write!(f, "EB({})", eb)
        }
    }
}


/// Function to turn a BTreeSet of AnalysisLocation into a string
pub fn set_string(set: &BTreeSet<AnalysisLocation>) -> String {
    format!("{{{}}}", set.iter()
                         .map(|al| format!("{}", al))
                         .collect::<Vec<String>>()
                         .join(", "))
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EmptyBlockLocation {
    block_index: u64
}

impl Ord for EmptyBlockLocation {
    fn cmp(&self, other: &EmptyBlockLocation) -> Ordering {
        self.block_index.cmp(&other.block_index) 
    }
}

impl PartialOrd for EmptyBlockLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl EmptyBlockLocation {
    pub fn new(block_index: u64) -> EmptyBlockLocation {
        EmptyBlockLocation {
            block_index: block_index
        }
    }

    pub fn block_index(&self) -> u64 {
        self.block_index
    }

    pub fn find<'f>(&self, control_flow_graph: &'f il::ControlFlowGraph)
    -> Result<&'f il::Block> {
        control_flow_graph.block(self.block_index)
    }
}

impl fmt::Display for EmptyBlockLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:X}", self.block_index,)
    }
}

impl Into<AnalysisLocation> for EmptyBlockLocation {
    fn into(self) -> AnalysisLocation {
        AnalysisLocation::EmptyBlock(self)
    }
}




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

    // Return the index of the block where this instruction is held.
    pub fn block_index(&self) -> u64 {
        self.block_index
    }

    // Return the index of the instruction.
    pub fn instruction_index(&self) -> u64 {
        self.instruction_index
    }


    pub fn find<'f>(&self, control_flow_graph: &'f il::ControlFlowGraph)
    -> Result<&'f il::Instruction> {
        control_flow_graph.block(self.block_index)?
                          .instruction(self.instruction_index)
    }


    pub fn find_mut<'f>(&self, control_flow_graph: &'f mut il::ControlFlowGraph)
    -> Result<&'f mut il::Instruction> {
        control_flow_graph.block_mut(self.block_index)?
                          .instruction_mut(self.instruction_index)
    }
}


pub fn block_last_instruction_location(block: &il::Block) -> Option<InstructionLocation> {
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
            "0x{:X}.{:02X}",
            self.block_index,
            self.instruction_index
        )
    }
}

impl Into<AnalysisLocation> for InstructionLocation {
    fn into(self) -> AnalysisLocation {
        AnalysisLocation::Instruction(self)
    }
}




#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EdgeLocation {
    head: u64,
    tail: u64
}

impl Ord for EdgeLocation {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.head < other.head {
            return Ordering::Less
        }
        else if self.head > other.head {
            return Ordering::Greater
        }
        else if self.tail < other.tail {
            return Ordering::Less
        }
        else if self.tail > other.tail {
            return Ordering::Greater
        }
        return Ordering::Equal
    }
}

impl PartialOrd for EdgeLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl EdgeLocation {
    pub fn new(head: u64, tail: u64) -> EdgeLocation {
        EdgeLocation {
            head: head,
            tail: tail
        }
    }


    pub fn head(&self) -> u64 {
        self.head
    }


    pub fn tail(&self) -> u64 {
        self.tail
    }


    pub fn find<'f>(&self, control_flow_graph: &'f il::ControlFlowGraph)
    -> Result<&'f il::Edge> {
        control_flow_graph.edge(self.head, self.tail)
    }


    pub fn find_mut<'f>(&self, control_flow_graph: &'f mut il::ControlFlowGraph)
    -> Result<&'f mut il::Edge> {
        control_flow_graph.edge_mut(self.head, self.tail)
    }
}


impl fmt::Display for EdgeLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:X}->0x{:0X}", self.head, self.tail)
    }
}


impl Into<AnalysisLocation> for EdgeLocation {
    fn into(self) -> AnalysisLocation {
        AnalysisLocation::Edge(self)
    }
}