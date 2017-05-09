//! Translator from host architectures to Falcon IL

use error::*;
use il::*;
use loader::memory::Memory;
use std::boxed::Box;
use std::collections::{BTreeMap, VecDeque};

pub mod x86;


pub enum Endian {
    Big,
    Little
}


/// The result of a block translation
pub struct BlockTranslationResult {
    /// A control flow graph which holds the semantics of this block
    control_flow_graph: ControlFlowGraph,
    /// The address at which this block was translated
    address: u64,
    /// The length of this block in bytes as represented in the host architecture
    length: usize,
    /// Addresses of known successor blocks, and optional conditions to reach them
    successors: Vec<(u64, Option<Expression>)>
}


impl BlockTranslationResult {
    pub fn new(
        control_flow_graph: ControlFlowGraph,
        address: u64,
        length: usize,
        successors: Vec<(u64, Option<Expression>)>
    ) -> BlockTranslationResult {
        BlockTranslationResult {
            control_flow_graph: control_flow_graph,
            address: address,
            length: length,
            successors: successors
        }
    }

    pub fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn successors(&self) -> &Vec<(u64, Option<Expression>)> {
        &self.successors
    }
}


pub trait Arch {
    /// Translates a basic block
    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult>;


    fn endian(&self) -> Endian;


    /// Translates a function
    fn translate_function(
        &self,
        memory: &Memory,
        function_address: u64)
    -> Result<Function> {
        let mut translation_queue = VecDeque::new();
        let mut translation_results = BTreeMap::new();

        translation_queue.push_front(function_address);

        // translate all blocks in the function
        while translation_queue.len() > 0 {
            let block_address = translation_queue.pop_front().unwrap();

            if translation_results.contains_key(&block_address) {
                continue;
            }

            let block_bytes = match memory.get(block_address) {
                Some(bytes) => bytes,
                None => bail!(
                    "Failed to get bytes for block at {}",
                    block_address
                )
            };

            // translate this block
            let block_translation_result = self.translate_block(block_bytes, block_address)?;

            // enqueue all successors
            for successor in block_translation_result.successors().iter() {
                translation_queue.push_back(successor.0);
            }

            translation_results.insert(block_address, block_translation_result);
        }

        // We now insert all of these blocks into a new control flow graph,
        // keeping track of their new entry and exit indices.
        let mut indices: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        let mut control_flow_graph = ControlFlowGraph::new();
        for result in &translation_results {
            let (entry, exit) = control_flow_graph.insert(result.1.control_flow_graph())?;
            indices.insert(*result.0, (entry, exit));
        }

        // Insert the edges
        for result in translation_results {
            let &(this_entry, this_exit) = indices.get(&result.0).unwrap();
            for successor in result.1.successors().iter() {
                let &(that_entry, that_exit) = indices.get(&successor.0).unwrap();
                match successor.1 {
                    Some(ref condition) => control_flow_graph.conditional_edge(this_exit, that_entry, condition.clone())?,
                    None => control_flow_graph.unconditional_edge(this_exit, that_entry)?
                }
            }
        }

        // One block is the start of our control_flow_graph
        control_flow_graph.set_entry(indices[&function_address].0)?;

        // merge for the user
        control_flow_graph.merge()?;

        Ok(Function::new(function_address, control_flow_graph))
    }
}


pub fn x86() -> Box<Arch> {
    Box::new(x86::X86::new())
}