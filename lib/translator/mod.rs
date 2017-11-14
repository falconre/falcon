//! Translators for various architectures to Falcon IL.
//!
//! Translators in Falcon do not lift individual instructions, but instead lift
//! basic blocks. This is both more performant than lifting individual
//! instructions, and allows Falcon to deal with weird cases such as the delay
//! slot in the MIPS architecture.
//!
//! Translators lift individual instructions to `ControlFlowGraph`, and combine
//! these graphs to form a single block. A single instruction may lift to not
//! only multiple Falcon IL instructions, but also multiple IL blocks.
//!
//! Direct branches in Falcon IL are omitted in the IL, and instead edges with
//! conditional guards are emitted. The Brc operation is only emitted for
//! indirect branches, and instructions which are typically used to call other
//! procedures.
//!
//! If you are lifting directly from an Elf binary, you do not need to pay
//! attention to the translators. The correct translator will be chosen
//! automatically.

use error::*;
use il::*;
use memory::MemoryPermissions;
use std::collections::{BTreeMap, VecDeque};

pub mod x86;
pub mod mips;


const DEFAULT_TRANSLATION_BLOCK_BYTES: usize = 64;

/// This trait is used by the translator to continually find and lift bytes from an underlying
/// memory model.
///
/// Anything that implements this trait can be used as a memory backing for lifting.
pub trait TranslationMemory {
    fn permissions(&self, address:u64) -> Option<MemoryPermissions>;

    fn get_u8(&self, address: u64) -> Option<u8>;

    fn get_bytes(&self, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..length {
            match self.permissions(address) {
                Some(permissions) => if !permissions.contains(MemoryPermissions::EXECUTE) {
                    break;
                },
                None => break
            }
            match self.get_u8(address + i as u64) {
                Some(u) => bytes.push(u),
                None => break
            };
        }
        bytes
    }
}


/// The result of translating a block from a native architecture.
///
/// # Native blocks translated to `ControlFlowGraph`
///
/// While a block on the native architecture may be a linear sequence of instructions,
/// when lifted this block may actually contain loops, conditionally executed instructions,
/// and a host of other oddness. Translators therefor return a `ControlFlowGraph` for the
/// translation of a block. The *entry* and *exit* for this `ControlFlowGraph` should be
/// set.
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
    /// Create a new `BlockTranslationResult`.
    ///
    /// # Parameters
    /// * `control_flow_graph` - A `ControlFlowGraph` representing the semantics of this block.
    /// * `address` - The address where this block was lifted.
    /// * `length` - The length of the block in bytes.
    /// * `successors` - Tuples of addresses and optional conditions for successors to this block.
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

    /// Get the `ControlFlowGraph` for this `BlockTranslationResult`
    pub fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }

    /// Get the address wherefrom this block was translated.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the length of this block in bytes.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Get the successors for this block.
    pub fn successors(&self) -> &Vec<(u64, Option<Expression>)> {
        &self.successors
    }
}


/// A generic translation trait, implemented by various architectures.
pub trait Translator: {
    /// Translates a basic block
    fn translate_block(&self, bytes: &[u8], address: u64) -> Result<BlockTranslationResult>;

    /// Translates a function
    fn translate_function(
        &self,
        memory: &TranslationMemory,
        function_address: u64)
    -> Result<Function> {

        let mut translation_queue = VecDeque::new();
        let mut translation_results = BTreeMap::new();

        translation_queue.push_front(function_address);

        // translate all blocks in the function
        while !translation_queue.is_empty() {
            let block_address = translation_queue.pop_front().unwrap();

            if translation_results.contains_key(&block_address) {
                continue;
            }

            let block_bytes = memory.get_bytes(block_address, DEFAULT_TRANSLATION_BLOCK_BYTES);

            // translate this block
            let block_translation_result = self.translate_block(&block_bytes, block_address)?;

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
            let (_, this_exit) = indices[&result.0];
            for successor in result.1.successors().iter() {
                let (that_entry, _) = indices[&successor.0];
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