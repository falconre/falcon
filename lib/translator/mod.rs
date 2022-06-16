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
//! Instructions for direct branches in Falcon IL are omitted in the IL, and
//! instead edges with conditional guards are emitted. The Brc operation is only
//! emitted for indirect branches, and instructions which are typically used to
//! call other functions.
//!
//! If you are lifting directly from loader (Elf/PE/other), you do not need to
//! pay attention to the translators. The correct translator will be chosen
//! automatically.

use crate::memory::MemoryPermissions;

pub mod aarch64;
mod block_translation_result;
pub mod mips;
mod options;
pub mod ppc;
pub mod x86;

use crate::il;
use crate::il::*;
use crate::Error;
pub use block_translation_result::BlockTranslationResult;
use falcon_capstone::capstone;
pub use options::{ManualEdge, Options, OptionsBuilder};
use std::collections::{BTreeMap, VecDeque};
pub(crate) const DEFAULT_TRANSLATION_BLOCK_BYTES: usize = 64;

/// This trait is used by the translator to continually find and lift bytes from an underlying
/// memory model.
///
/// Anything that implements this trait can be used as a memory backing for lifting.
pub trait TranslationMemory {
    fn permissions(&self, address: u64) -> Option<MemoryPermissions>;

    fn get_u8(&self, address: u64) -> Option<u8>;

    fn get_bytes(&self, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..length {
            match self.permissions(address) {
                Some(permissions) => {
                    if !permissions.contains(MemoryPermissions::EXECUTE) {
                        break;
                    }
                }
                None => break,
            }
            match self.get_u8(address + i as u64) {
                Some(u) => bytes.push(u),
                None => break,
            };
        }
        bytes
    }
}

// A convenience function for turning unhandled instructions into intrinsics
pub(crate) fn unhandled_intrinsic(
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &capstone::Instr,
) -> Result<(), Error> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(il::Intrinsic::new(
            instruction.mnemonic.clone(),
            format!("{} {}", instruction.mnemonic, instruction.op_str),
            Vec::new(),
            None,
            None,
            instruction.bytes.get(0..4).unwrap().to_vec(),
        ));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

/// A generic translation trait, implemented by various architectures.
pub trait Translator {
    /// Translates a basic block
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error>;

    /// Translates a function
    fn translate_function(
        &self,
        memory: &dyn TranslationMemory,
        function_address: u64,
    ) -> Result<Function, Error> {
        self.translate_function_extended(memory, function_address, &Options::default())
    }

    /// Translates a function
    ///
    /// Provides additional options over translate_function
    fn translate_function_extended(
        &self,
        memory: &dyn TranslationMemory,
        function_address: u64,
        options: &Options,
    ) -> Result<Function, Error> {
        // Addresses of blocks pending translation
        let mut translation_queue: VecDeque<u64> = VecDeque::new();

        // The results of block translations
        let mut translation_results: BTreeMap<u64, BlockTranslationResult> = BTreeMap::new();

        translation_queue.push_front(function_address);

        options.manual_edges().iter().for_each(|manual_edge| {
            translation_queue.push_back(manual_edge.head_address());
            translation_queue.push_back(manual_edge.tail_address());
        });

        // translate all blocks in the function
        while !translation_queue.is_empty() {
            let block_address = translation_queue.pop_front().unwrap();

            if translation_results.contains_key(&block_address) {
                continue;
            }

            let block_bytes = memory.get_bytes(block_address, DEFAULT_TRANSLATION_BLOCK_BYTES);
            if block_bytes.is_empty() {
                let mut control_flow_graph = ControlFlowGraph::new();
                let block_index = control_flow_graph.new_block()?.index();
                control_flow_graph.set_entry(block_index)?;
                control_flow_graph.set_exit(block_index)?;
                translation_results.insert(
                    block_address,
                    BlockTranslationResult::new(
                        vec![(block_address, control_flow_graph)],
                        block_address,
                        0,
                        Vec::new(),
                    ),
                );
                continue;
            }

            // translate this block
            let block_translation_result =
                self.translate_block(&block_bytes, block_address, options)?;

            // enqueue all successors
            for successor in block_translation_result.successors().iter() {
                if !translation_queue.contains(&successor.0) {
                    translation_queue.push_back(successor.0);
                }
            }

            translation_results.insert(block_address, block_translation_result);
        }

        // We now insert all of these blocks into a new control flow graph,
        // keeping track of their new entry and exit indices.

        // A mapping of instruction address to entry/exit vertex indices
        let mut instruction_indices: BTreeMap<u64, (usize, usize)> = BTreeMap::new();

        // A mapping of block address to entry/exit vertex indices;
        let mut block_indices: BTreeMap<u64, (usize, usize)> = BTreeMap::new();

        let mut control_flow_graph = ControlFlowGraph::new();
        for result in &translation_results {
            let block_translation_result = result.1;
            let mut block_entry = 0;
            let mut block_exit = 0;
            let mut previous_exit = None;
            for &(address, ref instruction_graph) in block_translation_result.instructions().iter()
            {
                // Have we already inserted this instruction?
                let (entry, exit) = if instruction_indices.get(&address).is_some() {
                    instruction_indices[&address]
                } else {
                    let (entry, exit) = control_flow_graph.insert(instruction_graph)?;
                    instruction_indices.insert(address, (entry, exit));
                    (entry, exit)
                };
                // If this is not our first instruction through this block.
                if let Some(previous_exit) = previous_exit {
                    // If an edge from the previous block to this block doesn't
                    // exist
                    if control_flow_graph.edge(previous_exit, entry).is_err() {
                        // Create an edge from the previous block to this block.
                        control_flow_graph.unconditional_edge(previous_exit, entry)?;
                    }
                }
                // Our first instruction through this block
                else {
                    block_entry = entry;
                }
                block_exit = exit;
                previous_exit = Some(exit);
            }
            block_indices.insert(*result.0, (block_entry, block_exit));
        }

        // Insert the edges

        // Start with edges for our manual edges
        for manual_edge in options.manual_edges() {
            let (_, edge_head) = block_indices[&manual_edge.head_address()];
            let (edge_tail, _) = block_indices[&manual_edge.tail_address()];

            if control_flow_graph.edge(edge_head, edge_tail).is_ok() {
                continue;
            }

            if let Some(condition) = manual_edge.condition() {
                control_flow_graph.conditional_edge(edge_head, edge_tail, condition.clone())?;
            } else {
                control_flow_graph.unconditional_edge(edge_head, edge_tail)?;
            }
        }

        // For every block translation result
        for (address, block_translation_result) in translation_results {
            // Get the exit index for the last/tail vertex in this block
            let (_, block_exit) = block_indices[&address];
            // For every successor in the block translation result (this is an
            // (address, condition) tuple)
            for (successor_address, successor_condition) in
                block_translation_result.successors().iter()
            {
                // get the entry index for the first/head block in the successor
                let (block_entry, _) = block_indices[successor_address];
                // check for duplicate edges
                if control_flow_graph.edge(block_exit, block_entry).is_ok() {
                    continue;
                }
                match successor_condition {
                    Some(ref condition) => control_flow_graph.conditional_edge(
                        block_exit,
                        block_entry,
                        condition.clone(),
                    )?,
                    None => control_flow_graph.unconditional_edge(block_exit, block_entry)?,
                }
            }
        }

        // One block is the start of our control_flow_graph
        control_flow_graph.set_entry(block_indices[&function_address].0)?;

        // merge for the user
        control_flow_graph.merge()?;

        Ok(Function::new(function_address, control_flow_graph))
    }
}
