use crate::il::*;
use crate::Error;

/// The result of translating a block from a native architecture.
///
/// # Native blocks translated to `ControlFlowGraph`
///
/// While a block on the native architecture may be a linear sequence of instructions,
/// when lifted this block may actually contain loops, conditionally executed instructions,
/// and a host of other oddness. Translators therefor return a `ControlFlowGraph` for the
/// translation of a block. The *entry* and *exit* for this `ControlFlowGraph` should be
/// set.
#[derive(Clone, Debug)]
pub struct BlockTranslationResult {
    /// A vector of one `ControlFlowGraph` per instruction, which represents the
    /// semantics of this block
    instructions: Vec<(u64, ControlFlowGraph)>,
    /// The address at which this block was translated
    address: u64,
    /// The length of this block in bytes as represented in the host architecture
    length: usize,
    /// Addresses of known successor blocks, and optional conditions to reach them
    successors: Vec<(u64, Option<Expression>)>,
}

impl BlockTranslationResult {
    /// Create a new `BlockTranslationResult`.
    ///
    /// # Parameters
    /// * `instructions` - A Vec of address/`ControlFlowGraph` pairs, one per instruction.
    /// * `address` - The address where this block was lifted.
    /// * `length` - The length of the block in bytes.
    /// * `successors` - Tuples of addresses and optional conditions for successors to this block.
    pub fn new(
        instructions: Vec<(u64, ControlFlowGraph)>,
        address: u64,
        length: usize,
        successors: Vec<(u64, Option<Expression>)>,
    ) -> BlockTranslationResult {
        BlockTranslationResult {
            instructions,
            address,
            length,
            successors,
        }
    }

    /// Get the `ControlFlowGraph` for this `BlockTranslationResult`
    pub fn instructions(&self) -> &Vec<(u64, ControlFlowGraph)> {
        &self.instructions
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

    /// Return a single `ControlFlowGraph` for this block
    pub fn blockify(&self) -> Result<ControlFlowGraph, Error> {
        let mut control_flow_graph = ControlFlowGraph::new();

        let block_index = {
            let block = control_flow_graph.new_block()?;
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        for (_, cfg) in &self.instructions {
            control_flow_graph.append(cfg)?;
        }

        control_flow_graph.merge()?;

        Ok(control_flow_graph)
    }
}
