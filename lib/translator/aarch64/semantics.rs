use crate::error::Result;
use crate::il;
use crate::translator::aarch64::register::get_register;

// A convenience function for turning unhandled instructions into intrinsics
pub(super) fn unhandled_intrinsic(
    bytes: &[u8],
    control_flow_graph: &mut il::ControlFlowGraph,
    instruction: &bad64::Instruction,
) -> Result<()> {
    let block_index = {
        let block = control_flow_graph.new_block()?;

        block.intrinsic(il::Intrinsic::new(
            instruction.op().to_string(),
            instruction.to_string(),
            Vec::new(),
            None,
            None,
            bytes.to_vec(),
        ));

        block.index()
    };

    control_flow_graph.set_entry(block_index)?;
    control_flow_graph.set_exit(block_index)?;

    Ok(())
}

// TODO: Rest of the instructions
