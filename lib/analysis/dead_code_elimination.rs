//! Dead-Code Elimination

use crate::analysis::{def_use, reaching_definitions};
use crate::il;
use crate::Error;
use std::collections::HashSet;

#[allow(dead_code)]
/// Eliminate dead code in an IL function
///
/// This pass does not eliminate variables which cross boundaries of
/// instructions where the operation is `il::Operation::Branch`. This should
/// preserve soundness, but reduces the amount of dead code eliminated.
///
/// Instructions are not removed by this analysis. Instead, they are replaced
/// with `nop` operations. This preserves the location of the removed
/// instruction, in case an analysis needs to find that instruction later.
pub fn dead_code_elimination(function: &il::Function) -> Result<il::Function, Error> {
    let rd = reaching_definitions::reaching_definitions(function)?;

    // This is a set of assignments we will always consider used.
    let mut live: HashSet<il::FunctionLocation> = HashSet::new();

    // Every assignment that reaches the last instruction in a block with no
    // successor
    function
        .blocks()
        .into_iter()
        .filter(|block| {
            function
                .control_flow_graph()
                .edges_out(block.index())
                .unwrap()
                .is_empty()
        })
        .for_each(|block| {
            let rfl = if let Some(instruction) = block.instructions().last() {
                il::RefFunctionLocation::Instruction(block, instruction)
            } else {
                il::RefFunctionLocation::EmptyBlock(block)
            };
            let rpl = il::RefProgramLocation::new(function, rfl);

            rd.get(&rpl.into())
                .unwrap()
                .locations()
                .iter()
                .for_each(|location| {
                    live.insert(location.function_location().clone());
                });
        });

    for block in function.blocks() {
        for instruction in block.instructions() {
            match *instruction.operation() {
                il::Operation::Branch { .. } | il::Operation::Intrinsic { .. } => {
                    let rpl = il::RefProgramLocation::new(
                        function,
                        il::RefFunctionLocation::Instruction(block, instruction),
                    );
                    rd[&rpl.into()].locations().iter().for_each(|location| {
                        live.insert(location.function_location().clone());
                    });
                }
                _ => {}
            }
        }
    }

    let du = def_use(function)?;

    // Get every assignment with no uses, that isn't in live
    let kill = function
        .locations()
        .into_iter()
        .filter(|location| {
            location
                .instruction()
                .map(|instruction| {
                    !instruction
                        .scalars_written()
                        .map(|scalars_written| scalars_written.is_empty())
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        })
        .filter(|location| !live.contains(&location.clone().into()))
        .filter(|location| du[&location.clone().program_location(function).into()].is_empty())
        .map(|l| l.into())
        .collect::<Vec<il::FunctionLocation>>();

    // Eliminate those instructions from our new function
    let mut dce_function = function.clone();

    for k in kill {
        let instruction_index = k.instruction_index().unwrap();
        let block_index = k.block_index().unwrap();
        let block = dce_function.block_mut(block_index).unwrap();
        *block
            .instruction_mut(instruction_index)
            .ok_or("Failed to find instruction")?
            .operation_mut() = il::Operation::nop();
    }

    Ok(dce_function)
}
