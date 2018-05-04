//! Dead-Code Elimination

use analysis::{reaching_definitions, def_use};
use error::*;
use il;
use std::collections::HashSet;


#[allow(dead_code)]
/// Eliminate dead code in an IL function
pub fn dead_code_elimination(function: &il::Function)
    -> Result<il::Function> {

    let rd = reaching_definitions::reaching_definitions(function)?;

    // This is a set of assignments we will always consider used.
    let mut live: HashSet<il::RefFunctionLocation> = HashSet::new();

    // Every assignment that reaches the last instruction in a block with no
    // successor
    function.blocks()
        .into_iter()
        .filter(|block|
            function.control_flow_graph()
                .edges_out(block.index())
                .unwrap()
                .is_empty())
        .for_each(|block| {
            let rfl =
                if let Some(instruction) = block.instructions().last() {
                    il::RefFunctionLocation::Instruction(block, instruction)
                }
                else {
                    il::RefFunctionLocation::EmptyBlock(block)
                };
            let rpl = il::RefProgramLocation::new(function, rfl);

            rd.get(&rpl).unwrap().locations()
                .iter()
                .for_each(|location| {
                    live.insert(location.function_location().clone().into());
                });
        });

    for block in function.blocks() {
        for instruction in block.instructions() {
            match *instruction.operation() {
                il::Operation::Branch { .. } |
                il::Operation::Raise { .. } => {
                    let rpl = il::RefProgramLocation::new(function,
                        il::RefFunctionLocation::Instruction(block, instruction));
                    rd[&rpl].locations()
                        .into_iter()
                        .for_each(|location| {
                            live.insert(location.function_location().clone());
                        });
                }
                _ => {}
            }
        }
    }

    let du = def_use(function)?;

    // Get every assignment with no uses, that isn't in live
    let kill =
        function.locations()
            .into_iter()
            .filter(|location|
                    location.instruction().map(|instruction|
                        !instruction.scalars_written().is_empty())
                    .unwrap_or(false))
            .filter(|location| !live.contains(location))
            .filter(|location|
                du[&location.clone().program_location(function)].is_empty())
            .collect::<Vec<il::RefFunctionLocation>>();

    // Eliminate those instructions from our new function
    let kill: Vec<il::FunctionLocation> =
        kill.into_iter()
            .map(|location| location.into())
            .collect();

    let mut dce_function = function.clone();

    for k in kill {
        let instruction_index = k.instruction_index().unwrap();
        let block_index = k.block_index().unwrap();
        let mut block = dce_function.block_mut(block_index).unwrap();
        block.remove_instruction(instruction_index)?;
    }

    Ok(dce_function)
}