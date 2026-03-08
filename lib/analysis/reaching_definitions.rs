use crate::analysis::{fixed_point, LocationSet};
use crate::il;
use crate::Error;
use std::collections::HashMap;

/// Compute reaching definitions for the given function.
pub fn reaching_definitions(
    function: &il::Function,
) -> Result<HashMap<il::ProgramLocation, LocationSet>, Error> {
    let rda = ReachingDefinitionsAnalysis { function };
    fixed_point::fixed_point_forward(rda, function)
}

// We require a struct to implement methods for our analysis over.
struct ReachingDefinitionsAnalysis<'r> {
    function: &'r il::Function,
}

impl<'r> fixed_point::FixedPointAnalysis<'r, LocationSet> for ReachingDefinitionsAnalysis<'r> {
    fn trans(
        &self,
        location: il::RefProgramLocation<'r>,
        state: Option<LocationSet>,
    ) -> Result<LocationSet, Error> {
        let mut state = match state {
            Some(state) => state,
            None => LocationSet::new(),
        };

        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                instruction
                    .operation()
                    .scalars_written()
                    .into_iter()
                    .for_each(|scalar_written| {
                        let kill: Vec<il::ProgramLocation> = state
                            .locations()
                            .iter()
                            .filter(|location| {
                                location
                                    .function_location()
                                    .apply(self.function)
                                    .unwrap()
                                    .instruction()
                                    .unwrap()
                                    .operation()
                                    .scalars_written()
                                    .into_iter()
                                    .any(|scalar| scalar == scalar_written)
                            })
                            .cloned()
                            .collect();
                        kill.iter().for_each(|location| state.remove(location));
                        state.insert(location.clone().into());
                    });
            }
            il::RefFunctionLocation::EmptyBlock(_) | il::RefFunctionLocation::Edge(_) => {}
        }

        Ok(state)
    }

    fn join(&self, mut state0: LocationSet, state1: &LocationSet) -> Result<LocationSet, Error> {
        state1
            .locations()
            .iter()
            .for_each(|location| state0.insert(location.clone()));
        Ok(state0)
    }
}

#[test]
fn reaching_definitions_test() {
    /*
    a = in
    b = 4
    if a < 10 {
        c = a
        [0xdeadbeef] = c
    }
    else {
        c = b
    }
    b = c
    c = [0xdeadbeef]
    */
    let mut control_flow_graph = il::ControlFlowGraph::new();

    let head_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("a", 32), il::expr_scalar("in", 32));
        block.assign(il::scalar("b", 32), il::expr_const(4, 32));

        block.index()
    };

    let gt_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("c", 32), il::expr_scalar("b", 32));

        block.index()
    };

    let lt_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("c", 32), il::expr_scalar("a", 32));
        block.store(il::expr_const(0xdeadbeef, 32), il::expr_scalar("c", 32));

        block.index()
    };

    let tail_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("b", 32), il::expr_scalar("c", 32));
        block.load(il::scalar("c", 32), il::expr_const(0xdeadbeef, 32));

        block.index()
    };

    let condition =
        il::Expression::cmpltu(il::expr_scalar("a", 32), il::expr_const(10, 32)).unwrap();

    control_flow_graph
        .conditional_edge(head_index, lt_index, condition.clone())
        .unwrap();
    control_flow_graph
        .conditional_edge(
            head_index,
            gt_index,
            il::Expression::cmpeq(condition, il::expr_const(0, 1)).unwrap(),
        )
        .unwrap();

    control_flow_graph
        .unconditional_edge(lt_index, tail_index)
        .unwrap();
    control_flow_graph
        .unconditional_edge(gt_index, tail_index)
        .unwrap();

    control_flow_graph.set_entry(head_index).unwrap();

    let function = il::Function::new(0, control_flow_graph);

    let rd = reaching_definitions(&function).unwrap();

    // for r in rd.iter() {
    //     println!("{}", r.0);
    //     for d in r.1 {
    //         println!("  {}", d);
    //     }
    // }

    let block = function.control_flow_graph().block(3).unwrap();
    let instruction = block.instruction(0).unwrap();

    let function_location = il::RefFunctionLocation::Instruction(block, instruction);
    let program_location = il::RefProgramLocation::new(&function, function_location);

    let r = &rd[&program_location.into()];

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(r.contains(
        &il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()
    ));

    let block = function.control_flow_graph().block(1).unwrap();
    assert!(r.contains(
        &il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()
    ));

    let block = function.control_flow_graph().block(2).unwrap();
    assert!(r.contains(
        &il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()
    ));

    let block = function.control_flow_graph().block(3).unwrap();
    assert!(r.contains(
        &il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()
    ));

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(!r.contains(
        &il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(1).unwrap())
        )
        .into()
    ));
}
