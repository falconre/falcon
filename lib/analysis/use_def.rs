use analysis::{fixed_point, reaching_definitions};
use error::*;
use il;
use il::variable::Variable;
use std::collections::{BTreeMap, BTreeSet};


#[allow(dead_code)]
struct UseDef<'r> {
    rd: BTreeMap<il::RefProgramLocation<'r>, BTreeSet<il::RefProgramLocation<'r>>>
}


#[allow(dead_code)]
/// Compute use definition chains for the given function.
pub fn use_def<'r>(function: &'r il::Function)
-> Result<BTreeMap<il::RefProgramLocation<'r>, BTreeSet<il::RefProgramLocation<'r>>>> {
    let rd = reaching_definitions::reaching_definitions(function)?;
    fixed_point::fixed_point_forward(UseDef { rd: rd }, function)
}


impl<'r> fixed_point::FixedPointAnalysis<'r, BTreeSet<il::RefProgramLocation<'r>>> for UseDef<'r> {
    fn trans(
        &self,
        location: il::RefProgramLocation<'r>,
        state: Option<BTreeSet<il::RefProgramLocation<'r>>>
    ) -> Result<BTreeSet<il::RefProgramLocation<'r>>> {

        let mut state = match state {
            Some(state) => state,
            None => BTreeSet::new()
        };

        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, ref instruction) => {
                let mut new_locations = Vec::new();
                for variable_read in instruction.operation().variables_read() {
                    for rd in &self.rd[&location] {
                        if rd.instruction()
                             .unwrap()
                             .operation()
                             .variable_written()
                             .unwrap()
                             .multi_var_clone() == variable_read.multi_var_clone() {
                            new_locations.push(rd.clone());
                        }
                    }
                }
                for new_location in new_locations {
                    state.insert(new_location);
                }
            },
            il::RefFunctionLocation::Edge(ref edge) => {
                if let Some(ref condition) = *edge.condition() {
                    let mut new_locations = Vec::new();
                    for variable_read in condition.scalars() {
                        for rd in &self.rd[&location] {
                            if rd.instruction()
                                 .unwrap()
                                 .operation()
                                 .variable_written()
                                 .unwrap()
                                 .multi_var_clone() == variable_read.multi_var_clone() {
                                new_locations.push(rd.clone());
                            }
                        }
                    }
                    for new_location in new_locations {
                        state.insert(new_location);
                    }
                }
            },
            il::RefFunctionLocation::EmptyBlock(_) => {}
        }

        Ok(state)
    }


    fn join(
        &self,
        mut state0: BTreeSet<il::RefProgramLocation<'r>>,
        state1: &BTreeSet<il::RefProgramLocation<'r>>
    ) -> Result<BTreeSet<il::RefProgramLocation<'r>>> {
        for state in state1 {
            state0.insert(state.clone());
        }
        Ok(state0)
    }
}


#[test]
fn use_def_test() {
    /*
    a = in
    b = 4
    if a < 10 {
        c = a
    }
    else {
        c = b
    }
    b = c
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

        block.index()
    };

    let tail_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("b", 32), il::expr_scalar("c", 32));

        block.index()
    };

    let condition = il::Expression::cmpltu(
        il::expr_scalar("a", 32),
        il::expr_const(10, 32)
    ).unwrap();

    control_flow_graph.conditional_edge(head_index, lt_index, condition.clone()).unwrap();
    control_flow_graph.conditional_edge(head_index, gt_index, 
        il::Expression::cmpeq(condition, il::expr_const(0, 1)).unwrap()
    ).unwrap();

    control_flow_graph.unconditional_edge(lt_index, tail_index).unwrap();
    control_flow_graph.unconditional_edge(gt_index, tail_index).unwrap();

    let function = il::Function::new(0, control_flow_graph);

    let ud = use_def(&function).unwrap();

    // for u in ud.iter() {
    //     println!("{}", u.0);
    //     for d in u.1 {
    //         println!("  {}", d);
    //     }
    // }

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].len() == 0);

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(1).unwrap()
        )
    )].len() == 0);

    let block = function.control_flow_graph().block(1).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].len() == 1);

    let block = function.control_flow_graph().block(3).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].contains(&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            function.control_flow_graph().block(1).unwrap(),
            function.control_flow_graph().block(1).unwrap().instruction(0).unwrap()
        )
    )));

    let block = function.control_flow_graph().block(3).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].contains(&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            function.control_flow_graph().block(2).unwrap(),
            function.control_flow_graph().block(2).unwrap().instruction(0).unwrap()
        )
    )));

    let block = function.control_flow_graph().block(3).unwrap();
    assert!(ud[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].len() == 2);
}