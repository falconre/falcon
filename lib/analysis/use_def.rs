use analysis::{LocationSet, reaching_definitions};
use error::*;
use il;
use std::collections::HashMap;


#[allow(dead_code)]
/// Compute use definition chains for the given function.
pub fn use_def<'r>(function: &'r il::Function)
-> Result<HashMap<il::RefProgramLocation<'r>, LocationSet<'r>>> {
    let rd = reaching_definitions::reaching_definitions(function)?;

    let mut ud = HashMap::new();

    for (location, _) in &rd {
        let defs = match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, ref instruction) => {
                instruction.operation()
                           .scalars_read()
                           .into_iter()
                           .fold(LocationSet::new(), |mut defs, scalar_read| {
                            rd[&location].locations().into_iter().for_each(|rd|
                                if rd.instruction()
                                     .unwrap()
                                     .operation()
                                     .scalar_written()
                                     .unwrap() == scalar_read {
                                    defs.insert(rd.clone());
                                }
                            );
                            defs
                           })
            },
            il::RefFunctionLocation::Edge(ref edge) =>
                edge.condition()
                    .map(|condition|
                        condition.scalars()
                                 .into_iter()
                                 .fold(LocationSet::new(), |mut defs, scalar| {
                                    rd[&location].locations().into_iter().for_each(|rd|
                                        if rd.instruction()
                                             .unwrap()
                                             .operation()
                                             .scalar_written()
                                             .unwrap() == scalar {
                                            defs.insert(rd.clone());
                                        }
                                    );
                                    defs
                                 })
                        )
                        .unwrap_or(LocationSet::new()),
            il::RefFunctionLocation::EmptyBlock(_) => LocationSet::new()
        };
        ud.insert(location.clone(), defs);
    }

    Ok(ud)
}



#[test]
fn use_def_test() {
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

    control_flow_graph.set_entry(head_index).unwrap();

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