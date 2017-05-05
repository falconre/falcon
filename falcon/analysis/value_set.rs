use analysis::analysis_location::AnalysisLocation::*;
use analysis::fixed_point::*;
use analysis::lattice::*;
use error::*;
use il;
use std::collections::BTreeMap;

struct ValueSetAnalysis<'v> {
    control_flow_graph: &'v il::ControlFlowGraph,
    max: usize
}


impl<'v> ValueSetAnalysis<'v> {
    pub fn new(control_flow_graph: &'v il::ControlFlowGraph, max: usize)
    -> ValueSetAnalysis<'v> {
        ValueSetAnalysis {
            control_flow_graph: control_flow_graph,
            max: max
        }
    }

    pub fn control_flow_graph(&self) -> &il::ControlFlowGraph {
        &self.control_flow_graph
    }
}


pub fn compute(control_flow_graph: &il::ControlFlowGraph, max: usize)
-> Result<BTreeMap<AnalysisLocation, LatticeAssignments>> {
    let value_set_analysis = ValueSetAnalysis::new(control_flow_graph, max);
    fixed_point(&value_set_analysis, value_set_analysis.control_flow_graph())
}


impl<'v> FixedPointAnalysis<LatticeAssignments> for ValueSetAnalysis<'v> {
    fn initial(&self, analysis_location: &AnalysisLocation) -> Result<LatticeAssignments> {
        Ok(LatticeAssignments::new(self.max))
    }


    fn trans(
        &self,
        analysis_location: &AnalysisLocation,
        state_in: &Option<LatticeAssignments>
    ) -> Result<LatticeAssignments> {

        let mut state_out = match *state_in {
            Some(ref state_in) => state_in.clone(),
            None => LatticeAssignments::new(self.max)
        };
        
        Ok(match *analysis_location {
            // For edges, we will first evaluate the conditional expression.
            // If the conditional expression evaluates to a single value of 0,
            // we will not pass through state_in, as the destination of this
            // branch is currently unreachable.
            Edge(ref el) => {
                let edge = el.find(self.control_flow_graph)?;
                if let Some(ref condition) = *edge.condition() {
                    let condition_value = state_out.eval(condition);
                    match condition_value {
                        LatticeValue::Join |
                        LatticeValue::Meet => state_out,
                        LatticeValue::Values(ref values) => {
                            if    values.len() == 1 
                               && values.iter().next().unwrap().value() == 0 {
                                LatticeAssignments::new(self.max)
                            }
                            else {
                                state_out
                            }
                        }
                    }
                }
                else {
                    state_out
                }
            },
            Instruction(ref il) => {
                let operation = il.find(&self.control_flow_graph)?.operation();
                match operation {
                    &il::Operation::Assign { ref dst, ref src } => {
                        for variable in operation.variables_read() {
                        }
                        let lattice_value = state_out.eval(src);
                        //info!("{} = {}", operation, lattice_value);
                        state_out.set(dst.clone(), lattice_value);
                        state_out
                    }
                    &il::Operation::Store { ref address, ref src } => {
                        state_out
                    }
                    &il::Operation::Load { ref dst, ref address } => {
                        state_out.set(dst.clone(), LatticeValue::Join);
                        state_out
                    }
                    &il::Operation::Brc { ref dst, ref condition } => {
                        state_out
                    }
                    &il::Operation::Phi { ref dst, ref src } => {
                        if src.len() == 0 {
                            state_out.set(dst.clone(), LatticeValue::Meet);
                            state_out
                        }
                        else {
                            let lattice_value = match state_out.get(src.first()
                                                                       .unwrap()) {
                                Some(lv) => lv.clone(),
                                None => LatticeValue::Meet
                            };
                            let meet = LatticeValue::Meet;
                            for lv in src {
                                let lattice_value = lattice_value.join(match state_out.get(&lv) {
                                    Some(lv) => lv,
                                    None => &&meet
                                });
                            }
                            state_out.set(dst.clone(), lattice_value.clone());
                            state_out
                        }
                    }
                }
            },
            EmptyBlock(_) => state_out
        })
    }


    fn join(
        &self,
        state0: LatticeAssignments,
        state1: &LatticeAssignments
    ) -> Result<LatticeAssignments> {
        Ok(state0.join(state1))
    }
}
