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

        let mut state_out = match state_in {
            &Some(ref state_in) => state_in.clone(),
            &None => LatticeAssignments::new(self.max)
        };

        if let &Instruction(ref il) = analysis_location {
            let operation = il.find(&self.control_flow_graph)?.operation();
            match operation {
                &il::Operation::Assign { ref dst, ref src } => {
                    for variable in operation.variables_read() {
                    }
                    let lattice_value = state_out.eval(src);
                    state_out.set(dst.clone(), lattice_value);
                }
                &il::Operation::Store { ref address, ref src } => {

                }
                &il::Operation::Load { ref dst, ref address } => {
                    state_out.set(dst.clone(), LatticeValue::Join)
                }
                &il::Operation::Brc { ref dst, ref condition } => {

                }
                &il::Operation::Phi { ref dst, ref src } => {
                    if src.len() == 0 {
                        state_out.set(dst.clone(), LatticeValue::Meet)
                    }
                    else {
                        let lattice_value = match state_out.get(src.first().unwrap()) {
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
                    }
                }
            }
        }

        Ok(state_out)
    }


    fn join(
        &self,
        state0: LatticeAssignments,
        state1: &LatticeAssignments
    ) -> Result<LatticeAssignments> {
        Ok(state0.join(state1))
    }
}
