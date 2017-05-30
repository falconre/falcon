use analysis::analysis_location::AnalysisLocation::*;
use analysis::fixed_point::*;
use analysis::lattice::*;
use error::*;
use il;
use std::collections::BTreeMap;
use std::ops::Deref;


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endian {
    Big,
    Little
}


impl Into<::translator::Endian> for Endian {
    fn into(self) -> ::translator::Endian {
        match self {
            Endian::Big => ::translator::Endian::Big,
            Endian::Little => ::translator::Endian::Little
        }
    }
}


impl From<::translator::Endian> for Endian {
    fn from(e: ::translator::Endian) -> Endian {
        match e {
            ::translator::Endian::Big => Endian::Big,
            ::translator::Endian::Little => Endian::Little
        }
    }
}


impl From<::loader::Endian> for Endian {
    fn from(e: ::loader::Endian) -> Endian {
        match e {
            ::loader::Endian::Big => Endian::Big,
            ::loader::Endian::Little => Endian::Little
        }
    }
}


struct ValueSetAnalysis<'v> {
    control_flow_graph: &'v il::ControlFlowGraph,
    max: usize,
    endian: Endian
}


impl<'v> ValueSetAnalysis<'v> {
    pub fn new(
        control_flow_graph: &'v il::ControlFlowGraph,
        max: usize,
        endian: Endian
    ) -> ValueSetAnalysis<'v> {
        ValueSetAnalysis {
            control_flow_graph: control_flow_graph,
            max: max,
            endian: endian
        }
    }

    pub fn control_flow_graph(&self) -> &il::ControlFlowGraph {
        &self.control_flow_graph
    }

    pub fn endian(&self) -> &Endian {
        &self.endian
    }
}


pub fn compute(
    control_flow_graph: &il::ControlFlowGraph,
    max: usize,
    endian: Endian
) -> Result<BTreeMap<AnalysisLocation, LatticeAssignments>> {
    let value_set_analysis = ValueSetAnalysis::new(control_flow_graph, max, endian);
    fixed_point_forward(&value_set_analysis, value_set_analysis.control_flow_graph())
}


impl<'v> FixedPointAnalysis<LatticeAssignments> for ValueSetAnalysis<'v> {
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
            Edge(_) => {
                /*
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
                */
                state_out
            },
            Instruction(ref il) => {
                let operation = il.find(&self.control_flow_graph)?.operation();
                match *operation {
                    il::Operation::Assign { ref dst, ref src } => {
                        let lattice_value = state_out.eval(src);
                        state_out.set(
                            dst.borrow().deref().clone(),
                            lattice_value
                        );
                        state_out
                    }
                    il::Operation::Store { dst: _, ref index, ref src } => {
                        let index = state_out.eval(index);
                        let mut value = state_out.eval(src);
                        if self.endian == Endian::Little {
                            value = value.endian_swap()?;
                        }
                        state_out.store(&index, value, src.bits());
                        state_out
                    }
                    il::Operation::Load { ref dst, ref index, src: _ } => {
                        let index = state_out.eval(index);
                        match state_out.load(&index, dst.borrow().bits()) {
                            Some(value) => {
                                if self.endian == Endian::Little {
                                    state_out.set(
                                        dst.borrow().deref().clone(),
                                        value.endian_swap()?
                                    );
                                } else {
                                    state_out.set(
                                        dst.borrow().deref().clone(),
                                        value
                                    );
                                }

                            }
                            None => state_out.set(
                                dst.borrow().deref().clone(),
                                LatticeValue::Meet
                            )
                        }
                        state_out
                    }
                    il::Operation::Phi { ref dst, ref src } => {
                        if let il::Variable::Scalar(ref dst) = *dst {
                            if src.len() == 0 {
                                state_out.set(
                                    dst.borrow().deref().clone(),
                                    LatticeValue::Meet
                                );
                                state_out
                            }
                            else {
                                let mut src_: Vec<il::Scalar> = Vec::new();
                                for s in src {
                                    if let il::Variable::Scalar(ref s) = *s {
                                        src_.push(s.borrow().deref().clone());
                                    }
                                }

                                let src = src_;
                                let mut lattice_value = match state_out.get(src.first()
                                                                               .unwrap()) {
                                    Some(lv) => lv.clone(),
                                    None => LatticeValue::Meet
                                };
                                let meet = LatticeValue::Meet;
                                for lv in src {
                                    lattice_value = lattice_value.join(match state_out.get(&lv) {
                                        Some(lv) => lv,
                                        None => &&meet
                                    });
                                }
                                state_out.set(
                                    dst.borrow().deref().clone(),
                                    lattice_value.clone()
                                );
                                state_out
                            }
                        }
                        else {
                            state_out
                        }
                    }
                    il::Operation::Raise { expr: _ } |
                    il::Operation::Brc { target: _, condition: _ } => {
                        state_out
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
