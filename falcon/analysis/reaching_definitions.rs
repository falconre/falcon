use analysis::fixed_point::*;
use analysis::analysis_location::AnalysisLocation::*;
use error::*;
use il;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;


/// The result of reaching definitions.
///
/// The result of reaching definitions is two sets, one with all
/// `AnalysisLocation`s which are valid upon entry to an `AnalysisLocation`
/// (the in_ set), and all `AnalysisLocation`s which are valid upon exit from
/// an `AnalysisLocation` (the out set).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Reaches {
    in_: BTreeSet<AnalysisLocation>,
    out: BTreeSet<AnalysisLocation>
}


impl Reaches {
    pub fn new() -> Reaches {
        Reaches {
            in_: BTreeSet::new(),
            out: BTreeSet::new()
        }
    }

    fn in_insert(&mut self, analysis_location: AnalysisLocation) {
        self.in_.insert(analysis_location);
    }

    fn in_remove(&mut self, analysis_location: &AnalysisLocation) {
        self.in_.remove(analysis_location);
    }

    /// The set of `AnalysisLocation`s whose variables written are valid upon
    /// entry to this `Reach`.
    pub fn in_(&self) -> &BTreeSet<AnalysisLocation> {
        &self.in_
    }

    fn set_in(&mut self, in_: BTreeSet<AnalysisLocation>) {
        self.in_ = in_;
    }

    fn set_in_to_out(&mut self) {
        self.in_ = self.out.clone();
    }

    fn out_insert(&mut self, analysis_location: AnalysisLocation) {
        self.out.insert(analysis_location);
    }

    fn out_remove(&mut self, analysis_location: &AnalysisLocation) {
        self.out.remove(analysis_location);
    }

    /// The set of AnalysisLocation whose variables written are valid upon
    /// exit from this `Reach`.
    pub fn out(&self) -> &BTreeSet<AnalysisLocation> {
        &self.out
    }

    fn set_out(&mut self, out: BTreeSet<AnalysisLocation>) {
        self.out = out;
    }

    // Provides a string representation of this struct.
    pub fn to_string(&self) -> String {
        format!(
            "{{in({}), out({})}}",
            self.in_()
                .iter()
                .map(|il| format!("{}", il))
                .collect::<Vec<String>>()
                .join(", "),
            self.out()
                .iter()
                .map(|il| format!("{}", il))
                .collect::<Vec<String>>()
                .join(", "),
               )
    }
}


impl Ord for Reaches {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.in_ < other.in_ {
            Ordering::Less
        }
        else if self.in_ > other.in_ {
            Ordering::Greater
        }
        else if self.out < other.out {
            Ordering::Less
        }
        else if self.out > other.out {
            Ordering::Greater
        }
        else {
            Ordering::Equal
        }
    }
}


impl PartialOrd for Reaches {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}




impl fmt::Display for Reaches {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}


pub fn compute(control_flow_graph: &il::ControlFlowGraph)
-> Result<BTreeMap<AnalysisLocation, Reaches>> {
    let reaching_definitions = ReachingDefinitions::new(control_flow_graph);
    reaching_definitions.compute()
}


struct ReachingDefinitions<'a> {
    control_flow_graph: &'a il::ControlFlowGraph
}


impl<'a> ReachingDefinitions<'a> {
    pub fn new(control_flow_graph: &'a il::ControlFlowGraph) -> ReachingDefinitions<'a> {
        ReachingDefinitions {
            control_flow_graph: control_flow_graph
        }
    }

    pub fn compute(&self) -> Result<BTreeMap<AnalysisLocation, Reaches>> {
        fixed_point(self, &self.control_flow_graph)
    }
}



impl<'f> FixedPointAnalysis<Reaches> for ReachingDefinitions<'f> {
    fn initial(&self, analysis_location: &AnalysisLocation) -> Result<Reaches> {
        Ok(Reaches::new())
    }


    fn trans(
        &self,
        analysis_location: &AnalysisLocation,
        reaches_in: &Option<Reaches>
    ) -> Result<Reaches> {

        // Copy in state to out state
        let mut reaches_out = match reaches_in {
            &Some(ref reaches_in) => {
                reaches_in.clone()
            }
            &None => Reaches::new()
        };

        // reaches_out.out() contains the outputs of all the predecessor
        // analylis_location points for this analysis_location. We need to
        // copy those over to reaches_out.in()
        reaches_out.set_in_to_out();

        // Handle edges and instructions differently, as edges never assign and
        // always pass reaching definitions through
        match analysis_location {
            // Edges...
            &Edge(_) => return Ok(reaches_out),
            // Instructions..
            &Instruction(ref ii) => { 
                // If this instruction writes to a variable
                if let Some(this_dst) = ii.find(self.control_flow_graph)?
                                        .variable_written() {

                    let mut to_kill = Vec::new();
                    // Evaluate every location that reaches this location as a
                    // candidate to be killed.
                    for kill_location in reaches_out.in_().iter() {
                        // Candidates should always be instructions.
                        if let &AnalysisLocation::Instruction(ref ii) = kill_location {
                            // If this candidate writes to an instruction
                            if let Some(dst) = ii.find(self.control_flow_graph)?
                                                 .variable_written() {
                                // Do they write to the same variable?
                                if this_dst.name() == dst.name() {
                                    // Add this kill_location to be killed.
                                    to_kill.push(kill_location.clone());
                                }
                            }
                        }
                    }

                    // Remove all the locations we identified for killing from
                    // the out set.
                    for tk in to_kill {
                        reaches_out.out_remove(&tk);
                    }

                    // Add this location to the out set.
                    reaches_out.out_insert(ii.clone().into());
                }

                Ok(reaches_out)
            },
            &EmptyBlock(_) => return Ok(reaches_out)
        }
    }


    fn join(&self, mut state0: Reaches, state1: &Reaches) -> Result<Reaches> {
        for al in state1.out() {
            state0.out_insert(al.clone());
        }
        Ok(state0)
    }
}