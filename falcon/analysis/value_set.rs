use analysis::analysis_location::*;
use analysis::fixed_point::FixedPointAnalysis;
use error::*;
use il;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::{BTreeMap, BTreeSet};



// A lattice of possible values
#[derive(Clone, Eq, PartialEq)]
pub enum ValueSet {
    Join,
    Values(BTreeSet<u64>),
    Meet
}


use self::ValueSet::*;


impl Ord for ValueSet {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            &Join => {
                match other {
                    &Join => Ordering::Equal,
                    _ => Ordering::Less
                }
            },
            &Values(ref values) => {
                match other {
                    &Join => Ordering::Greater,
                    &Values(ref other_values) => values.cmp(other_values),
                    &Meet => Ordering::Less
                }
            },
            &Meet => {
                match other {
                    &Meet => Ordering::Equal,
                    _ => Ordering::Greater
                }
            }
        }
    }
}


impl PartialOrd for ValueSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl ValueSet {
    pub fn join() -> ValueSet {
        ValueSet::Join
    }

    pub fn meet() -> ValueSet {
        ValueSet::Meet
    }

    pub fn values() -> ValueSet {
        ValueSet::Values(BTreeSet::new())
    }
}


type ValueSetAssignments = BTreeMap<il::Variable, ValueSet>;


struct ValueSetAnalysis {
    control_flow_graph: il::ControlFlowGraph
}


impl ValueSetAnalysis {
    pub fn new(mut control_flow_graph: il::ControlFlowGraph) -> ValueSetAnalysis {
        control_flow_graph.ssa();
        ValueSetAnalysis {
            control_flow_graph: control_flow_graph
        }
    }
}


impl FixedPointAnalysis<ValueSetAssignments> for ValueSetAnalysis {
    fn initial(&self, analysis_location: &AnalysisLocation) -> Result<ValueSetAssignments> {
        Ok(BTreeMap::new())
    }


    fn trans(
        &self,
        analysis_location: &AnalysisLocation,
        state_in: &Option<ValueSetAssignments>
    ) -> Result<ValueSetAssignments> {

        let state_out = match state_in {
            &Some(ref state_in) => state_in.clone(),
            &None => BTreeMap::new()
        };

        Ok(state_out)
    }


    fn join(
        &self,
        mut state0: ValueSetAssignments,
        state1: &ValueSetAssignments
    ) -> Result<ValueSetAssignments> {
        Ok(state0)
    }
}