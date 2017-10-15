use analysis::fixed_point;
use error::*;
use il;
use std::collections::{BTreeMap, BTreeSet};


struct ReachingDefinitions {}


#[allow(dead_code)]
/// Compute reaching definitions for the given function.
pub fn reaching_definitions<'r>(function: &'r il::Function)
-> Result<BTreeMap<il::RefProgramLocation<'r>, BTreeSet<il::RefProgramLocation<'r>>>> {
    fixed_point::fixed_point_forward(ReachingDefinitions{}, function)
}


impl<'r> fixed_point::FixedPointAnalysis<'r, BTreeSet<il::RefProgramLocation<'r>>> for ReachingDefinitions {
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
                let mut kill = Vec::new();
                if let Some(variable) = instruction.operation().variable_written() {
                    for location in &state {
                        if location.instruction()
                                   .unwrap()
                                   .operation()
                                   .variable_written()
                                   .unwrap()
                                   .multi_var_clone() == variable.multi_var_clone() {
                            kill.push(location.clone());
                        }
                    }
                    for k in kill {
                        state.remove(&k);
                    }
                    state.insert(location.clone());
                }
            },
            il::RefFunctionLocation::EmptyBlock(_) |
            il::RefFunctionLocation::Edge(_) => {}
        }

        Ok(state)
    }


    fn join(
        &self,
        mut state0: BTreeSet<il::RefProgramLocation<'r>>,
        state1: &'r BTreeSet<il::RefProgramLocation>
    ) -> Result<BTreeSet<il::RefProgramLocation<'r>>> {
        for state in state1 {
            state0.insert(state.clone());
        }
        Ok(state0)
    }
}