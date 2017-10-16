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
        state1: &'r BTreeSet<il::RefProgramLocation>
    ) -> Result<BTreeSet<il::RefProgramLocation<'r>>> {
        for state in state1 {
            state0.insert(state.clone());
        }
        Ok(state0)
    }
}