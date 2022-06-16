//! Determine offset of stack pointer from function entry.
//!
//! Determine the value of the stack pointer at every location in the function
//! as an offset from the stack pointer's value at function entry.
//!
//! This analysis works off a very simple lattice, Top/Value/Bottom, where Value
//! is an isize.

use crate::analysis::fixed_point;
use crate::architecture::Architecture;
use crate::executor::eval;
use crate::il;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, PartialOrd};
use std::collections::HashMap;

/// Determine offset of stack pointer from program entry at each place in the
/// program.
pub fn stack_pointer_offsets(
    function: &il::Function,
    architecture: &dyn Architecture,
) -> Result<HashMap<il::ProgramLocation, StackPointerOffset>, Error> {
    let spoa = StackPointerOffsetAnalysis {
        stack_pointer: architecture.stack_pointer(),
    };
    transform(fixed_point::fixed_point_forward(spoa, function)?)
}

/// Returns true if there is a valid StackPointerOffset value for every location
/// in the function.
pub fn perfect(
    stack_pointer_offsets: &HashMap<il::RefProgramLocation, StackPointerOffset>,
) -> bool {
    stack_pointer_offsets.iter().all(|(_, spo)| spo.is_value())
}

/// The offset of the stack pointer from the beginning of the function.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StackPointerOffset {
    Top,
    Value(isize),
    Bottom,
}

impl StackPointerOffset {
    pub fn is_top(&self) -> bool {
        matches!(self, StackPointerOffset::Top)
    }

    pub fn is_value(&self) -> bool {
        self.value().is_some()
    }

    pub fn is_bototm(&self) -> bool {
        matches!(self, StackPointerOffset::Bottom)
    }

    pub fn value(&self) -> Option<isize> {
        match self {
            StackPointerOffset::Value(value) => Some(*value),
            _ => None,
        }
    }

    fn from_intermediate(intermediate: &IntermediateOffset) -> Result<StackPointerOffset, Error> {
        Ok(match intermediate {
            IntermediateOffset::Top => StackPointerOffset::Top,
            IntermediateOffset::Bottom => StackPointerOffset::Bottom,
            IntermediateOffset::Value(value) => StackPointerOffset::Value(
                value
                    .value_u64()
                    .ok_or_else(|| Error::Analysis("Stack pointer was not u64".to_string()))?
                    as isize,
            ),
        })
    }
}

fn transform(
    states: HashMap<il::ProgramLocation, IntermediateOffset>,
) -> Result<HashMap<il::ProgramLocation, StackPointerOffset>, Error> {
    states
        .into_iter()
        .try_fold(HashMap::new(), |mut t, (rpl, ispo)| {
            t.insert(rpl, StackPointerOffset::from_intermediate(&ispo)?);
            Ok(t)
        })
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum IntermediateOffset {
    Top,
    Value(il::Constant),
    Bottom,
}

impl PartialOrd for IntermediateOffset {
    fn partial_cmp(&self, other: &IntermediateOffset) -> Option<Ordering> {
        match *self {
            IntermediateOffset::Top => match *other {
                IntermediateOffset::Top => Some(Ordering::Equal),
                IntermediateOffset::Value(_) | IntermediateOffset::Bottom => {
                    Some(Ordering::Greater)
                }
            },
            IntermediateOffset::Value(ref lhs) => match *other {
                IntermediateOffset::Top => Some(Ordering::Less),
                IntermediateOffset::Value(ref rhs) => {
                    if lhs == rhs {
                        Some(Ordering::Equal)
                    } else {
                        None
                    }
                }
                IntermediateOffset::Bottom => Some(Ordering::Greater),
            },
            IntermediateOffset::Bottom => match *other {
                IntermediateOffset::Top | IntermediateOffset::Value(_) => Some(Ordering::Less),
                IntermediateOffset::Bottom => Some(Ordering::Equal),
            },
        }
    }
}

struct StackPointerOffsetAnalysis {
    stack_pointer: il::Scalar,
}

impl StackPointerOffsetAnalysis {
    // Handle an operation for stack pointer offset analysis
    fn handle_operation(
        &self,
        operation: &il::Operation,
        stack_pointer_offset: IntermediateOffset,
    ) -> Result<IntermediateOffset, Error> {
        Ok(match *operation {
            // If we're assigning, operate off current stack pointer value
            il::Operation::Assign { ref dst, ref src } => {
                if *dst == self.stack_pointer {
                    match stack_pointer_offset {
                        IntermediateOffset::Top => IntermediateOffset::Top,
                        IntermediateOffset::Value(ref constant) => {
                            let expr =
                                src.replace_scalar(&self.stack_pointer, &constant.clone().into())?;
                            if expr.all_constants() {
                                IntermediateOffset::Value(eval(&expr)?)
                            } else {
                                IntermediateOffset::Top
                            }
                        }
                        IntermediateOffset::Bottom => IntermediateOffset::Bottom,
                    }
                } else {
                    stack_pointer_offset
                }
            }
            // If we are loading stack pointer, set it to top
            il::Operation::Load { ref dst, .. } => {
                if *dst == self.stack_pointer {
                    IntermediateOffset::Top
                } else {
                    stack_pointer_offset
                }
            }
            _ => stack_pointer_offset,
        })
    }
}

/// Track the offset for the stack pointer at any point in the program
impl<'f> fixed_point::FixedPointAnalysis<'f, IntermediateOffset> for StackPointerOffsetAnalysis {
    fn trans(
        &self,
        location: il::RefProgramLocation<'f>,
        state: Option<IntermediateOffset>,
    ) -> Result<IntermediateOffset, Error> {
        // If we are the function entry, we set the value of the stack pointer
        // to 0.
        let stack_pointer_offset = match state {
            Some(state) => state,
            None => {
                // Get function entry
                let function_entry = il::RefProgramLocation::from_function(location.function())
                    .ok_or("Unable to get function entry")??;

                if location == function_entry {
                    IntermediateOffset::Value(il::const_(0, 32))
                } else {
                    IntermediateOffset::Top
                }
            }
        };

        Ok(match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                self.handle_operation(instruction.operation(), stack_pointer_offset)?
            }
            _ => stack_pointer_offset,
        })
    }

    fn join(
        &self,
        state0: IntermediateOffset,
        state1: &IntermediateOffset,
    ) -> Result<IntermediateOffset, Error> {
        Ok(match state0 {
            IntermediateOffset::Top => IntermediateOffset::Top,
            IntermediateOffset::Value(v0) => match *state1 {
                IntermediateOffset::Top => IntermediateOffset::Top,
                IntermediateOffset::Value(ref v1) => {
                    if v0 == *v1 {
                        IntermediateOffset::Value(v0)
                    } else {
                        IntermediateOffset::Top
                    }
                }
                IntermediateOffset::Bottom => IntermediateOffset::Value(v0),
            },
            IntermediateOffset::Bottom => match *state1 {
                IntermediateOffset::Top => IntermediateOffset::Top,
                IntermediateOffset::Value(ref v1) => IntermediateOffset::Value(v1.clone()),
                IntermediateOffset::Bottom => IntermediateOffset::Bottom,
            },
        })
    }
}
