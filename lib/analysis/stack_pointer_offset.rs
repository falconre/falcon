//! Determine offset of stack pointer from function entry.
//!
//! Determine the value of the stack pointer at every location in the function
//! as an offset from the stack pointer's value at function entry.
//!
//! This analysis works off a very simple lattice, Top/Value/Bottom, where Value
//! is a single il::Constant.

use analysis::fixed_point;
use error::*;
use executor::eval;
use il;
use std::collections::HashMap;
use std::cmp::{Ordering, PartialOrd};
use types::Architecture;

/// Determine offset of stack pointer from program entry at each place in the
/// program.
pub fn stack_pointer_offsets<'f>(
    function: &'f il::Function,
    architecture: &Architecture
) -> Result<HashMap<il::RefProgramLocation<'f>, StackPointerOffset>> {

    let spoa = StackPointerOffsetAnalysis {
        stack_pointer: architecture.stack_pointer()
    };
    fixed_point::fixed_point_forward(spoa, function)
}


/// Returns true if there is a valid StackPointerOffset value for every location
/// in the function.
pub fn perfect<'f>(
    stack_pointer_offsets: &HashMap<il::RefProgramLocation<'f>, StackPointerOffset>
) -> bool {
    stack_pointer_offsets.iter().any(|(_, spo)| spo.is_value())
}


/// A constant value representing the value of the stack pointer at some point
/// in the function.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum StackPointerOffset {
    Top,
    Value(il::Constant),
    Bottom
}


impl StackPointerOffset {
    pub fn is_top(&self) -> bool {
        match *self {
            StackPointerOffset::Top => true,
            _ => false
        }
    }

    pub fn is_value(&self) -> bool {
        match *self {
            StackPointerOffset::Value(_) => true,
            _ => false
        }
    }

    pub fn value(&self) -> Option<&il::Constant> {
        if let StackPointerOffset::Value(ref constant) = *self {
            Some(constant)
        }
        else {
            None
        }
    }

    pub fn is_bottom(&self) -> bool {
        match *self {
            StackPointerOffset::Bottom => true,
            _ => false
        }
    }
}


impl PartialOrd for StackPointerOffset {
    fn partial_cmp(&self, other: &StackPointerOffset) -> Option<Ordering> {
        match *self {
            StackPointerOffset::Top => match *other {
                StackPointerOffset::Top => Some(Ordering::Equal),
                StackPointerOffset::Value(_) |
                StackPointerOffset::Bottom => Some(Ordering::Greater)
            },
            StackPointerOffset::Value(ref lhs) => match *other {
                StackPointerOffset::Top => Some(Ordering::Less),
                StackPointerOffset::Value(ref rhs) =>
                    if lhs == rhs { Some(Ordering::Equal) }
                    else { None},
                StackPointerOffset::Bottom => Some(Ordering::Greater)
            },
            StackPointerOffset::Bottom => match *other {
                StackPointerOffset::Top |
                StackPointerOffset::Value(_) => Some(Ordering::Less),
                StackPointerOffset::Bottom => Some(Ordering::Equal)
            }
        }
    }
}


struct StackPointerOffsetAnalysis {
    stack_pointer: il::Scalar
}


impl StackPointerOffsetAnalysis {
    /// Handle an operation for stack pointer offset analysis
    fn handle_operation(
        &self,
        operation: &il::Operation,
        stack_pointer_offset: StackPointerOffset
    ) -> Result<StackPointerOffset> {
        Ok(match *operation {
            // If we're assigning, operate off current stack pointer value
            il::Operation::Assign { ref dst, ref src } => {
                if *dst == self.stack_pointer {
                    match stack_pointer_offset {
                        StackPointerOffset::Top => StackPointerOffset::Top,
                        StackPointerOffset::Value(ref constant) => {
                            let expr = src.replace_scalar(&self.stack_pointer,
                                                          &constant.clone().into())?;
                            if expr.all_constants() {
                                StackPointerOffset::Value(eval(&expr)?.into())
                            }
                            else {
                                StackPointerOffset::Top
                            }
                        },
                        StackPointerOffset::Bottom => StackPointerOffset::Bottom
                    }
                }
                else {
                    stack_pointer_offset
                }
            },
            // If we are loading stack pointer, set it to top
            il::Operation::Load { ref dst, .. } => {
                if *dst == self.stack_pointer {
                    StackPointerOffset::Top
                }
                else {
                    stack_pointer_offset
                }
            },
            _ => stack_pointer_offset
        })
    }
}


/// Track the offset for the stack pointer at any point in the program
impl<'f> fixed_point::FixedPointAnalysis<'f, StackPointerOffset> for StackPointerOffsetAnalysis {
    fn trans(
        &self,
        location: il::RefProgramLocation<'f>,
        state: Option<StackPointerOffset>
    ) -> Result<StackPointerOffset> {

        // If we are the function entry, we set the value of the stack pointer
        // to 0.
        let stack_pointer_offset = match state {
            Some(state) => state,
            None => {
                // Get function entry
                let function_entry =
                    il::RefProgramLocation::from_function(location.function())
                        .ok_or("Unable to get function entry")?;

                if location == function_entry {
                    StackPointerOffset::Value(il::const_(0, 32))
                }
                else {
                    StackPointerOffset::Top
                }
            }
        };

        Ok(match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, ref instruction) =>
                self.handle_operation(instruction.operation(),
                                      stack_pointer_offset)?,
            _ => stack_pointer_offset
        })
    }

    fn join(&self, state0: StackPointerOffset, state1: &StackPointerOffset)
        -> Result<StackPointerOffset> {

        Ok(match state0 {
            StackPointerOffset::Top => StackPointerOffset::Top,
            StackPointerOffset::Value(v0) => {
                match *state1 {
                    StackPointerOffset::Top => StackPointerOffset::Top,
                    StackPointerOffset::Value(ref v1) => {
                        if v0 == *v1 {
                            StackPointerOffset::Value(v0)
                        }
                        else {
                            StackPointerOffset::Top
                        }
                    },
                    StackPointerOffset::Bottom => StackPointerOffset::Value(v0)
                }
            },
            StackPointerOffset::Bottom => {
                match *state1 {
                    StackPointerOffset::Top => StackPointerOffset::Top,
                    StackPointerOffset::Value(ref v1) =>
                        StackPointerOffset::Value(v1.clone()),
                    StackPointerOffset::Bottom => StackPointerOffset::Bottom
                }
            }
        })
    }
}