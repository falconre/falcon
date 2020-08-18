//! An `Operation` captures the semantics of the IL.

use crate::il::*;
use std::fmt;

/// An IL Operation updates some state.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Operation {
    /// Assign the value given in expression to the variable indicated.
    Assign { dst: Scalar, src: Expression },
    /// Store the value in src at the address given in index.
    Store { index: Expression, src: Expression },
    /// Load the value in memory at index and place the result in the variable dst.
    Load { dst: Scalar, index: Expression },
    /// Branch to the value given by target.
    Branch { target: Expression },
    /// Holds an Intrinsic for unmodellable instructions
    Intrinsic { intrinsic: Intrinsic },
    /// An operation that does nothing, and allows for a placeholder `Instruction`
    Nop { placeholder: Option<Box<Operation>> },
    /// Performs the nested operation only if the condition is non-zero.
    Conditional {
        condition: Expression,
        operation: Box<Operation>,
    },
}

impl Default for Operation {
    fn default() -> Self {
        Self::Nop { placeholder: None }
    }
}

impl Operation {
    /// Create a new `Operation::Assign`.
    pub fn assign(dst: Scalar, src: Expression) -> Operation {
        Operation::Assign { dst, src }
    }

    /// Create a new `Operation::Store`.
    pub fn store(index: Expression, src: Expression) -> Operation {
        Operation::Store { index, src }
    }

    /// Create a new `Operation::Load`.
    pub fn load(dst: Scalar, index: Expression) -> Operation {
        Operation::Load { dst, index }
    }

    /// Create a new `Operation::Brc`.
    pub fn branch(target: Expression) -> Operation {
        Operation::Branch { target }
    }

    /// Create a new `Operation::Branch` wrapped in `Operation::Conditional`.
    pub fn conditional_branch(condition: Expression, target: Expression) -> Operation {
        Self::conditional(condition, Self::branch(target))
    }

    /// Create a new `Operation::Intrinsic`.
    pub fn intrinsic(intrinsic: Intrinsic) -> Operation {
        Operation::Intrinsic { intrinsic }
    }

    /// Create a new `Operation::Nop`
    pub fn nop() -> Operation {
        Operation::Nop { placeholder: None }
    }

    /// Create a new `Operation::Nop` as placeholder for the given `Operation`
    pub fn placeholder(operation: Operation) -> Operation {
        Operation::Nop {
            placeholder: Some(Box::new(operation)),
        }
    }

    /// Create a new `Operation::Conditional`.
    pub fn conditional(condition: Expression, operation: Operation) -> Operation {
        Operation::Conditional {
            condition,
            operation: Box::new(operation),
        }
    }

    pub fn is_assign(&self) -> bool {
        match self {
            Operation::Assign { .. } => true,
            _ => false,
        }
    }

    pub fn is_store(&self) -> bool {
        match self {
            Operation::Store { .. } => true,
            _ => false,
        }
    }

    pub fn is_load(&self) -> bool {
        match self {
            Operation::Load { .. } => true,
            _ => false,
        }
    }

    pub fn is_branch(&self) -> bool {
        match self {
            Operation::Branch { .. } => true,
            _ => false,
        }
    }

    pub fn is_intrinsic(&self) -> bool {
        match self {
            Operation::Intrinsic { .. } => true,
            _ => false,
        }
    }

    pub fn is_nop(&self) -> bool {
        match self {
            Operation::Nop { .. } => true,
            _ => false,
        }
    }

    pub fn is_conditional(&self) -> bool {
        match self {
            Operation::Conditional { .. } => true,
            _ => false,
        }
    }

    /// Get each `Scalar` read by this `Operation`.
    pub fn scalars_read(&self) -> Option<Vec<&Scalar>> {
        match *self {
            Operation::Assign { ref src, .. } => Some(src.scalars()),
            Operation::Store { ref index, ref src } => Some(
                index
                    .scalars()
                    .into_iter()
                    .chain(src.scalars().into_iter())
                    .collect(),
            ),
            Operation::Load { ref index, .. } => Some(index.scalars()),
            Operation::Branch { ref target } => Some(target.scalars()),
            Operation::Intrinsic { ref intrinsic } => intrinsic.scalars_read(),
            Operation::Nop { .. } => Some(Vec::new()),
            Operation::Conditional {
                ref condition,
                ref operation,
            } => {
                if let Some(scalars) = operation.scalars_read() {
                    Some(
                        scalars
                            .into_iter()
                            .chain(condition.scalars().into_iter())
                            .collect(),
                    )
                } else {
                    None
                }
            }
        }
    }

    /// Get a mutable reference to each `Scalar` read by this `Operation`.
    pub fn scalars_read_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        match *self {
            Operation::Assign { ref mut src, .. } => Some(src.scalars_mut()),
            Operation::Store {
                ref mut index,
                ref mut src,
            } => Some(
                index
                    .scalars_mut()
                    .into_iter()
                    .chain(src.scalars_mut().into_iter())
                    .collect(),
            ),
            Operation::Load { ref mut index, .. } => Some(index.scalars_mut()),
            Operation::Branch { ref mut target } => Some(target.scalars_mut()),
            Operation::Intrinsic { ref mut intrinsic } => intrinsic.scalars_read_mut(),
            Operation::Nop { .. } => Some(Vec::new()),
            Operation::Conditional {
                ref mut condition,
                ref mut operation,
            } => {
                if let Some(scalars) = operation.scalars_read_mut() {
                    Some(
                        scalars
                            .into_iter()
                            .chain(condition.scalars_mut().into_iter())
                            .collect(),
                    )
                } else {
                    None
                }
            }
        }
    }

    /// Get a Vec of the `Scalar`s written by this `Operation`
    pub fn scalars_written(&self) -> Option<Vec<&Scalar>> {
        match *self {
            Operation::Assign { ref dst, .. } | Operation::Load { ref dst, .. } => Some(vec![dst]),
            Operation::Store { .. } | Operation::Branch { .. } => Some(Vec::new()),
            Operation::Intrinsic { ref intrinsic } => intrinsic.scalars_written(),
            Operation::Nop { .. } => Some(Vec::new()),
            Operation::Conditional { ref operation, .. } => operation.scalars_written(),
        }
    }

    /// Get a Vec of mutable referencer to the `Scalar`s written by this
    /// `Operation`
    pub fn scalars_written_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        match *self {
            Operation::Assign { ref mut dst, .. } | Operation::Load { ref mut dst, .. } => {
                Some(vec![dst])
            }
            Operation::Store { .. } | Operation::Branch { .. } => Some(Vec::new()),
            Operation::Intrinsic { ref mut intrinsic } => intrinsic.scalars_written_mut(),
            Operation::Nop { .. } => Some(Vec::new()),
            Operation::Conditional {
                ref mut operation, ..
            } => operation.scalars_written_mut(),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operation::Assign { ref dst, ref src } => write!(f, "{} = {}", dst, src),
            Operation::Store { ref index, ref src } => write!(f, "[{}] = {}", index, src),
            Operation::Load { ref dst, ref index } => write!(f, "{} = [{}]", dst, index),
            Operation::Branch { ref target } => write!(f, "branch {}", target),
            Operation::Intrinsic { ref intrinsic } => write!(f, "intrinsic {}", intrinsic),
            Operation::Nop { .. } => write!(f, "nop"),
            Operation::Conditional {
                ref condition,
                ref operation,
            } => write!(f, "{} if {}", operation, condition),
        }
    }
}
