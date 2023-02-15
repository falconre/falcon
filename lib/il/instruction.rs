//! An `Instruction` holds an `Operation`.

use crate::il::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An `Instruction` represents location, and non-semantical information about
/// an `Operation`.
///
/// An `instruction` gives location to an `Operation`.
///
/// Methods are provided to create individual instructions, as all uses cases
/// cannot be seen beforehand. However, it is generally poor-form to create
/// an `Instruction` manually. You should use the methods on `Block` which
/// correspond to the `Operation` you wish to create, and the `Instruction`
/// will be created automatically.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Default)]
pub struct Instruction {
    operation: Operation,
    index: usize,
    comment: Option<String>,
    address: Option<u64>,
}

impl Instruction {
    /// Create a new instruction with the given index and operation.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the methods
    /// on `il::Block` which correspond to the operation you wish to append to
    /// that block.
    pub fn new(index: usize, operation: Operation) -> Instruction {
        Instruction {
            operation,
            index,
            comment: None,
            address: None,
        }
    }

    /// Create a new `Assign` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `assign` method on `il::Block` instead.
    pub fn assign(index: usize, dst: Scalar, src: Expression) -> Instruction {
        Instruction::new(index, Operation::assign(dst, src))
    }

    /// Create a new `Store` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `store` method on `il::Block` instead.
    pub fn store(instruction_index: usize, index: Expression, src: Expression) -> Instruction {
        Instruction::new(instruction_index, Operation::store(index, src))
    }

    /// Create a new `Load` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `load` method on `il::Block` instead.
    pub fn load(instruction_index: usize, dst: Scalar, index: Expression) -> Instruction {
        Instruction::new(instruction_index, Operation::load(dst, index))
    }

    /// Create a new `Brc` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `brc` method on `il::Block` instead.
    pub fn branch(index: usize, target: Expression) -> Instruction {
        Instruction::new(index, Operation::branch(target))
    }

    /// Create a new `Intrinsic` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `intrinsic` method on `il::Block` instead.
    pub fn intrinsic(index: usize, intrinsic: Intrinsic) -> Instruction {
        Instruction::new(index, Operation::Intrinsic { intrinsic })
    }

    /// Create a new `Nop` instruction.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `nop` method on `il::Block` instead.
    pub fn nop(index: usize) -> Instruction {
        Instruction::new(index, Operation::nop())
    }

    /// Create a new `Nop` instruction as placeholder for the given `Operation`.
    ///
    /// # Warning
    /// You almost never want to call this function. You should use the
    /// `nop_placeholder` method on `il::Block` instead.
    pub fn placeholder(index: usize, operation: Operation) -> Instruction {
        Instruction::new(index, Operation::placeholder(operation))
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Assign`
    pub fn is_assign(&self) -> bool {
        matches!(self.operation, Operation::Assign { .. })
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Store`
    pub fn is_store(&self) -> bool {
        matches!(self.operation, Operation::Store { .. })
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Load`
    pub fn is_load(&self) -> bool {
        matches!(self.operation, Operation::Load { .. })
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Brc`
    pub fn is_branch(&self) -> bool {
        matches!(self.operation, Operation::Branch { .. })
    }

    /// Get the `Operation` for this `Instruction`
    pub fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Get a mutable reference to the `Operation` for this `Instruction`
    pub fn operation_mut(&mut self) -> &mut Operation {
        &mut self.operation
    }

    /// Get the index for this `Instruction`.
    ///
    /// An `Instruction` index is assigned by its parent `Block` and uniquely identifies the
    /// `Instruction` within the `Block`. `Instruction` indices need not be continuous, nor
    /// in order.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get the optional comment for this `Instruction`
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Set the optional comment for this `Instruction`
    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    /// Get the optional address for this `Instruction`
    ///
    /// An `Instruction` will typically have an address if one was given by a translator. It is
    /// not uncommon for there to be a mixture of `Instruction`s with and without comments. For
    /// example, applying SSA to a `Function` will cause `Phi` instructions to be inserted, and
    /// these instructions will not have addresses.
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// Set the optional address for this `Instruction`
    pub fn set_address(&mut self, address: Option<u64>) {
        self.address = address;
    }

    /// Clone this instruction with a new index.
    pub(crate) fn clone_new_index(&self, index: usize) -> Instruction {
        Instruction {
            operation: self.operation.clone(),
            index,
            comment: self.comment.clone(),
            address: self.address,
        }
    }

    /// Get the `Scalar` which will be written by this `Instruction`.
    pub fn scalars_written(&self) -> Option<Vec<&Scalar>> {
        self.operation.scalars_written()
    }

    /// Get a mutable reference to the `Scalar` which will be written by this
    /// `Instruction`.
    pub fn scalar_written_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        self.operation.scalars_written_mut()
    }

    /// Get a Vec of each `Scalar` read by this `Instruction`.
    pub fn scalars_read(&self) -> Option<Vec<&Scalar>> {
        self.operation.scalars_read()
    }

    /// Get a Vec of mutable references for each `Scalar` read by this
    /// `Instruction`.
    pub fn scalars_read_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        self.operation.scalars_read_mut()
    }

    /// Get all the scalars used in this instruction
    pub fn scalars(&self) -> Option<Vec<&Scalar>> {
        let mut scalars = self
            .scalars_written()?
            .into_iter()
            .chain(self.scalars_read()?.into_iter())
            .collect::<Vec<&Scalar>>();

        scalars.sort();
        scalars.dedup();
        Some(scalars)
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = match self.address {
            Some(address) => format!("{:X} {:02X} {}", address, self.index, self.operation),
            None => format!("{:02X} {}", self.index, self.operation),
        };
        if let Some(ref comment) = self.comment {
            write!(f, "{} // {}", prefix, comment)
        } else {
            write!(f, "{}", prefix)
        }
    }
}
