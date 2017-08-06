//! An `Instruction` holds an `Operation`.
//!
//! An `instruction` gives location to an `Operation`.
//!
//! An `Instruction` is created automatically when calling various `Operation`-type functions
//! over a `Block`, such as `Block::assign`.

use il::*;
use std::fmt;

/// An `Instruction` represents location, and non-semantical information about
/// an `Operation`.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Instruction {
    operation: Operation,
    index: u64,
    comment: Option<String>,
    address: Option<u64>
}


impl Instruction {
    pub(crate) fn new(index: u64, operation: Operation) -> Instruction {
        Instruction {
            operation: operation,
            index: index,
            comment: None,
            address: None
        }
    }


    pub(crate) fn assign(index: u64, dst: Scalar, src: Expression) -> Instruction {
        Instruction::new(index, Operation::assign(dst, src))
    }


    pub(crate) fn store(
        instruction_index: u64,
        dst: Array,
        dst_index: Expression,
        src: Expression
    ) -> Instruction {

        Instruction::new(instruction_index, Operation::store(dst, dst_index, src))
    }


    pub(crate) fn load(
        instruction_index: u64,
        dst: Scalar,
        src_index: Expression,
        src: Array
    ) -> Instruction {

        Instruction::new(instruction_index, Operation::load(dst, src_index, src))
    }


    pub(crate) fn brc(index: u64, target: Expression, condition: Expression)
    -> Instruction {

        Instruction::new(index, Operation::brc(target, condition))
    }


    pub(crate) fn phi(index: u64, dst: MultiVar, src: Vec<MultiVar>)
    -> Instruction {

        Instruction::new(index, Operation::phi(dst, src))
    }


    pub(crate) fn raise(index: u64, expr: Expression) -> Instruction {
        Instruction::new(index, Operation::Raise { expr: expr })
    }


    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Assign`
    pub fn is_assign(&self) -> bool {
        if let Operation::Assign{..} = self.operation {
            true
        }
        else {
            false
        }
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Store`
    pub fn is_store(&self) -> bool {
        if let Operation::Store{..} = self.operation {
            true
        }
        else {
            false
        }
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Load`
    pub fn is_load(&self) -> bool {
        if let Operation::Load{..} = self.operation {
            true
        }
        else {
            false
        }
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Brc`
    pub fn is_brc(&self) -> bool {
        if let Operation::Brc{..} = self.operation {
            true
        }
        else {
            false
        }
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Phi`
    pub fn is_phi(&self) -> bool {
        if let Operation::Phi{..} = self.operation {
            true
        }
        else {
            false
        }
    }

    /// Returns `true` if the `Operation` for this `Instruction` is `Operation::Raise`
    pub fn is_raise(&self) -> bool {
        if let Operation::Raise{..} = self.operation {
            true
        }
        else {
            false
        }
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
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Get the optional comment for this `Instruction`
    pub fn comment(&self) -> &Option<String> {
        &self.comment
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
        self.address.clone()
    }

    /// Set the optional address for this `Instruction`
    pub fn set_address(&mut self, address: Option<u64>) {
        self.address = address;
    }

    /// Clone this instruction with a new index.
    pub(crate) fn clone_new_index(&self, index: u64) -> Instruction {
        Instruction {
            operation: self.operation.clone(),
            index: index,
            comment: self.comment.clone(),
            address: self.address
        }
    }

    /// Get the `Variable` which will be written by this `Instruction`.
    ///
    /// This is a convenience function around `Operation::variable_written`.
    pub fn variable_written(&self) -> Option<&Variable> {
        self.operation.variable_written()
    }

    /// Get a mutable reference to the `Variable` which will be written by this `Instruction`.
    ///
    /// This is a convenience function around `Operation::variable_written_mut`.
    pub fn variable_written_mut(&mut self) -> Option<&mut Variable> {
        self.operation.variable_written_mut()
    }

    /// Get a Vec of each `Variable` read by this `Instruction`.
    ///
    /// This is a convenience function around `Operation::variables_read`.
    pub fn variables_read(&self) -> Vec<&Variable> {
        self.operation.variables_read()
    }

    /// Get a Vec of mutable references for each `Variable` read by this `Instruction`.
    ///
    /// This is a convenience function around `Operation::variables_read_mut`.
    pub fn variables_read_mut(&mut self) -> Vec<&mut Variable> {
        self.operation.variables_read_mut()
    }
}



impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = match self.address {
            Some(address) => 
                format!("{:X} {:02X} {}", address, self.index, self.operation),
            None =>
                format!("{:02X} {}", self.index, self.operation)
        };
        if let Some(ref comment) = self.comment {
            write!(f, "{} // {}", prefix, comment)
        }
        else {
            write!(f, "{}", prefix)
        }
    }
}