//! An `Edge` is a direct edge between `Block` in `ControlFlowGraph`
//!
//! A Falcon IL `Edge` has an optional condition. When the condition is present, the `Edge` is,
//! "Guarded," by the `Expression` in the condition. `Edge` conditions are `Expressions` that must
//! evaluate to a 1-bit `Constant`. When the condition evaluates to 1, the `Edge` may be taken.
//! Otherwise the `Edge` is not taken. When the condition is not present, the `Edge` is
//! unconditional and will always be taken.
//!
//! To create a new edge, call `ControlFlowGraph::unconditional_edge` or
//! `ControlFlowGraph::conditional_edge`.

use il::*;
use std::fmt;

/// Edge between IL blocks
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Edge {
    head: u64,
    tail: u64,
    condition: Option<Expression>,
    comment: Option<String>
}


impl Edge {
    pub(crate) fn new(head: u64, tail: u64, condition: Option<Expression>) -> Edge {
        Edge {
            head: head,
            tail: tail,
            condition: condition,
            comment: None
        }
    }

    /// Retrieve the condition for this `Edge`.
    pub fn condition(&self) -> &Option<Expression> {
        &self.condition
    }

    /// Retrieve a mutable reference to the condition for this `Edge`
    pub fn condition_mut(&mut self) -> &mut Option<Expression> {
        &mut self.condition
    }

    /// Retrieve the index of the head `Vertex` for this `Edge`.
    pub fn head(&self) -> u64 { self.head }

    /// Retrieve the index of the tail `Vertex` for this `Edge`.
    pub fn tail(&self) -> u64 { self.tail }

    /// Set the comment for this `Edge`.
    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    /// Get the comment for this `Edge`.
    pub fn comment(&self) -> &Option<String> {
        &self.comment
    }
}


impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref comment) = self.comment {
            write!(f, "// {}\n", comment)?
        }
        if let Some(ref condition) = self.condition {
            write!(
                f,
                "(0x{:X}->0x{:X}) ? ({})",
                self.head,
                self.tail,
                condition
            )?
        }
        else {
            write!(f, "(0x{:X}->0x{:X})", self.head, self.tail)?
        }
        Ok(())
    }
}


impl graph::Edge for Edge {
    fn head(&self) -> u64 { self.head }
    fn tail(&self) -> u64 { self.tail }
    fn dot_label(&self) -> String { format!("{}", self) }
}