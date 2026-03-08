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

use crate::il::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Edge between IL blocks
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Default)]
pub struct Edge {
    head: usize,
    tail: usize,
    condition: Option<Expression>,
    comment: Option<String>,
}

impl Edge {
    pub(crate) fn new(head: usize, tail: usize, condition: Option<Expression>) -> Edge {
        Edge {
            head,
            tail,
            condition,
            comment: None,
        }
    }

    /// Retrieve the condition for this `Edge`.
    pub fn condition(&self) -> Option<&Expression> {
        self.condition.as_ref()
    }

    /// Retrieve a mutable reference to the condition for this `Edge`
    pub fn condition_mut(&mut self) -> Option<&mut Expression> {
        self.condition.as_mut()
    }

    /// Retrieve the index of the head `Vertex` for this `Edge`.
    pub fn head(&self) -> usize {
        self.head
    }

    /// Retrieve the index of the tail `Vertex` for this `Edge`.
    pub fn tail(&self) -> usize {
        self.tail
    }

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
            writeln!(f, "// {}", comment)?
        }
        if let Some(ref condition) = self.condition {
            write!(
                f,
                "(0x{:X}->0x{:X}) ? ({})",
                self.head, self.tail, condition
            )?
        } else {
            write!(f, "(0x{:X}->0x{:X})", self.head, self.tail)?
        }
        Ok(())
    }
}

impl graph::Edge for Edge {
    fn head(&self) -> usize {
        self.head
    }
    fn tail(&self) -> usize {
        self.tail
    }
    fn dot_label(&self) -> String {
        match self.condition {
            Some(ref condition) => format!("{}", condition),
            None => "".to_string(),
        }
    }
}
