//! `PhiNode` represents a phi node in the SSA form

use crate::il::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PhiNode {
    incoming: BTreeMap<usize, Scalar>, // Input from another block
    entry: Option<Scalar>,             // Input from CFG entry
    out: Scalar,
}

impl PhiNode {
    pub fn new(out: Scalar) -> Self {
        Self {
            incoming: BTreeMap::new(),
            entry: None,
            out,
        }
    }

    pub fn add_incoming(&mut self, src: Scalar, block_index: usize) {
        self.incoming.insert(block_index, src);
    }

    pub fn incoming_scalar(&self, block_index: usize) -> Option<&Scalar> {
        self.incoming.get(&block_index)
    }

    pub fn incoming_scalar_mut(&mut self, block_index: usize) -> Option<&mut Scalar> {
        self.incoming.get_mut(&block_index)
    }

    pub fn set_entry_scalar(&mut self, src: Scalar) {
        self.entry = Some(src);
    }

    pub fn entry_scalar(&self) -> Option<&Scalar> {
        self.entry.as_ref()
    }

    pub fn entry_scalar_mut(&mut self) -> Option<&mut Scalar> {
        self.entry.as_mut()
    }

    pub fn out(&self) -> &Scalar {
        &self.out
    }

    pub fn out_mut(&mut self) -> &mut Scalar {
        &mut self.out
    }
}

impl fmt::Display for PhiNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = phi", self.out)?;
        for (block_index, src) in &self.incoming {
            write!(f, " [{}, 0x{:X}]", src, block_index)?
        }
        if let Some(src) = &self.entry {
            write!(f, " [{}, entry]", src)?
        }
        Ok(())
    }
}
