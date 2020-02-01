//! `PhiNode` represents a phi node in the SSA form

use crate::il::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PhiNode {
    incoming: BTreeMap<usize, Scalar>,
    out: Scalar,
}

impl PhiNode {
    pub fn new(out: Scalar) -> Self {
        Self {
            incoming: BTreeMap::new(),
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
        Ok(())
    }
}
