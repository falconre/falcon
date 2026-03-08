//! Efficient memory representations.
//!
//! Falcon implements a layered memory model. When analyses interact with
//! memory, they interact directly with the top layer. When a memory layer
//! cannot satisfy an analysis' request, it checks the layer beneath it. I
//! believe angr implements a similar model.
//!
//! The performance of the memory model has tremendous impact on the performance
//! of memory-dependent analyses. In practice, this layered approach greatly
//! speeds up the runtime of of these analyses.
//!
//! If you choose to implement your own memory model, you should also see the
//! `TranslationMemory` trait in the `translator` module. Implementation of this
//! trait will allow the translator to lift instructions from your memory model.

pub mod backing;
pub mod paged;
mod value;

pub use self::value::Value;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// RWX permissions for memory.
    #[derive(Deserialize, Serialize)]
    pub struct MemoryPermissions: u32 {
        const NONE    = 0b000;
        const READ    = 0b001;
        const WRITE   = 0b010;
        const EXECUTE = 0b100;
        const ALL     = 0b111;
    }
}
