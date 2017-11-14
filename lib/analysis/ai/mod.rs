//! Abstract Interpretation Analyses
//!
//! This module implements the core abstractions and components for abstract
//! interpretation over Falcon IL.
//!
//! We make heavy use of generics to allow for plug-and-play analyses.
//!
//! * The `domain` module implements the traits and abstractions for an abstract
//! domain.
//! * The `kset` module is an example implementation of an abstract domain.
//! * The `interpreter` module provides an interpreter over the fixed point
//! engine which operates over abstract domains.
//! * The `memory` module is wraps `falcon::memory::paged::Memory` and provides
//! a memory model over abstract domains which supports the join operation.

pub mod domain;
pub mod kset;
pub mod interpreter;
pub mod memory;

#[cfg(test)] mod test_lattice;