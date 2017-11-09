//! Implementations and traits for static analysis over Falcon IL.

mod def_use;
pub mod ai;
pub mod fixed_point;
mod reaching_definitions;
mod use_def;

pub use self::def_use::def_use;
pub use self::reaching_definitions::reaching_definitions;
pub use self::use_def::use_def;