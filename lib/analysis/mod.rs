//! Implementations and traits for static analysis over Falcon IL.

pub mod ai;
pub mod calling_convention;
mod def_use;
pub mod fixed_point;
mod location_set;
mod reaching_definitions;
pub mod stack_pointer_offset;
mod use_def;

pub use self::def_use::def_use;
pub use self::location_set::LocationSet;
pub use self::reaching_definitions::reaching_definitions;
pub use self::use_def::use_def;