//! Implementations and traits for static analysis over Falcon IL.

pub mod calling_convention;
pub mod constants;
mod dead_code_elimination;
mod def_use;
pub mod fixed_point;
mod location_set;
mod reaching_definitions;
pub mod stack_pointer_offsets;
mod use_def;

pub use self::dead_code_elimination::dead_code_elimination;
pub use self::def_use::def_use;
pub use self::location_set::LocationSet;
pub use self::reaching_definitions::reaching_definitions;
pub use self::use_def::use_def;
