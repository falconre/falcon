//! Various methods of executing over Falcon IL

use error::*;
use il;

pub mod engine;
pub mod eval;
pub mod driver;
pub mod memory;
pub mod successor;

pub use self::engine::*;
pub use self::eval::eval;
pub use self::driver::*;
pub use self::memory::*;
pub use self::successor::*;