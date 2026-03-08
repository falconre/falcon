//! Concrete execution over Falcon IL.

use crate::il;
use crate::memory;
use crate::Error;

mod driver;
mod eval;
mod state;
mod successor;

pub use self::driver::*;
pub use self::eval::eval;
pub use self::state::*;
pub use self::successor::*;

/// A `falcon::memory::paged::Memory` over `il::Constant`.
pub type Memory = memory::paged::Memory<il::Constant>;

use crate::memory::MemoryPermissions;
use crate::translator;

impl translator::TranslationMemory for Memory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        self.load(address, 8)
            .unwrap()
            .map(|constant| constant.value_u64().unwrap() as u8)
    }

    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.permissions(address)
    }
}
