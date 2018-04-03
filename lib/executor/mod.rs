//! Concrete execution over Falcon IL.

use error::*;
use il;
use memory;

mod state;
mod eval;
mod driver;
mod successor;

pub use self::state::*;
pub use self::eval::eval;
pub use self::driver::*;
pub use self::successor::*;

/// A `falcon::memory::paged::Memory` over `il::Constant`.
pub type Memory = memory::paged::Memory<il::Constant>;

use memory::MemoryPermissions;
use translator;

impl translator::TranslationMemory for Memory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        match self.load(address, 8).unwrap() {
            Some(constant) => Some(constant.value_u64().unwrap() as u8),
            None => None
        }
    }


    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.permissions(address)
    }
}