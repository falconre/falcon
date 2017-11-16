//! A memory model for abstract interpretation
//!
//! This memory model wraps falcon::memory::paged::Memory and adds a `join`
//! method which operates over abstract values.

use analysis::ai::domain;
use error::*;
use memory::paged;
use memory;
use serde::Serialize;
use types::Endian;


/// A memory model for abstract interpretation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Memory<'m, V: memory::value::Value + domain::Value>(paged::Memory<'m, V>);

impl<'m, V> Memory<'m, V> where V: memory::value::Value + domain::Value {
    /// Create a new memory model for abstract interpretation.
    pub fn new(endian: Endian) -> Memory<'m, V> {
        Memory(paged::Memory::new(endian))
    }


    /// Create a new memory model for abstract interpretation with the given
    /// memory backing.
    pub fn new_with_backing(endian: Endian, backing: &'m memory::backing::Memory)
        -> Memory<'m, V> {
            Memory(paged::Memory::new_with_backing(endian, backing))
        }


    /// Store an abstract value at the given address.
    pub fn store(&mut self, address: u64, value: V) -> Result<()> {
        self.0.store(address, value)
    }


    /// Load an abstract value from the given address.
    pub fn load(&self, address: u64, bits: usize) -> Result<V> {
        Ok(match self.0.load(address, bits)? {
            Some(v) => v,
            None => V::empty(bits)
        })
    }


    /// Returns true if all memory locations at address are None
    fn empty_memory(&self, address: u64, length: usize) -> Result<bool> {
        for i in 0..length {
            if self.0.load(address + i as u64, 8)?.is_some() {
                return Ok(false);
            }
        }
        Ok(true)
    }


    /// Join this abstract memory model with another.
    pub fn join(mut self, other: &Memory<V>) -> Result<Memory<'m, V>> {
        // for every page in the other memory
        for other_page in &other.0.pages {
            let address = *other_page.0;
            let page = other_page.1;
            for i in 0..paged::PAGE_SIZE {
                if let Some(other_value) = page.cells[i].as_ref()
                                                        .and_then(|cell| cell.value()) {
                    // If every value in this memory is None, we can just write the other
                    // value
                    if self.empty_memory(address + i as u64, other_value.bits() / 8)? {
                        self.store(address + i as u64, other_value.clone())?;
                        continue;
                    }
                    // Do we have a value here that matches perfectly?
                    if let Some(this_value) = self.0.load(address + i as u64, other_value.bits())? {
                        self.store(address + i as u64, this_value.join(other_value)?)?;
                        continue;
                    }
                    // Otherwise join by byte
                    let bytes = other_value.bits() / 8;
                    for offset in 0..bytes {
                        let shift = match self.0.endian() {
                            Endian::Big => (bytes - offset - 1) * 8,
                            Endian::Little => offset * 8
                        };
                        let other_byte = other_value.shr(shift)?;
                        let other_byte = if other_byte.bits() == 8 {
                            other_byte
                        }
                        else {
                            other_byte.trun(8)?
                        };
                        let byte_address = address + (i + offset) as u64;
                        let this_byte = self.load(byte_address, 8)?;
                        self.store(byte_address, this_byte.join(&other_byte)?)?;
                    }
                }
            }
        }
        Ok(self)
    }
}


impl<'m, V: memory::value::Value + domain::Value + Serialize> domain::Memory<V> for Memory<'m, V> {
    fn join(self, other: &Memory<V>) -> Result<Memory<'m, V>> {
        self.join(other)
    }
}


#[cfg(test)]
mod memory_tests {
    use analysis::ai::kset::KSet;
    use analysis::ai::memory::Memory;
    use il;
    use types::Endian;

    #[test]
    fn ai_memory_big_endian() {
        let mut memory: Memory<KSet> = Memory::new(Endian::Big);

        let value = KSet::constant(il::const_(0xAABBCCDD, 32));

        memory.store(0x100, value.clone()).unwrap();

        let load_value = memory.load(0x100, 32).unwrap();

        assert_eq!(load_value, value);

        let load_0 = memory.load(0x100, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xAA, 8)));

        let load_0 = memory.load(0x101, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xBB, 8)));

        let load_0 = memory.load(0x102, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xCC, 8)));

        let load_0 = memory.load(0x103, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xDD, 8)));

        memory.store(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

        let load_0 = memory.load(0x100, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xAA, 8)));

        let load_0 = memory.load(0x101, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xBB, 8)));

        let load_0 = memory.load(0x102, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xFF, 8)));

        let load_0 = memory.load(0x103, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xDD, 8)));

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xaabbffdd, 32)));

        let other_memory: Memory<KSet> = Memory::new(Endian::Big);
        let memory = memory.join(&other_memory).unwrap();
        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xaabbffdd, 32)));

        let other_memory: Memory<KSet> = Memory::new(Endian::Big);
        let memory = other_memory.join(&memory).unwrap();
        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xaabbffdd, 32)));

        let mut memory: Memory<KSet> = Memory::new(Endian::Big);
        memory.store(0x100, KSet::constant(il::const_(0xAABBCCDD, 32))).unwrap();
        let mut other_memory: Memory<KSet> = Memory::new(Endian::Big);
        other_memory.store(0x100, KSet::constant(il::const_(0x11223344, 32))).unwrap();
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x100, 8).unwrap(), 
            KSet::constant(il::const_(0xaa, 8))
                .join(&KSet::constant(il::const_(0x11, 8)))
                .unwrap());

        let mut memory: Memory<KSet> = Memory::new(Endian::Big);
        memory.store(0x100, KSet::constant(il::const_(0xAABBCCDD, 32))).unwrap();
        let mut other_memory: Memory<KSet> = Memory::new(Endian::Big);
        other_memory.store(0x100, KSet::constant(il::const_(0x1122, 16))).unwrap();
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x102, 16).unwrap(),  KSet::constant(il::const_(0xCCDD, 16)));
        assert_eq!(memory.load(0x100, 8).unwrap(), 
            KSet::constant(il::const_(0xaa, 8))
                .join(&KSet::constant(il::const_(0x11, 8)))
                .unwrap());
        assert_eq!(memory.load(0x100, 8).unwrap(), 
            KSet::constant(il::const_(0xbb, 8))
                .join(&KSet::constant(il::const_(0x22, 8)))
                .unwrap());

    }

    #[test]
    fn ai_memory_little_endian() {
        let mut memory: Memory<KSet> = Memory::new(Endian::Little);

        let value = KSet::constant(il::const_(0xAABBCCDD, 32));

        memory.store(0x100, value.clone()).unwrap();

        let load_value = memory.load(0x100, 32).unwrap();

        assert_eq!(load_value, value);

        let load_0 = memory.load(0x100, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xDD, 8)));

        let load_0 = memory.load(0x101, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xCC, 8)));

        let load_0 = memory.load(0x102, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xBB, 8)));

        let load_0 = memory.load(0x103, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xAA, 8)));

        memory.store(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

        let load_0 = memory.load(0x100, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xDD, 8)));

        let load_0 = memory.load(0x101, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xCC, 8)));

        let load_0 = memory.load(0x102, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xFF, 8)));

        let load_0 = memory.load(0x103, 8).unwrap();
        assert_eq!(load_0, KSet::constant(il::const_(0xAA, 8)));

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xAAFFCCDD, 32)));

        let other_memory: Memory<KSet> = Memory::new(Endian::Little);
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xAAFFCCDD, 32)));        
    }
}