//! A memory model for abstract interpretation
//!
//! This memory model wraps falcon::memory::paged::Memory and adds a `join`
//! method which operates over abstract values.

use analysis::ai::domain;
use error::*;
use memory::paged;
use memory;
use serde::Serialize;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use types::Endian;


pub trait Value: memory::value::Value + domain::Value {}


/// A memory model for abstract interpretation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Memory<'m, V: Value> {
    memory: paged::Memory<'m, V>,
}

impl<'m, V> Memory<'m, V> where V: Value {
    /// Create a new memory model for abstract interpretation.
    pub fn new(endian: Endian) -> Memory<'m, V> {
        Memory {
            memory: paged::Memory::new(endian),
        }
    }


    /// Get the endianness of this `Memory`
    pub fn endian(&self) -> Endian {
        self.memory.endian()
    }


    /// Create a new memory model for abstract interpretation with the given
    /// memory backing.
    pub fn new_with_backing(endian: Endian, backing: &'m memory::backing::Memory)
        -> Memory<'m, V> {

        Memory {
            memory: paged::Memory::new_with_backing(endian, backing),
        }
    }


    /// Perform a weak update, which joins the given value with the value in memory
    pub fn store_weak(&mut self, address: u64, value: &V) -> Result<()> {
        let value = match self.memory.load(address, value.bits())? {
            Some(v) => v.join(value)?,
            None => value.clone()
        };
        self.memory.store(address, value)
    }


    /// Perform a strong update, which overwrites the value in memory with the
    /// given value
    pub fn store_strong(&mut self, address: u64, value: V) -> Result<()> {
        self.memory.store(address, value)
    }


    /// Load an abstract value from the given address.
    pub fn load(&self, address: u64, bits: usize) -> Result<V> {
        Ok(match self.memory.load(address, bits)? {
            Some(v) => v,
            None => V::top(bits)
        })
    }


    /// Set all values in this memory model to top
    pub fn top(&mut self) -> Result<()> {
        *self = Memory::new(self.endian());
        
        Ok(())
    }


    /// Join this abstract memory model with another.
    pub fn join(mut self, other: &Memory<V>) -> Result<Memory<'m, V>> {
        // for every page in the other memory
        for other_page in &other.memory.pages {
            let page = other_page.1;
            for i in 0..paged::PAGE_SIZE {
                let address = *other_page.0 + i as u64;
                if let Some(other_value) = page.cells[i].as_ref()
                                                        .and_then(|cell| cell.value()) {
                    self.store_weak(address, other_value)?;
                }
            }
        }

        // for every page in this memory
        let mut insertions = Vec::new();
        for this_page in &self.memory.pages {
            let page = this_page.1;
            for i in 0..paged::PAGE_SIZE {
                let address = *this_page.0 + i as u64;
                if let Some(this_value) = page.cells[i].as_ref()
                                                       .and_then(|cell| cell.value()) {
                    let other_value = other.load(address, this_value.bits())?;
                    insertions.push((address, other_value));
                }
            }
        }

        for (address, value) in insertions {
            self.store_weak(address, &value)?;
        }

        // If the other memory does not have a backing, drop this backing.
        // This happens if a memory goes to top.
        if other.memory.backing().is_none() {
            self.memory.set_backing(None);
        }

        Ok(self)
    }
}


impl<'m, V> PartialOrd for Memory<'m, V> where V: Value {
    fn partial_cmp(&self, other: &Memory<'m, V>) -> Option<Ordering> {
        let mut ordering = Ordering::Equal;

        for self_page in &self.memory.pages {
            for i in 0..paged::PAGE_SIZE {
                let address = self_page.0 + i as u64;
                let this_byte: V = self.load(address, 8).unwrap();
                let other_byte: V = other.load(address, 8).unwrap();
                let byte_ordering = match this_byte.partial_cmp(&other_byte) {
                    Some(ordering) => ordering,
                    None => { println!("Memory None 0"); return None; }
                };
                ordering =
                    if byte_ordering == Ordering::Equal {
                        ordering
                    }
                    else if ordering == Ordering::Equal || ordering == byte_ordering {
                        // println!("  ..Memory ordering 2 0x{:x} {:?} {:?} {:?} {:?}",
                        //     address, ordering, byte_ordering, this_byte, other_byte);
                        byte_ordering
                    }
                    else {
                        // println!("Memory None 1 0x{:x} {:?} {:?} {:?} {:?}",
                        //     address, ordering, byte_ordering, this_byte, other_byte);
                        return None;
                    }
            }
        }

        for other_page in &other.memory.pages {
            if self.memory.pages.get(&other_page.0).is_some() {
                continue;
            }
            for i in 0..paged::PAGE_SIZE {
                let address = other_page.0 + i as u64;
                let this_byte = self.load(address, 8).unwrap();
                let other_byte = other.load(address, 8).unwrap();
                let byte_ordering = match this_byte.partial_cmp(&other_byte) {
                    Some(ordering) => ordering,
                    None => { println!("Memory None 2"); return None; }
                };
                ordering =
                    if byte_ordering == Ordering::Equal {
                        ordering
                    }
                    else if ordering == Ordering::Equal || ordering == byte_ordering {
                        // println!("Memory None 4 0x{:x} {:?} {:?} {:?} {:?}",
                        //     address, ordering, byte_ordering, this_byte, other_byte);
                        byte_ordering
                    }
                    else {
                        println!("Memory None 3");
                        return None;
                    }
            }
        }

        Some(ordering)
    }
}


impl<'m, V> PartialEq for Memory<'m, V> where V: Value {
    fn eq(&self, other: &Self) -> bool {
        match self.partial_cmp(other) {
            Some(ordering) => match ordering {
                Ordering::Equal => true,
                _ => false
            },
            None => false
        }
    }
}


impl<'m, V: Value + Serialize> domain::Memory<V> for Memory<'m, V> {
    fn join(self, other: &Memory<V>) -> Result<Memory<'m, V>> {
        self.join(other)
    }

    fn top(&mut self) -> Result<()> {
        self.top()
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

        memory.store_strong(0x100, value.clone()).unwrap();

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

        memory.store_strong(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

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
        let mut memory = memory.join(&other_memory).unwrap();
        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::Top(32));

        memory.store_strong(0x100, value.clone()).unwrap();
        let other_memory = memory.clone();
        let memory = memory.join(&other_memory).unwrap();
        assert_eq!(memory.load(0x100, 32).unwrap(), value);

        let mut memory: Memory<KSet> = Memory::new(Endian::Big);
        memory.store_strong(0x100, KSet::constant(il::const_(0xAABBCCDD, 32))).unwrap();
        let mut other_memory: Memory<KSet> = Memory::new(Endian::Big);
        other_memory.store_strong(0x100, KSet::constant(il::const_(0x11223344, 32))).unwrap();
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x100, 8).unwrap(), 
            KSet::constant(il::const_(0xaa, 8))
                .join(&KSet::constant(il::const_(0x11, 8)))
                .unwrap());

        let mut memory: Memory<KSet> = Memory::new(Endian::Big);
        memory.store_strong(0x100, KSet::constant(il::const_(0xAABBCCDD, 32))).unwrap();
        let mut other_memory: Memory<KSet> = Memory::new(Endian::Big);
        other_memory.store_strong(0x100, KSet::constant(il::const_(0x1122, 16))).unwrap();
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x102, 16).unwrap(),  KSet::Top(16));
        assert_eq!(memory.load(0x100, 8).unwrap(), 
            KSet::constant(il::const_(0xaa, 8))
                .join(&KSet::constant(il::const_(0x11, 8)))
                .unwrap());
        assert_eq!(memory.load(0x101, 8).unwrap(), 
            KSet::constant(il::const_(0xbb, 8))
                .join(&KSet::constant(il::const_(0x22, 8)))
                .unwrap());

    }

    #[test]
    fn ai_memory_little_endian() {
        let mut memory: Memory<KSet> = Memory::new(Endian::Little);

        let value = KSet::constant(il::const_(0xAABBCCDD, 32));

        memory.store_strong(0x100, value.clone()).unwrap();

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

        memory.store_strong(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

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

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::Top(32));        
    }
}