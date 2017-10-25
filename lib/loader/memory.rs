//! A representation of memory given by an executable/loader.

use error::*;
use translator::TranslationMemory;
use std::collections::BTreeMap;
use std::cmp::{Ord, Ordering, PartialOrd};

bitflags! {
    /// RWX permissions for memory.
    pub struct MemoryPermissions: u32 {
        const NONE    = 0b000;
        const READ    = 0b001;
        const WRITE   = 0b010;
        const EXECUTE = 0b100;
        const ALL     = 0b111;
    }
}


/// A continuous memory area of any size given by a loader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySegment {
    address: u64,
    bytes: Vec<u8>,
    permissions: MemoryPermissions
}

impl MemorySegment {
    pub(crate) fn new(address: u64, bytes: Vec<u8>, permissions: MemoryPermissions)
    -> MemorySegment {
        MemorySegment {
            address: address,
            bytes: bytes,
            permissions: permissions
        }
    }

    /// Get the address of this `MemorySegment`.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get a `u8` slice of this `MemorySegment`'s contents.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get a mutable reference to the contents of this `MemorySegment`.
    pub fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Get the permissions given to this `MemorySegment` by the loader.
    pub fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }

    /// Get the length of this `MemorySegment` in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    fn truncate(&mut self, new_size: usize) {
        self.bytes.truncate(new_size)
    }
}

impl Ord for MemorySegment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl PartialOrd for MemorySegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


/// A full representation of all memory as given by a loader.
#[derive(Clone, Debug)]
pub struct Memory {
    segments: BTreeMap<u64, MemorySegment>
}

impl Memory {
    /// Create a new, empty `Memory`
    pub fn new() -> Memory {
        Memory {
            segments: BTreeMap::new()
        }
    }

    /// Add a `MemorySegment` to this `Memory`
    ///
    /// Handles overlapping memory segments, placing this segment, "On top of," any
    /// existing segments.
    pub fn add_segment(&mut self, segment: MemorySegment) {
        // handle overlapping segments
        let mut add_segments = Vec::new();
        let mut del_segments = Vec::new();
        for ref mut s in &mut self.segments {
            let address = s.0;
            let s = &mut s.1;
            // if a segment runs into this one, truncate it
            if s.address() + s.len() as u64 > segment.address() {
                s.truncate((segment.address() - *address) as usize);
            }
            // if a segment starts in this one, adjust it
            if    s.address() > segment.address()
               && s.address() < segment.address() + segment.len() as u64 {
                if s.address() + s.len() as u64 > segment.address() + segment.len() as u64 {
                    let offset = (  segment.address() 
                                  + segment.len() as u64
                                  - s.address()) as usize;
                    let new_segment = MemorySegment::new(
                        segment.address() + segment.len() as u64,
                        s.bytes().get(offset..s.len()).unwrap().to_vec(),
                        s.permissions()
                    );
                    add_segments.push(new_segment);
                }
                del_segments.push(s.address());
            }
        }

        // delete any overlapping segments
        for address in del_segments {
            self.segments.remove(&address);
        }

        // add segments as required from adjusting overlapping segments
        for segment in add_segments {
            self.segments.insert(segment.address(), segment);
        }

        // add our segment
        self.segments.insert(segment.address(), segment);
    }

    /// Get a buffer to as much data as possible given a memory address
    pub fn get(&self, address: u64) -> Option<&[u8]> {
        for segment in &self.segments {
            if *segment.0 <= address && segment.0 + segment.1.len() as u64 > address {
                let segment = segment.1;
                let range = ((address - segment.address()) as usize)..(segment.len() as usize);
                let address = segment.address();
                return self.segments[&address].bytes().get(range);
            }
        }
        None
    }

    /// Get a single `u8` from the specified address, or `None` if nothing exists at the given
    /// address.
    pub fn get_u8(&self, address: u64) -> Option<u8> {
        for segment in &self.segments {
            if *segment.0 <= address && segment.0 + segment.1.len() as u64 > address {
                return match segment.1.bytes().get((address - segment.0) as usize) {
                    Some(u) => Some(u.to_owned()),
                    None => None
                }
            }
        }
        None
    }

    /// Set the `u8` at the given address.
    pub fn set_u8(&mut self, address: u64, value: u8) -> Result<()> {
        for segment in &mut self.segments {
            if *segment.0 <= address && segment.0 + segment.1.len() as u64 > address {
                segment.1.bytes_mut()[(address - segment.0) as usize] = value;
                return Ok(())
            }
        }
        bail!("Invalid index 0x{:x} into memory segments", address)
    }

    /// Get a little-endian `u32` from the given address.
    pub fn get_u32_le(&self, address: u64) -> Option<u32> {
        let mut result: u32 = 0;
        for i in 0..4 {
            match self.get_u8(address + i as u64) {
                None => return None,
                Some(u) => result |= (u as u32) << ((i * 8) as u32)
            }
        }
        Some(result)
    }

    /// Set a little-endian `u32` at the given address.
    pub fn set_u32_le(&mut self, address: u64, mut value: u32) -> Result<()> {
        for i in address..(address + 4 as u64) {
            let value_u8: u8 = (value & 0xff) as u8;
            value >>= 8;
            self.set_u8(i, value_u8)?;
        }
        Ok(())
    }

    /// Get a null-terminated string beginning at the given address
    pub fn get_str(&self, address: u64) -> Option<String> {
        if let Some(buf) = self.get(address) {
            for i in 0..buf.len() {
                if buf[i] == 0 {
                    return Some(String::from_utf8(buf.get(0..i)
                                                     .unwrap()
                                                     .to_vec())
                                                     .unwrap());
                }
            }
        }
        None
    }

    /// Get a mapping of address to `MemorySegment` for each `MemorySegment` in this `Memory`.
    pub fn segments(&self) -> &BTreeMap<u64, MemorySegment> {
        &self.segments
    }

    /// get permissions for an address
    pub fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        for segment in &self.segments {
            if *segment.0 <= address && segment.0 + segment.1.len() as u64 > address {
                return Some(segment.1.permissions);
            }
        }
        None
    }
}


impl TranslationMemory for Memory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        if let Some(permissions) = self.permissions(address) {
            if !permissions.contains(MemoryPermissions::READ | MemoryPermissions::EXECUTE) {
                return None;
            }
        }
        self.get_u8(address)
    }
}