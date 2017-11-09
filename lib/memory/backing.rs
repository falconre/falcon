//! A flat representation of memory provided by lifters, typically used in a
//! read-only fashion
//!
//! This memory model implements the `TranslationMemory` trait, allowing lifters
//! to use it to lift instructions.

use error::*;
use memory::MemoryPermissions;
use std::collections::Bound::Included;
use std::collections::BTreeMap;
use translator::TranslationMemory;
use types::Endian;


/// A section of backed memory. Essentially a vector of type `u8` with
/// permissions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Section {
    data: Vec<u8>,
    permissions: MemoryPermissions,
}


impl Section {
    /// Create a new memory section.
    pub fn new(data: Vec<u8>, permissions: MemoryPermissions) -> Section {
        Section {
            data: data,
            permissions: permissions,
        }
    }

    /// Get this memory section's data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of this memory section.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Get the permissions of this memory section.
    pub fn permissions(&self) -> MemoryPermissions {
        self.permissions.clone()
    }

    /// Truncate the data of this memory section.
    fn truncate(&mut self, size: usize) {
        self.data.truncate(size);
    }
}


/// A simple memory model, containing permissioned sections of type `u8`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Memory {
    endian: Endian,
    sections: BTreeMap<u64, Section>
}



impl Memory {
    /// Create a new backed memory module with the given endianness.
    pub fn new(endian: Endian) -> Memory {
        Memory {
            endian: endian,
            sections: BTreeMap::new()
        }
    }

    /// Get the sections in this memory module.
    pub fn sections(&self) -> &BTreeMap<u64, Section> {
        &self.sections
    }

    /// Get the permissions at the given address.
    pub fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        match self.section_address(address) {
            Some(section_address) => Some(self.sections[&section_address].permissions()),
            None => None
        }
    }

    /// Get the `u8` value at the given address.
    pub fn get8(&self, address: u64) -> Option<u8> {
        match self.section_address_offset(address) {
            Some((address, offset)) =>
                Some(self.sections[&address].data()[offset]),
            None => None
        }
    }

    /// Set the 32-bit value at the given address, allowing the memory model
    /// to account for the underlying endianness.
    pub fn set32(&mut self, address: u64, value: u32) -> Result<()> {
        let (section_address, offset) =
            self.section_address_offset(address)
                .expect(&format!("Address 0x{:x} has no section", address));

        let section = self.sections.get_mut(&section_address).unwrap();

        if offset + 4 > section.len() {
            bail!(format!("Section at 0x{:x} is of size {}, and not big \
                           enough to hold 32-bit value",
                           section_address,
                           section.len()));
        }

        match self.endian {
            Endian::Big => {
                *section.data.get_mut(offset    ).unwrap() = (value >> 24) as u8;
                *section.data.get_mut(offset + 1).unwrap() = (value >> 16) as u8;
                *section.data.get_mut(offset + 2).unwrap() = (value >> 8 ) as u8;
                *section.data.get_mut(offset + 3).unwrap() = (value      ) as u8;
            },
            Endian::Little => {
                *section.data.get_mut(offset    ).unwrap() = (value      ) as u8;
                *section.data.get_mut(offset + 1).unwrap() = (value >> 8 ) as u8;
                *section.data.get_mut(offset + 2).unwrap() = (value >> 16) as u8;
                *section.data.get_mut(offset + 3).unwrap() = (value >> 24) as u8;
            }
        }

        Ok(())
    }

    /// Get the 32-bit value at the given address, allowing the memory model to
    /// account for the underlying endianness.
    pub fn get32(&self, address: u64) -> Option<u32> {
        let (section_address, offset) = match self.section_address_offset(address) {
            Some((section_address, offset)) => (section_address, offset),
            None => return None
        };

        let section = self.sections.get(&section_address).unwrap();

        if offset + 4 > section.len() {
            return None;
        }

        Some(match self.endian {
            Endian::Big => {
                (section.data[offset    ] as u32) << 24 |
                (section.data[offset + 1] as u32) << 16 |
                (section.data[offset + 2] as u32) <<  8 |
                (section.data[offset + 3] as u32)
            },
            Endian::Little => {
                (section.data[offset    ] as u32)       |
                (section.data[offset + 1] as u32) <<  8 |
                (section.data[offset + 2] as u32) << 16 |
                (section.data[offset + 3] as u32) << 24
            }
        })
    }

    /// Set the memory at the given address, and give that memory the given
    /// permissions.
    ///
    /// This takes care of the underlying memory sections automatically.
    pub fn set_memory(
        &mut self,
        address: u64,
        data: Vec<u8>,
        permissions: MemoryPermissions
    ) {
        // All overlapping memory sections need to be adjusted
        // Start by collecting addresses and lengths
        let als = self.sections
                      .iter()
                      .map(|(address, section)| (*address, section.len()))
                      .collect::<Vec<(u64, usize)>>();

        // Adjust overlapping memory sections
        for al in als {
            let (a, l) = (al.0, al.1 as u64);
            if a < address && a + l > address {
                if a + l <= address + data.len() as u64 {
                    let new_length = (address - a) as usize;
                    self.sections.get_mut(&a).unwrap().truncate(new_length);
                }
                else {
                    let offset = address + data.len() as u64 - a;
                    let split = self.sections
                                    .get_mut(&a)
                                    .unwrap()
                                    .data
                                    .split_off(offset as usize);
                    let permissions = self.sections[&a].permissions();
                    self.sections.insert(
                        address + data.len() as u64,
                        Section::new(split, permissions)
                    );

                    let new_length = (address - a) as usize;
                    self.sections.get_mut(&a).unwrap().truncate(new_length);
                } 
            }
            else if a >= address && a + l <= address + data.len() as u64 {
                self.sections.remove(&a);
            }
            else if a >= address && a + l > address + data.len() as u64 {
                let offset = address + data.len() as u64 - a;
                let split = self.sections
                                .get_mut(&a)
                                .unwrap()
                                .data
                                .split_off(offset as usize);
                let permissions = self.sections[&a].permissions();
                self.sections.remove(&a);
                self.sections.insert(
                        address + data.len() as u64,
                        Section::new(split, permissions)
                );
            }
        }

        self.sections.insert(address, Section::new(data, permissions));
    }


    fn section_address(&self, address: u64) -> Option<u64> {
        let mut sections = self.sections.range((Included(0), Included(address)));
        if let Some((section_address, section)) = sections.next_back() {
            if    *section_address <= address
               && *section_address + section.len() as u64 > address {
                return Some(*section_address);
            }
        }
        None
    }


    fn section_address_offset(&self, address: u64) -> Option<(u64, usize)> {
        match self.section_address(address) {
            Some(section_address) =>
                Some((section_address, (address - section_address) as usize)),
            None => None
        }
    }
}


impl TranslationMemory for Memory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        self.get8(address)
    }

    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.permissions(address)
    }
}