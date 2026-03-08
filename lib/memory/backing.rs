//! A flat representation of memory provided by lifters, typically used in a
//! read-only fashion
//!
//! This memory model implements the `TranslationMemory` trait, allowing lifters
//! to use it to lift instructions.

use crate::architecture::Endian;
use crate::executor;
use crate::il;
use crate::memory::MemoryPermissions;
use crate::translator::TranslationMemory;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Bound::Included;

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
        Section { data, permissions }
    }

    /// Get this memory section's data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of this memory section.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the data field is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the permissions of this memory section.
    pub fn permissions(&self) -> MemoryPermissions {
        self.permissions
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
    sections: BTreeMap<u64, Section>,
}

impl Memory {
    /// Create a new backed memory module with the given endianness.
    pub fn new(endian: Endian) -> Memory {
        Memory {
            endian,
            sections: BTreeMap::new(),
        }
    }

    /// Get the sections in this memory module.
    pub fn sections(&self) -> &BTreeMap<u64, Section> {
        &self.sections
    }

    /// Get the permissions at the given address.
    pub fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.section_address(address).map(|section_address| {
            self.sections
                .get(&section_address)
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to get section at 0x{:x} in \
                         backing::Memory::permissions()",
                        section_address
                    )
                })
                .permissions()
        })
    }

    /// Get the `u8` value at the given address.
    pub fn get8(&self, address: u64) -> Option<u8> {
        self.section_address_offset(address)
            .map(|(address, offset)| {
                *self
                    .sections
                    .get(&address)
                    .unwrap_or_else(|| {
                        panic!(
                            "Failed to get section at 0x{:x} in \
                         backing::Memory::permissions()",
                            address
                        )
                    })
                    .data()
                    .get(offset)
                    .unwrap_or_else(|| {
                        panic!(
                            "Failed to get offset 0x{:x} from 0x{:x} in \
                         backing::Memory::permissions()",
                            offset, address
                        )
                    })
            })
    }

    /// Set the 32-bit value at the given address, allowing the memory model
    /// to account for the underlying endianness.
    pub fn set32(&mut self, address: u64, value: u32) -> Result<(), Error> {
        let (section_address, offset) = self
            .section_address_offset(address)
            .unwrap_or_else(|| panic!("Address 0x{:x} has no section", address));

        let section = self.sections.get_mut(&section_address).unwrap();

        if offset + 4 > section.len() {
            return Err(Error::Custom(format!(
                "Section at 0x{:x} is of size {}, and not big \
                 enough to hold 32-bit value",
                section_address,
                section.len()
            )));
        }

        match self.endian {
            Endian::Big => {
                *section.data.get_mut(offset).unwrap() = (value >> 24) as u8;
                *section.data.get_mut(offset + 1).unwrap() = (value >> 16) as u8;
                *section.data.get_mut(offset + 2).unwrap() = (value >> 8) as u8;
                *section.data.get_mut(offset + 3).unwrap() = (value) as u8;
            }
            Endian::Little => {
                *section.data.get_mut(offset).unwrap() = (value) as u8;
                *section.data.get_mut(offset + 1).unwrap() = (value >> 8) as u8;
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
            None => return None,
        };

        let section = self.sections.get(&section_address).unwrap();

        if offset + 4 > section.len() {
            return None;
        }

        Some(match self.endian {
            Endian::Big => {
                (section.data[offset] as u32) << 24
                    | (section.data[offset + 1] as u32) << 16
                    | (section.data[offset + 2] as u32) << 8
                    | (section.data[offset + 3] as u32)
            }
            Endian::Little => {
                (section.data[offset] as u32)
                    | (section.data[offset + 1] as u32) << 8
                    | (section.data[offset + 2] as u32) << 16
                    | (section.data[offset + 3] as u32) << 24
            }
        })
    }

    /// Get a constant value up to a certain number of bits
    pub fn get(&self, address: u64, bits: usize) -> Option<il::Constant> {
        if bits % 8 > 0 || bits == 0 {
            return None;
        }

        let mut value = il::expr_const(self.get8(address)? as u64, bits);

        match self.endian {
            Endian::Big => {
                for i in 1..(bits / 8) {
                    value = il::Expression::or(
                        il::Expression::shl(value, il::expr_const(8, bits)).unwrap(),
                        il::expr_const(self.get8(address + i as u64).unwrap() as u64, bits),
                    )
                    .unwrap();
                }
                Some(executor::eval(&value).unwrap())
            }
            Endian::Little => {
                for i in 1..(bits / 8) {
                    value = il::Expression::or(
                        il::Expression::shl(
                            il::expr_const(self.get8(address + i as u64).unwrap() as u64, bits),
                            il::expr_const((i * 8) as u64, bits),
                        )
                        .unwrap(),
                        value,
                    )
                    .unwrap();
                }
                Some(executor::eval(&value).unwrap())
            }
        }
    }

    /// Set the memory at the given address, and give that memory the given
    /// permissions.
    ///
    /// This takes care of the underlying memory sections automatically.
    pub fn set_memory(&mut self, address: u64, data: Vec<u8>, permissions: MemoryPermissions) {
        // All overlapping memory sections need to be adjusted
        // Start by collecting addresses and lengths
        let als = self
            .sections
            .iter()
            .map(|(address, section)| (*address, section.len()))
            .collect::<Vec<(u64, usize)>>();

        // Adjust overlapping memory sections
        for al in als {
            let (a, l) = (al.0, al.1 as u64);
            if a < address && a + l > address {
                if a + l <= address + data.len() as u64 {
                    let new_length = (address - a) as usize;
                    self.sections
                        .get_mut(&a)
                        .unwrap_or_else(|| {
                            panic!(
                                "Failed to get section 0x{:x} in \
                             backing::Memory::set_memory(). This should never \
                             happen.",
                                a
                            )
                        })
                        .truncate(new_length);
                } else {
                    let offset = address + data.len() as u64 - a;
                    let split = self
                        .sections
                        .get_mut(&a)
                        .unwrap_or_else(|| {
                            panic!(
                                "Failed to get section 0x{:x} in \
                             backing::Memory::set_memory(). This should \
                             never happen.",
                                a
                            )
                        })
                        .data
                        .split_off(offset as usize);
                    let permissions = self
                        .sections
                        .get(&a)
                        .unwrap_or_else(|| {
                            panic!(
                                "Failed to get section 0x{:x} in \
                             backing::Memory::set_memory(). This should \
                             never happen.",
                                a
                            )
                        })
                        .permissions();
                    self.sections.insert(
                        address + data.len() as u64,
                        Section::new(split, permissions),
                    );

                    let new_length = (address - a) as usize;
                    self.sections.get_mut(&a).unwrap().truncate(new_length);
                }
            } else if a >= address && a + l <= address + data.len() as u64 {
                if self.sections.get(&a).is_none() {
                    panic!(
                        "About to remove 0x{:x} from sections in \
                            backing::Memory::set_memory, but address does not
                            exist",
                        a
                    );
                }
                self.sections.remove(&a);
            } else if a >= address
                && a < address + data.len() as u64
                && a + l > address + data.len() as u64
            {
                let offset = address + data.len() as u64 - a;
                let data_len = self.sections.get(&a).unwrap().data.len() as u64;
                if offset > data_len {
                    panic!("offset 0x{:x} is > data.len() 0x{:x}", offset, data_len);
                }
                let split = self
                    .sections
                    .get_mut(&a)
                    .unwrap()
                    .data
                    .split_off(offset as usize);
                let permissions = self
                    .sections
                    .get(&a)
                    .unwrap_or_else(|| {
                        panic!(
                            "Failed to get section for 0x{:x} while updating \
                         permissions in backing::Memory::set_memory(). \
                         This should never happen.",
                            a
                        )
                    })
                    .permissions();
                self.sections.remove(&a);
                self.sections.insert(
                    address + data.len() as u64,
                    Section::new(split, permissions),
                );
            }
        }

        self.sections
            .insert(address, Section::new(data, permissions));
    }

    fn section_address(&self, address: u64) -> Option<u64> {
        let mut sections = self.sections.range((Included(0), Included(address)));
        if let Some((section_address, section)) = sections.next_back() {
            if *section_address <= address && *section_address + section.len() as u64 > address {
                return Some(*section_address);
            }
        }
        None
    }

    fn section_address_offset(&self, address: u64) -> Option<(u64, usize)> {
        self.section_address(address)
            .map(|section_address| (section_address, (address - section_address) as usize))
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
