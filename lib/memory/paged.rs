//! A memory model with copy-on-write pages, which attempts not to split values
//! and accepts a memory backing.
//!
//! This memory model operates over types which implement the `Value` trait.

use crate::architecture::Endian;
use crate::il;
use crate::Error;
use crate::RC;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::memory::backing;
use crate::memory::value::Value;
use crate::memory::MemoryPermissions;

/// The size of the copy-on-write pages.
pub const PAGE_SIZE: usize = 1024;
pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

/// A memory cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MemoryCell<V: Value> {
    Value(V),
    Backref(u64),
}

impl<V> MemoryCell<V>
where
    V: Value,
{
    pub fn value(&self) -> Option<&V> {
        match *self {
            MemoryCell::Value(ref v) => Some(v),
            MemoryCell::Backref(_) => None,
        }
    }
}

/// A memory page.
///
/// These pages do not line up 1-to-1 with pages of the target architecture.
/// They are used for performance reasons in the copy-on-write memory model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Page<V: Value> {
    pub(crate) cells: Vec<Option<MemoryCell<V>>>,
    permissions: Option<MemoryPermissions>,
}

impl<V> Page<V>
where
    V: Value,
{
    fn new(size: usize) -> Page<V> {
        let mut v = Vec::new();
        for _ in 0..size {
            v.push(None);
        }

        Page {
            cells: v,
            permissions: None,
        }
    }

    fn store(&mut self, offset: usize, cell: MemoryCell<V>) {
        self.cells.as_mut_slice()[offset] = Some(cell);
    }

    fn load(&self, offset: usize) -> Option<&MemoryCell<V>> {
        self.cells[offset].as_ref()
    }

    pub fn permissions(&self) -> Option<&MemoryPermissions> {
        self.permissions.as_ref()
    }
    pub fn set_permissions(&mut self, permissions: Option<MemoryPermissions>) {
        self.permissions = permissions;
    }

    pub fn cells(&self) -> &[Option<MemoryCell<V>>] {
        &self.cells
    }
}

impl<V: Value> PartialEq for Memory<V> {
    fn eq(&self, other: &Self) -> bool {
        if self.pages == other.pages && self.endian == other.endian {
            self.backing()
                .and_then(|self_backing| {
                    other.backing().map(|other_backing| {
                        if RC::ptr_eq(&self_backing, &other_backing) {
                            true
                        } else {
                            self_backing == other_backing
                        }
                    })
                })
                .unwrap_or(false)
        } else {
            false
        }
    }
}

/// A copy-on-write paged memory model.
#[derive(Clone, Debug, Deserialize, Eq, Serialize)]
pub struct Memory<V: Value> {
    #[serde(skip)]
    backing: Option<RC<backing::Memory>>,
    endian: Endian,
    pub(crate) pages: HashMap<u64, RC<Page<V>>>,
}

impl<V> Memory<V>
where
    V: Value,
{
    /// Create a new paged memory model with the given endianness.
    pub fn new(endian: Endian) -> Memory<V> {
        Memory {
            backing: None,
            endian,
            pages: HashMap::new(),
        }
    }

    /// Get the endiannes of this memory model
    pub fn endian(&self) -> Endian {
        self.endian.clone()
    }

    /// Create a new paged memory model with the given endianness and memory
    /// backing.
    ///
    /// Paged memory will use the given backing when asked to load values which
    /// it does not have.
    pub fn new_with_backing(endian: Endian, backing: RC<backing::Memory>) -> Memory<V> {
        Memory {
            backing: Some(backing),
            endian,
            pages: HashMap::new(),
        }
    }

    /// Get the permissions for the given address.
    pub fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        let page_address = address & PAGE_MASK;
        self.pages
            .get(&page_address)
            .map(|page| page.permissions().cloned())
            .unwrap_or_else(|| {
                self.backing()
                    .and_then(|backing| backing.permissions(address))
            })
    }

    /// Set memory permissions for the page at the given address
    pub fn set_permissions(&mut self, address: u64, len: u64, permissions: MemoryPermissions) {
        let mut page_address = address & PAGE_MASK;
        let total_length = len + (address - page_address);
        while page_address < total_length {
            RC::make_mut(
                self.pages
                    .entry(page_address)
                    .or_insert_with(|| RC::new(Page::new(PAGE_SIZE))),
            )
            .set_permissions(Some(permissions));
            page_address += PAGE_SIZE as u64;
        }
    }

    /// Get a reference to the memory backing, if there is one
    pub fn backing(&self) -> Option<RC<backing::Memory>> {
        self.backing.clone()
    }

    /// Set the memory backing
    pub fn set_backing(&mut self, backing: Option<RC<backing::Memory>>) {
        self.backing = backing;
    }

    /// Get the pages which store the data for this memory model
    pub fn pages(&self) -> &HashMap<u64, RC<Page<V>>> {
        &self.pages
    }

    fn store_cell(&mut self, address: u64, cell: MemoryCell<V>) {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;

        if let Some(page) = self.pages.get_mut(&page_address) {
            RC::make_mut(page).store(offset, cell);
            return;
        }
        let mut page = Page::new(PAGE_SIZE);
        page.store(offset, cell);
        self.pages.insert(page_address, RC::new(page));
    }

    fn load_cell(&self, address: u64) -> Option<&MemoryCell<V>> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;
        match self.pages.get(&page_address) {
            Some(page) => page.load(offset),
            None => None,
        }
    }

    fn load_backing(&self, address: u64) -> Option<V> {
        self.backing().and_then(|backing| {
            backing
                .get8(address)
                .map(|v| V::constant(il::const_(v as u64, 8)))
        })
    }

    /// Don't take backrefs into account during this store. Needed sometimes to
    /// keep us from infinitely recursing
    fn store_no_backref(&mut self, address: u64, value: V) {
        let bytes = value.bits() / 8;
        self.store_cell(address, MemoryCell::Value(value));
        for i in 1..bytes {
            self.store_cell(address + i as u64, MemoryCell::Backref(address));
        }
    }

    /// Store a value at the given address.
    ///
    /// The value must have a bit-width >= 8, and the bit-width must be evenly
    /// divisible by 8.
    pub fn store(&mut self, address: u64, value: V) -> Result<(), Error> {
        if value.bits() % 8 != 0 || value.bits() == 0 {
            return Err(format!(
                "Storing value in paged memory with bit width not divisible by 8 and > 0 {}",
                value.bits()
            )
            .into());
        }

        // There are a few scenarios here we need to account for
        // E is for Expression, B is for Backref. Consider a 4-byte write, with
        // the original memory on top and our write immediately underneath that.
        //
        // Case 0
        // EEEBEE   The easiest scenario, we just replace expressions in place
        //  WWWW
        //
        // Case 1
        // EBBEEE   We overwrite some backrefs that refer to before our write.
        //  WWWW    We need to truncate the expression before.
        //          First byte we overwrite is a backref.
        //
        // Case 2
        // EEEBBB   We overwrite an expression that starts in the middle of our
        //  WWWW    write.
        //          Byte after last byte is a backref.
        //
        // Case 3
        // EBBBBB   We overwrite an expression that starts before our expression,
        //  WWWW    and continues after out expression.
        //          Handle case 2, then case 1, and case 3 will be fine.

        // Handle backrefs that come after by finding the first address after
        // our write, truncating it to the appropriate size, and rewriting it
        let address_after_write = address + (value.bits() / 8) as u64;

        let value_to_write = if let Some(MemoryCell::Backref(backref_address)) =
            self.load_cell(address_after_write)
        {
            let backref_value = self
                .load_cell(*backref_address)
                .ok_or("Backref cell pointed to null cell")?
                .value()
                .ok_or("Backref cell pointed to cell without value")?;
            // furthest most address backref value reaches
            let backref_furthest_address = backref_address + (backref_value.bits() / 8) as u64;
            // how many bits are left after our write
            let left_bits = ((backref_furthest_address - address_after_write) * 8) as usize;
            // load that value
            self.load(address_after_write, left_bits)?
        } else {
            None
        };

        if let Some(value_to_write) = value_to_write {
            self.store_no_backref(address_after_write, value_to_write);
        }

        // handle values we overwrite before this write
        let value_to_write =
            if let Some(MemoryCell::Backref(backref_address)) = self.load_cell(address) {
                let backref_value = self.load_cell(*backref_address).unwrap().value().unwrap();
                // furthest most address backref value reaches
                let backref_furthest_address = backref_address + (backref_value.bits() / 8) as u64;
                // how many bits are we about to overwrite
                let overwrite_bits = (backref_furthest_address - address) * 8;
                // how many bits are left over
                let left_bits = backref_value.bits() - overwrite_bits as usize;
                Some((*backref_address, self.load(*backref_address, left_bits)?))
            } else {
                None
            };

        if let Some(value_to_write) = value_to_write {
            self.store_no_backref(value_to_write.0, value_to_write.1.unwrap());
        }

        // Go ahead and store this value
        self.store_no_backref(address, value);

        Ok(())
    }

    /// Loads a value from the given address.
    ///
    /// `bits` must be >= 8, and evenly divisible by 8.
    ///
    /// If a value cannot be retrieved for all bits of the load, `None` will
    /// be returned.
    pub fn load(&self, address: u64, bits: usize) -> Result<Option<V>, Error> {
        if bits % 8 != 0 {
            return Err(format!("Loading paged memory with non-8 bit-width {}", bits).into());
        } else if bits == 0 {
            return Err("Loading paged memory with 0 bit-width".into());
        }

        // The scenarios we need to account for
        // E is Expression, B is Backref, L is for Load
        //
        // Case 0
        // EEBBBE   A perfect match. No adjustments required.
        //  LLLL
        //
        // Case 1
        // EEBBBB   An expression extends beyond the load, truncate
        //  LLLL
        //
        // Case 2
        // EBBBBB   An expression overlaps on both sides. Shift and truncate.
        //  LLLL
        //
        // Case 3
        // EEBEBE   Multiple sub-expressions. Shift and or them together.
        //  LLLL
        //
        // Case 4
        // EBEBEB   Overlapping expression before, in the middle, and after
        //  LLLL    Handle case 2, then case 3
        //

        // This will be a nightmare to deal with endian-wise, so we're going to
        // attempt to load everything the first time, and if this doesn't work
        // then we'll do single-byte loads and patch everything together.

        // Get started with our first load
        let load_value = if let Some(cell) = self.load_cell(address) {
            match *cell {
                MemoryCell::Value(ref value) => {
                    if value.bits() <= bits {
                        value.clone()
                    } else {
                        match self.endian {
                            Endian::Little => value.trun(bits)?,
                            Endian::Big => value.shr(value.bits() - bits)?.trun(bits)?,
                        }
                    }
                }
                MemoryCell::Backref(backref_address) => {
                    let value = self
                        .load_cell(backref_address)
                        .ok_or("Backref cell pointed to null cell")?
                        .value()
                        .ok_or("Backref cell pointed to cell without value")?;
                    let value = match self.endian {
                        Endian::Little => {
                            let shift_bits = ((address - backref_address) * 8) as usize;
                            let trun_bits = value.bits() - shift_bits;
                            value.shr(shift_bits)?.trun(trun_bits).map_err(|e| {
                                e.chain(Error::Custom(format!(
                                    "Shifted {:?} right {} and truncated to {}",
                                    value, shift_bits, bits
                                )))
                            })?
                        }
                        Endian::Big => {
                            let offset = ((address - backref_address) * 8) as usize;
                            let shift_bits = if bits + offset >= value.bits() {
                                0
                            } else {
                                value.bits() - bits - offset
                            };
                            let trun_bits = value.bits() - offset - shift_bits;
                            value.shr(shift_bits)?.trun(trun_bits).map_err(|e| {
                                e.chain(Error::Custom(format!(
                                    "Shifted {:?} right {} and truncated to {}",
                                    value, shift_bits, bits
                                )))
                            })?
                        }
                    };
                    if value.bits() > bits {
                        value.trun(bits).map_err(|e| {
                            e.chain(Error::Custom(format!(
                                "Error truncating {} bits to {}",
                                value.bits(),
                                bits
                            )))
                        })?
                    } else {
                        value
                    }
                }
            }
        } else {
            match self.load_backing(address) {
                Some(v) => v,
                None => return Ok(None),
            }
        };

        // if we're done, finish
        if load_value.bits() == bits {
            return Ok(Some(load_value));
        }

        /*
        000000AA -> AA000000 offset = 0
        000000BB -> 00BB0000 0ffset = 1
        offset = 1
        */

        // Fall back to single-byte loads
        let mut result: Option<V> = None;
        let bytes = (bits / 8) as u64;
        for offset in 0..bytes {
            let value = match self.load(address + offset, 8)? {
                Some(v) => v,
                None => match self.load_backing(address) {
                    Some(v) => v,
                    None => return Ok(None),
                },
            };
            let value = value.zext(bits)?;
            let shift = match self.endian {
                Endian::Big => (bytes - offset - 1) * 8,
                Endian::Little => offset * 8,
            };
            let value = value.shl(shift as usize)?;
            result = match result {
                Some(r) => Some(r.or(&value)?),
                None => Some(value),
            };
        }

        Ok(result)
    }
}

#[cfg(test)]
mod memory_tests {
    use crate::architecture::Endian;
    use crate::il;
    use crate::memory;
    use crate::memory::paged::Memory;
    use crate::memory::MemoryPermissions;
    use crate::RC;

    #[test]
    fn big_endian() {
        let mut memory: Memory<il::Constant> = Memory::new(Endian::Big);

        let value = il::const_(0xAABBCCDD, 32);

        memory.store(0x100, value.clone()).unwrap();

        let load_value = memory.load(0x100, 32).unwrap().unwrap();

        assert_eq!(load_value, value);

        let load_0 = memory.load(0x100, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xAA, 8));

        let load_0 = memory.load(0x101, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xBB, 8));

        let load_0 = memory.load(0x102, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xCC, 8));

        let load_0 = memory.load(0x103, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xDD, 8));

        memory.store(0x102, il::const_(0xFF, 8)).unwrap();

        let load_0 = memory.load(0x100, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xAA, 8));

        let load_0 = memory.load(0x101, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xBB, 8));

        let load_0 = memory.load(0x102, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xFF, 8));

        let load_0 = memory.load(0x103, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xDD, 8));

        assert_eq!(
            memory.load(0x100, 32).unwrap().unwrap(),
            il::const_(0xaabbffdd, 32)
        );

        /*
               \/
            AA BB CC DD 11 22 33 44
            0x44AABBCC
        */

        let mut memory: Memory<il::Constant> = Memory::new(Endian::Big);

        memory.store(0x100, il::const_(0xAABBCCDD, 32)).unwrap();
        memory.store(0x104, il::const_(0x11223344, 32)).unwrap();

        assert_eq!(
            memory.load(0x101, 32).unwrap().unwrap(),
            il::const_(0xBBCCDD11, 32)
        );
    }

    #[test]
    fn little_endian() {
        let mut memory: Memory<il::Constant> = Memory::new(Endian::Little);

        let value = il::const_(0xAABBCCDD, 32);

        memory.store(0x100, value.clone()).unwrap();

        let load_value = memory.load(0x100, 32).unwrap().unwrap();

        assert_eq!(load_value, value);

        let load_0 = memory.load(0x100, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xDD, 8));

        let load_0 = memory.load(0x101, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xCC, 8));

        let load_0 = memory.load(0x102, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xBB, 8));

        let load_0 = memory.load(0x103, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xAA, 8));

        memory.store(0x102, il::const_(0xFF, 8)).unwrap();

        let load_0 = memory.load(0x100, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xDD, 8));

        let load_0 = memory.load(0x101, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xCC, 8));

        let load_0 = memory.load(0x102, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xFF, 8));

        let load_0 = memory.load(0x103, 8).unwrap().unwrap();
        assert_eq!(load_0, il::const_(0xAA, 8));

        assert_eq!(
            memory.load(0x100, 32).unwrap().unwrap(),
            il::const_(0xAAFFCCDD, 32)
        );

        /*
               \/
            DD CC BB AA 44 33 22 11
            0x44AABBCC
        */

        let mut memory: Memory<il::Constant> = Memory::new(Endian::Little);

        memory.store(0x100, il::const_(0xAABBCCDD, 32)).unwrap();
        memory.store(0x104, il::const_(0x11223344, 32)).unwrap();

        assert_eq!(
            memory.load(0x101, 32).unwrap().unwrap(),
            il::const_(0x44AABBCC, 32)
        );
    }

    #[test]
    fn backed() {
        let mut backing = memory::backing::Memory::new(Endian::Big);

        backing.set_memory(
            0x100,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77].to_vec(),
            MemoryPermissions::READ,
        );

        let mut memory: Memory<il::Constant> =
            Memory::new_with_backing(Endian::Big, RC::new(backing));

        let value = il::const_(0xAABBCCDD, 32);

        memory.store(0x100, value.clone()).unwrap();
        memory.store(0x107, value.clone()).unwrap();

        let load_value = memory.load(0x100, 32).unwrap().unwrap();

        assert_eq!(load_value, value);

        assert_eq!(
            memory.load(0x106, 32).unwrap().unwrap(),
            il::const_(0x66AABBCC, 32)
        );
    }

    #[test]
    fn set_permissions() {
        let mut backing = memory::backing::Memory::new(Endian::Big);

        backing.set_memory(
            0x100,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77].to_vec(),
            MemoryPermissions::READ,
        );

        let mut memory: Memory<il::Constant> =
            Memory::new_with_backing(Endian::Big, RC::new(backing));

        assert_eq!(MemoryPermissions::READ, memory.permissions(0x100).unwrap());

        memory.set_permissions(0, 1024, MemoryPermissions::READ | MemoryPermissions::WRITE);

        assert_eq!(
            MemoryPermissions::READ | MemoryPermissions::WRITE,
            memory.permissions(0).unwrap()
        );

        assert_eq!(
            MemoryPermissions::READ | MemoryPermissions::WRITE,
            memory.permissions(0x100).unwrap()
        );
    }
}
