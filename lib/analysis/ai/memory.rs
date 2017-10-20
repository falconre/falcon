//! A symbolic memory model.
//!
//! Each cell of `SymbolicMemory` is a valid `il::Expr`. Concrete values may be stored as
//! `il::Constant`, and symbolic values stored as valid expressions.
//!
//! `SymbolicMemory` is paged under-the-hood with reference-counted pages. When these pages
//! are written to, we use the copy-on-write functionality of rust's `std::rc::Rc` type,
//! giving us copy-on-write paging. This allows for very fast forks of `SymbolicMemory`.

use error::*;
use RC;
use types::Endian;
use std::collections::BTreeMap;
use std::fmt::Debug;


const PAGE_SIZE: usize = 4092;


pub trait MemoryValue: Clone + Debug + Eq + PartialEq {
    /// Return the number of bits contained in this value
    fn bits(&self) -> usize;

    /// Shift the value left by the given number of bits
    fn shl(&self, bits: usize) -> Result<Self>;

    /// Shift the value right by the given number of bits
    fn shr(&self, bits: usize) -> Result<Self>;

    /// Truncate the value to the given number of bits
    fn trun(&self, bits: usize) -> Result<Self>;

    /// Zero-extend the value to the given number of bits
    fn zext(&self, bits: usize) -> Result<Self>;

    /// Or this value with the given value
    fn or(&self, other: &Self) -> Result<Self>;

    /// Join two values together
    fn join(&self, other: &Self) -> Result<Self>;

    /// Return an empty value
    fn empty(bits: usize) -> Self;
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum MemoryCell<V: MemoryValue> {
    Value(V),
    Backref(u64)
}

impl<V> MemoryCell<V> where V: MemoryValue {
    fn value(&self) -> Option<&V> {
        match self {
            &MemoryCell::Value(ref v) => Some(v),
            &MemoryCell::Backref(_) => None
        }
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
struct Page<V: MemoryValue> {
    size: usize,
    cells: Vec<MemoryCell<V>>
}


impl<V> Page<V> where V: MemoryValue {
    fn new(size: usize) -> Page<V> {
        let mut v = Vec::new();
        for _ in 0..size {
            v.push(MemoryCell::Value(V::empty(8)));
        }

        Page {
            size: size,
            cells: v
        }
    }

    fn new_with_cells(size: usize, cells: Vec<MemoryCell<V>>) -> Page<V> {
        if cells.len() != size {
            panic!("Page::new_with_cells size={} cells.len()={}", size, cells.len());
        }
        Page {
            size: size,
            cells: cells
        }
    }

    fn store(&mut self, offset: usize, cell: MemoryCell<V>) -> Result<()> {
        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        self.cells.as_mut_slice()[offset] = cell;

        Ok(())
    }

    fn load(&self, offset: usize) -> Result<&MemoryCell<V>> {
        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        Ok(&self.cells[offset])
    }
}


/// A symbolic memory model for Falcon IL expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Memory<V: MemoryValue> {
    endian: Endian,
    pages: BTreeMap<u64, RC<Page<V>>>
}


impl<V> Memory<V> where V: MemoryValue {
    /// Create a new `SymbolicMemory`.
    pub fn new(endian: Endian) -> Memory<V> {
        Memory {
            endian: endian,
            pages: BTreeMap::new()
        }
    }


    fn store_cell(&mut self, address: u64, cell: MemoryCell<V>) -> Result<()> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;

        if let Some(mut page) = self.pages.get_mut(&page_address) {
            RC::make_mut(&mut page).store(offset, cell)?;
            return Ok(())
        }

        let mut page = Page::new(PAGE_SIZE);
        page.store(offset, cell)?;
        self.pages.insert(page_address, RC::new(page));

        Ok(())
    }


    fn load_cell(&self, address: u64) -> Result<Option<&MemoryCell<V>>> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;
        match self.pages.get(&page_address) {
            Some(page) => Ok(Some(page.load(offset)?)),
            None => Ok(None)
        }
    }


    /// Store an expression at the given address.
    ///
    /// The value must have a bit-width >= 8, and the bit-width must be evenly divisible
    /// by 8.
    pub fn store(&mut self, address: u64, value: V) -> Result<()> {
        if value.bits() % 8 != 0 || value.bits() == 0 {
            return Err(format!("Storing value in symbolic with bit width not divisible by 8 and > 0 {}",
                value.bits()).into());
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

        // If the byte after the last byte is a Backref
        let address_after_write = address + (value.bits() / 8) as u64;

        let write = if let Some(cell) = self.load_cell(address_after_write)? {
            if let MemoryCell::Backref(backref_address) = *cell {
                let value = self.load_cell(backref_address)?
                                .unwrap()
                                .value()
                                .unwrap();
                let value_bits = value.bits();
                let shift_bits = (address_after_write - backref_address) * 8;
                let final_bits = value_bits - shift_bits as usize;
                match self.endian {
                    Endian::Little => {
                        let value = value.shr(shift_bits as usize)?.trun(final_bits)?;
                        Some((address_after_write, value))
                    },
                    Endian::Big => {
                        let value = value.trun(final_bits)?;
                        Some((address_after_write, value))
                    }
                }
            }
            else {
                None
            }
        }
        else {
            None
        };

        if let Some((address, value)) = write {
            let value_bytes = (value.bits() / 8) as u64;
            self.store_cell(address, MemoryCell::Value(value))?;
            for i in 1..value_bytes {
                self.store_cell(address + i, MemoryCell::Backref(address))?;
            }
        }

        // If the first byte of the write is a Backref
        let write = if let Some(cell) = self.load_cell(address)? {
            if let MemoryCell::Backref(backref_address) = *cell {
                let value = self.load_cell(backref_address)?
                                .unwrap()
                                .value()
                                .unwrap();
                let value_bits = value.bits();
                let final_bits = (address - backref_address) as usize * 8;
                let shift_bits = value_bits - final_bits;
                match self.endian {
                    Endian::Little => {
                        let value = value.trun(final_bits)?;
                        Some((backref_address, value))
                    },
                    Endian::Big => {
                        let value = value.shr(shift_bits)?.trun(final_bits)?;
                        Some((backref_address, value))
                    }
                }
            }
            else {
                None
            }
        }
        else {
            None
        };

        if let Some((address, value)) = write {
            self.store(address, value)?;
        }

        // Now store this value and set its backrefs
        let bits = value.bits();
        self.store_cell(address, MemoryCell::Value(value))?;

        for i in 1..(bits / 8) {
            self.store_cell(address + i as u64, MemoryCell::Backref(address))?;
        }

        Ok(())
    }


    /// Loads an expression from the given address.
    ///
    /// `bits` must be >= 8, and evenly divisible by 8.
    /// If a value exists, it will be returned in `Some(expr)`. If no value exists for all
    /// bits at the given address, `None` will be returned.
    pub fn load(&self, address: u64, bits: usize) -> Result<V> {
        if bits % 8 != 0 {
            return Err(format!("Loading symbolic memory with non-8 bit-width {}", bits).into());
        }
        else if bits == 0 {
            return Err("Loading symbolic memory with 0 bit-width".into());
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
        let load_value = if let Some(cell) = self.load_cell(address)? {
            match *cell {
                MemoryCell::Value(ref value) => {
                    if value.bits() <= bits {
                        value.clone()
                    }
                    else {
                        value.trun(bits)?
                    }
                },
                MemoryCell::Backref(backref_address) => {
                    let value = self.load_cell(backref_address)?
                                    .unwrap()
                                    .value()
                                    .unwrap();
                    let value_bits = value.bits();
                    let shift_bits = ((address - backref_address) * 8) as usize;
                    let final_bits = value_bits - shift_bits as usize;
                    let value = match self.endian {
                        Endian::Little => {
                            value.shl(shift_bits)?.trun(final_bits)?
                        },
                        Endian::Big => {
                            value.trun(final_bits)?
                        }
                    };
                    if value.bits() > bits {
                        value.trun(bits)?
                    }
                    else {
                        value
                    }
                }
            }
        }
        else {
            return Ok(V::empty(bits));
        };

        // if we're done, finish
        if load_value.bits() == bits {
            return Ok(load_value);
        }

        // Fall back to single-byte loads
        let mut result = self.load(address, 8)?;
        let bytes = (bits / 8) as u64;
        for offset in 1..bytes {
            let value = self.load(address + offset, 8)?;
            // trace!("LOAD [{:x}]={}", address + offset, expr);
            let value = value.zext(bits)?;
            let shift = match self.endian {
                Endian::Big => (bytes - offset - 1) * 8,
                Endian::Little => offset * 8
            };
            let value = value.shl(shift as usize)?;
            result = result.or(&value)?;
        }

        Ok(result)
    }

    pub fn join(mut self, other: &Memory<V>) -> Result<Memory<V>> {
        // for every page in the other memory
        for other_page in &other.pages {
            let page = match self.pages.get(&other_page.0) {
                // If this page exists in this memory
                Some(this_page) =>
                    // And the two pages are equivalent, clone this page.
                    // It's an RC, so should be a cheap clone.
                    if this_page == other_page.1 {
                        this_page.clone()
                    }
                    else {
                        // We're going to join cell by cell
                        let mut cells = Vec::new();
                        let other_cells = &other_page.1.cells;
                        let this_cells = &this_page.cells;
                        // for every cell
                        for i in 0..this_cells.len() {
                            // if the cells are equal, clone one and push it
                            if this_cells[i] == other_cells[i] {
                                cells.push(this_cells[i].clone());
                                continue;
                            }

                            // If both cells are values, and they're the same bit-size, join
                            // them and push the result
                            if let Some(this_value) = this_cells[i].value() {
                                if let Some(other_value) = other_cells[i].value() {
                                    if this_value.bits() == other_value.bits() {
                                        // join them and store the value
                                        let value = this_value.join(other_value)?;
                                        cells.push(MemoryCell::Value(value));
                                        continue;
                                    }
                                }
                            }

                            // Otherwise get 8-bit values from both pages, join, push
                            let address = other_page.0 + i as u64;
                            let this_value = self.load(address, 8)?;
                            let other_value = other.load(address, 8)?;
                            cells.push(MemoryCell::Value(this_value.join(&other_value)?));
                        }
                        RC::new(Page::new_with_cells(PAGE_SIZE, cells))
                    },
                // This page does not exist here, clone other page
                None => other_page.1.clone()
            };
            self.pages.insert(*other_page.0, page);
        }
        Ok(self)
    }
}