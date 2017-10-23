//! A symbolic memory model.
//!
//! Each cell of `SymbolicMemory` is a valid `il::Expr`. Concrete values may be stored as
//! `il::Constant`, and symbolic values stored as valid expressions.
//!
//! `SymbolicMemory` is paged under-the-hood with reference-counted pages. When these pages
//! are written to, we use the copy-on-write functionality of rust's `std::rc::Rc` type,
//! giving us copy-on-write paging. This allows for very fast forks of `SymbolicMemory`.

use error::*;
use il;
use RC;
use types::Endian;
use std::collections::BTreeMap;


const PAGE_SIZE: usize = 4092;


/// We would prefer to avoid splitting values when reading/writing memory values
/// > 1 byte to memory. One way we can do this is by enabling memory to hold values
/// > 1 byte in length. Yeah, no, I'm sure this will work out well.
/// Every memory location will hold either an expression, or a Backref, which is
/// an address of the beginning of an expression which extends to this address.
///
/// If we get this right, it should be pretty awesome. _If_we_get_this_right_.
#[derive(Clone, Debug, Deserialize, Serialize)]
enum MemoryCell {
    Expression(il::Expression),
    Backref(u64)
}

impl MemoryCell {
    fn expression(&self) -> Option<&il::Expression> {
        match self {
            &MemoryCell::Expression(ref expr) => Some(expr),
            &MemoryCell::Backref(_) => None
        }
    }
}


#[derive(Clone, Debug, Deserialize, Serialize)]
struct Page {
    size: usize,
    cells: Vec<MemoryCell>
}


impl Page {
    fn new(size: usize) -> Page {
        let mut v = Vec::new();
        for _ in 0..size {
            v.push(MemoryCell::Expression(il::expr_const(0, 8)));
        }

        Page {
            size: size,
            cells: v
        }
    }

    fn store(&mut self, offset: usize, cell: MemoryCell) -> Result<()> {
        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        self.cells.as_mut_slice()[offset] = cell;

        Ok(())
    }

    fn load(&self, offset: usize) -> Result<&MemoryCell> {
        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        Ok(&self.cells[offset])
    }
}


/// A symbolic memory model for Falcon IL expressions.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Memory {
    endian: Endian,
    pages: BTreeMap<u64, RC<Page>>
}


impl Memory {
    /// Create a new `SymbolicMemory`.
    pub fn new(endian: Endian) -> Memory {
        Memory {
            endian: endian,
            pages: BTreeMap::new()
        }
    }

    /// Get the endianness of this `SymbolicMemory`.
    pub fn endian(&self) -> &Endian {
        &self.endian
    }


    fn store_cell(&mut self, address: u64, cell: MemoryCell) -> Result<()> {
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


    fn load_cell(&self, address: u64) -> Result<Option<&MemoryCell>> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;
        match self.pages.get(&page_address) {
            Some(page) => Ok(Some(page.load(offset)?)),
            None => Ok(None)
        }
    }


    fn store_no_backref(&mut self, address: u64, value: il::Expression) -> Result<()> {
        let bytes = value.bits() / 8;
        self.store_cell(address, MemoryCell::Expression(value))?;
        for i in 1..bytes {
            self.store_cell(address + i as u64, MemoryCell::Backref(address))?;
        }
        Ok(())
    }


    /// Store an expression at the given address.
    ///
    /// The value must have a bit-width >= 8, and the bit-width must be evenly divisible
    /// by 8.
    pub fn store(&mut self, address: u64, value: il::Expression) -> Result<()> {
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

        let expr_to_write =
            if let Some(cell) = self.load_cell(address_after_write)? {
                if let MemoryCell::Backref(backref_address) = *cell {
                    let backref_expr = self.load_cell(backref_address)?
                                           .unwrap()
                                           .expression()
                                           .unwrap();
                    let backref_furthest_address = backref_address + (backref_expr.bits() / 8) as u64;
                    let left_bits = ((backref_furthest_address - address_after_write) * 8) as usize;
                    Some(self.load(address_after_write, left_bits)?.unwrap())
                }
                else {
                    None
                }
            }
            else {
                None
            };

        if let Some(expr_to_write) = expr_to_write {
            self.store_no_backref(address_after_write, expr_to_write)?;
        }

        let expr_to_write =
            if let Some(cell) = self.load_cell(address)? {
                if let MemoryCell::Backref(backref_address) = *cell {
                    let backref_expr = self.load_cell(backref_address)?
                                           .unwrap()
                                           .expression()
                                           .unwrap();
                    let backref_furthest_address = backref_address + (backref_expr.bits() / 8) as u64;
                    let overwrite_bits = (backref_furthest_address - address) * 8;
                    let left_bits = backref_expr.bits() - overwrite_bits as usize;
                    Some((backref_address, self.load(backref_address, left_bits)?.unwrap()))
                }
                else {
                    None
                }
            }
            else {
                None
            };

        if let Some(expr_to_write) = expr_to_write {
            self.store_no_backref(expr_to_write.0, expr_to_write.1)?;
        }

        self.store_no_backref(address, value)
    }


    /// Loads an expression from the given address.
    ///
    /// `bits` must be >= 8, and evenly divisible by 8.
    /// If a value exists, it will be returned in `Some(expr)`. If no value exists for all
    /// bits at the given address, `None` will be returned.
    pub fn load(&self, address: u64, bits: usize) -> Result<Option<il::Expression>> {
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
        let load_expr = if let Some(cell) = self.load_cell(address)? {
            match *cell {
                MemoryCell::Expression(ref expr) => {
                    if expr.bits() <= bits {
                        expr.clone()
                    }
                    else {
                        match self.endian {
                            Endian::Little => il::Expression::trun(bits, expr.clone())?,
                            Endian::Big => il::Expression::trun(
                                bits,
                                il::Expression::shr(
                                    expr.clone(),
                                    il::expr_const((expr.bits() - bits) as u64, expr.bits())
                                )?
                            )?
                        }
                    }
                },
                MemoryCell::Backref(backref_address) => {
                    let expr = self.load_cell(backref_address)?
                                   .unwrap()
                                   .expression()
                                   .unwrap();
                    let expr = match self.endian {
                        Endian::Little => {
                            let shift_bits = ((address - backref_address) * 8) as usize;
                            il::Expression::trun(
                                bits,
                                il::Expression::shr(
                                    expr.clone(),
                                    il::expr_const(shift_bits as u64, expr.bits())
                                )?
                            )?
                        },
                        Endian::Big => {
                            let offset = ((address - backref_address) * 8) as usize;
                            let shift_bits = expr.bits() - bits - offset;
                            il::Expression::trun(
                                bits,
                                il::Expression::shr(
                                    expr.clone(),
                                    il::expr_const(shift_bits as u64, expr.bits())
                                )?
                            )?
                        }
                    };
                    if expr.bits() > bits {
                        il::Expression::trun(bits, expr)?
                    }
                    else {
                        expr
                    }
                }
            }
        }
        else {
            return Ok(None);
        };

        if load_expr.bits() == bits {
            return Ok(Some(load_expr));
        }

        let mut result: Option<il::Expression> = None;
        let bytes = (bits / 8) as u64;
        for offset in 0..bytes {
            let expr = match self.load(address + offset, 8)? {
                Some(expr) => expr,
                None => return Ok(None)
            };
            let expr = il::Expression::zext(bits, expr)?;
            let shift = match self.endian {
                Endian::Big => (bytes - offset - 1) * 8,
                Endian::Little => offset * 8
            };
            let expr_bits = expr.bits();
            let expr = il::Expression::shl(expr, il::expr_const(shift, expr_bits))?;
            result = match result {
                Some(result) => Some(il::Expression::or(result, expr)?),
                None => Some(expr)
            };
        }

        Ok(result)
    }
}


#[cfg(test)]
mod memory_tests {
    use executor::eval;
    use il;
    use symbolic::memory::Memory;
    use types::Endian;

    #[test]
    fn symbolc_memory_big_endian() {
        let mut memory = Memory::new(Endian::Big);

        memory.store(0x100, il::expr_const(0xaabbccdd, 32)).unwrap();

        assert_eq!(
            eval(&memory.load(0x100, 32).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaabbccdd, 32)).unwrap()
        );

        assert_eq!(
            eval(&memory.load(0x100, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaa, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x101, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xbb, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x102, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xcc, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x103, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xdd, 8)).unwrap()
        );

        memory.store(0x102, il::expr_const(0xFF, 8)).unwrap();

        assert_eq!(
            eval(&memory.load(0x100, 32).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaabbffdd, 32)).unwrap()
        );

        assert_eq!(
            eval(&memory.load(0x100, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaa, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x101, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xbb, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x102, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xff, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x103, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xdd, 8)).unwrap()
        );
    }

    #[test]
    fn ai_memory_little_endian() {
        let mut memory = Memory::new(Endian::Little);

        memory.store(0x100, il::expr_const(0xaabbccdd, 32)).unwrap();

        assert_eq!(
            eval(&memory.load(0x100, 32).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaabbccdd, 32)).unwrap()
        );

        assert_eq!(
            eval(&memory.load(0x100, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xdd, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x101, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xcc, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x102, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xbb, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x103, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaa, 8)).unwrap()
        );

        memory.store(0x102, il::expr_const(0xff, 8)).unwrap();

        assert_eq!(
            eval(&memory.load(0x100, 32).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaaffccdd, 32)).unwrap()
        );

        assert_eq!(
            eval(&memory.load(0x100, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xdd, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x101, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xcc, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x102, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xff, 8)).unwrap()
        );
        assert_eq!(
            eval(&memory.load(0x103, 8).unwrap().unwrap()).unwrap(),
            eval(&il::expr_const(0xaa, 8)).unwrap()
        );       
    }
}