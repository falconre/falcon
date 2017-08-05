use error::*;
use il;
use std::collections::BTreeMap;
use std::rc::Rc;


const PAGE_SIZE: usize = 1024;


#[derive(Clone, Debug)]
pub enum Endian {
    Big,
    Little
}


#[derive(Clone)]
struct SymbolicPage {
    size: usize,
    cells: Vec<il::Expression>
}


impl SymbolicPage {
    fn new(size: usize) -> SymbolicPage {
        let mut v = Vec::new();
        for i in 0..size {
            v.push(il::expr_const(0, 8));
        }

        SymbolicPage {
            size: size,
            cells: v
        }
    }

    fn store(&mut self, offset: usize, value: il::Expression) -> Result<()> {
        if value.bits() != 8 {
            bail!("SymbolicPage tried to store value with bits={}", value.bits());
        }

        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        self.cells.as_mut_slice()[offset] = value;

        Ok(())
    }

    fn load(&self, offset: usize) -> Result<il::Expression> {
        if offset >= self.size {
            bail!("Out of bounds offset {} for SymbolicPage with size {}", offset, self.size);
        }

        Ok(self.cells[offset].clone())
    }
}


#[derive(Clone)]
pub struct SymbolicMemory {
    address_width: usize,
    endian: Endian,
    pages: BTreeMap<u64, Rc<SymbolicPage>>
}


impl SymbolicMemory {
    pub fn new(address_width: usize, endian: Endian) -> SymbolicMemory {
        SymbolicMemory {
            address_width: address_width,
            endian: endian,
            pages: BTreeMap::new()
        }
    }


    pub fn address_width(&self) -> usize {
        self.address_width
    }


    pub fn endian(&self) -> &Endian {
        &self.endian
    }


    fn store_byte(&mut self, address: u64, value: il::Expression) -> Result<()> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;

        if let Some(mut page) = self.pages.get_mut(&page_address) {
            Rc::make_mut(&mut page).store(offset, value)?;
            return Ok(())
        }

        let mut page = SymbolicPage::new(PAGE_SIZE);
        page.store(offset, value)?;
        self.pages.insert(page_address, Rc::new(page));

        Ok(())
    }


    fn load_byte(&self, address: u64) -> Result<Option<il::Expression>> {
        let page_address = address & !(PAGE_SIZE as u64 - 1);
        let offset = (address & (PAGE_SIZE as u64 - 1)) as usize;
        match self.pages.get(&page_address) {
            Some(page) => Ok(Some(page.load(offset)?)),
            None => Ok(None)
        }
    }


    pub fn store(&mut self, address: u64, value: il::Expression) -> Result<()> {
        if value.bits() % 8 != 0 {
            return Err(format!("Storing value in symbolic with bit width not divisible by 8 {}",
                value.bits()).into());
        }
        if value.bits() > 8 {
            let bytes = value.bits() / 8;
            for offset in 0..bytes {
                let offset = offset as u64;
                let shift = match self.endian {
                    Endian::Big => (bytes as u64 - offset - 1) * 8,
                    Endian::Little => offset * 8
                };
                let shift = il::expr_const(shift, value.bits());
                let value = il::Expression::shr(value.clone(), shift)?;
                let value = il::Expression::trun(8, value)?;
                // trace!("STORE [{:x}]={}", address + offset, value);
                self.store_byte(address + offset, value)?;
            }
        }
        else if value.bits() == 8 {
            self.store_byte(address, value)?;
        }
        else {
            return Err(format!("Invalid bit width in symbolic memory store: {}",
                value.bits()).into());
        }
        Ok(())
    }


    /// Errors if the address is invalid (bits == 0 or bits % 8 != 0)
    /// Returns None if no value is at the given address.
    pub fn load(&self, address: u64, bits: usize) -> Result<Option<il::Expression>> {
        if bits % 8 != 0 {
            Err(format!("Loading symbolic memory with non-8 bit-width {}", bits).into())
        }
        else if bits == 0 {
            Err("Loading symbolic memory with 0 bit-width".into())
        }
        else if bits == 8 {
            match self.load_byte(address)? {
                Some(expr) => Ok(Some(expr.clone())),
                None => Ok(None)
            }
        }
        else {
            let mut result = None;
            let bytes = (bits / 8) as u64;
            for offset in 0..bytes {
                let expr = match self.load_byte((address + offset))? {
                    Some(expr) => expr,
                    None => return Ok(None)
                };
                // trace!("LOAD [{:x}]={}", address + offset, expr);
                let expr = il::Expression::zext(bits, expr.clone())?;
                let shift = match self.endian {
                    Endian::Big => (bytes - offset - 1) * 8,
                    Endian::Little => offset * 8
                };
                let shift = il::expr_const(shift, bits);
                let expr = il::Expression::shl(expr, shift)?;
                result = match result {
                    Some(result) => Some(il::Expression::or(result, expr)?),
                    None => Some(expr)
                };
            }

            Ok(result)
        }
    }
}