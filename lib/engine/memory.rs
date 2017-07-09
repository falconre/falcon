use error::*;
use il;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum Endianness {
    Big,
    Little
}

#[derive(Clone)]
pub struct SymbolicMemory {
    address_width: usize,
    endianness: Endianness,
    cells: BTreeMap<u64, il::Expression>
}


impl SymbolicMemory {
    pub fn new(address_width: usize, endianness: Endianness) -> SymbolicMemory {
        SymbolicMemory {
            address_width: address_width,
            endianness: endianness,
            cells: BTreeMap::new()
        }
    }


    pub fn address_width(&self) -> usize {
        self.address_width
    }


    pub fn endianness(&self) -> &Endianness {
        &self.endianness
    }


    pub fn cells(&self) -> &BTreeMap<u64, il::Expression> {
        &self.cells
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
                let shift = match self.endianness {
                    Endianness::Little => offset * 8,
                    Endianness::Big => (bytes as u64 - offset) * 8
                };
                let shift = il::expr_const(shift, value.bits());
                let value = il::Expression::shr(value.clone(), shift)?;
                let value = il::Expression::trun(8, value)?;
                self.cells.insert(address + offset, value);
            }
        }
        else if value.bits() == 8 {
            self.cells.insert(address, value);
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
            return Err(format!("Loading symbolic memory with non-8 bit-width {}",
                bits).into());
        }
        else if bits == 0 {
            return Err("Loading symbolic memory with 0 bit-width".into());
        }

        let mut result = None;
        let bytes = (bits / 8) as u64;
        for offset in 0..bytes {
            let expr = match self.cells.get(&(address + offset)) {
                Some(ref expr) => *expr,
                None => return Ok(None)
            };
            let expr = il::Expression::zext(bits, expr.clone())?;
            let shift = match self.endianness {
                Endianness::Little => (bytes - offset) * 8,
                Endianness::Big => offset * 8
            };
            let shift = il::expr_const(shift, bits);
            let expr = il::Expression::shl(shift, expr)?;
            result = match result {
                Some(result) => Some(il::Expression::or(result, expr)?),
                None => Some(expr)
            };
        }

        Ok(result)
    }
}