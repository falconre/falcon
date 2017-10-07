use executor::*;
use il;
use std::collections::BTreeMap;
use translator::TranslationMemory;
use types::Endian;

#[derive(Clone)]
pub struct Memory {
    cells: BTreeMap<u64, u8>,
    endian: Endian
}


impl Memory {
    pub fn new(endian: Endian) -> Memory {
        Memory {
            cells: BTreeMap::new(),
            endian: endian
        }
    }


    pub fn endian(&self) -> &Endian {
        &self.endian
    }


    pub fn store(&mut self, address: u64, value: il::Expression) -> Result<()> {
        if value.bits() == 0 {
            bail!("Attempted to store an expression with 0 bits");
        }
        else if value.bits() & 7 > 0 {
            bail!("Attempted to store an expression not evenly divisible by 8");
        }
        else if value.bits() == 8 {
            self.cells.insert(address, eval(&value)?.value() as u8);
            Ok(())
        }
        else {
            for i in 0..(value.bits() as u64 / 8) {
                let expr = match self.endian {
                    Endian::Big => il::Expression::trun(
                        8,
                        il::Expression::shr(
                            value.clone(),
                            il::expr_const(value.bits() as u64 - (i + 1) * 8, value.bits())
                        )?
                    )?,
                    Endian::Little => il::Expression::trun(
                        8,
                        il::Expression::shr(
                            value.clone(),
                            il::expr_const(i * 8, value.bits())
                        )?
                    )?
                };

                let cell_value = eval(&expr)?.value() as u8;
                self.cells.insert(address + i, cell_value);
            }

            Ok(())
        }
    }


    pub fn load(&self, address: u64, bits: usize) -> Result<Option<il::Expression>> {
        if bits == 0 {
            bail!("Attempted to load an expression with 0 bits");
        }
        else if bits & 7 > 0 {
            bail!("Attempted to load an expression not evenly divisible by 8");
        }

        let mut value: u64 = 0;
        for i in 0..(bits as u64 / 8) {
            value |= match self.cells.get(&(address + i)) {
                Some(v) => match self.endian {
                    Endian::Big => (*v as u64) << (bits as u64 - (i + 1) * 8),
                    Endian::Little => (*v as u64) << (i * 8)
                },
                None => return Ok(None)
            };
        }

        Ok(Some(il::expr_const(value, bits)))
    }
}


impl TranslationMemory for Memory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        match self.load(address, 8).unwrap() {
            Some(expr) => Some(eval(&expr).unwrap().value() as u8),
            None => None
        }
    }
}