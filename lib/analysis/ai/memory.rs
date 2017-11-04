use error::*;
use memory::paged;
use memory;
use RC;
use types::Endian;
use std::fmt::Debug;


pub trait Value: memory::value::Value + Clone + Debug + Eq + PartialEq {
    /// Join two values together
    fn join(&self, other: &Self) -> Result<Self>;

    /// Return an empty value
    fn empty(bits: usize) -> Self;
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Memory<'m, V: Value>(paged::Memory<'m, V>);

impl<'m, V> Memory<'m, V> where V: Value {
    pub fn new(endian: Endian) -> Memory<'m, V> {
        Memory(paged::Memory::new(endian))
    }


    pub fn new_with_backing(endian: Endian, backing: &'m memory::backing::Memory)
        -> Memory<'m, V> {
            Memory(paged::Memory::new_with_backing(endian, backing))
        }


    pub fn store(&mut self, address: u64, value: V) -> Result<()> {
        self.0.store(address, value)
    }


    pub fn load(&self, address: u64, bits: usize) -> Result<V> {
        Ok(match self.0.load(address, bits)? {
            Some(v) => v,
            None => V::empty(bits)
        })
    }


    pub fn join(mut self, other: &Memory<V>) -> Result<Memory<'m, V>> {
        // for every page in the other memory
        for other_page in &other.0.pages {
            let page = match self.0.pages.get(&other_page.0) {
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
                            if let Some(this_value) = this_cells[i].as_ref()
                                                                   .and_then(|ref c| c.value()) {
                                if let Some(other_value) = other_cells[i].as_ref()
                                                                         .and_then(|ref c| c.value()) {
                                    if memory::value::Value::bits(this_value) == other_value.bits() {

                                        // join them and store the value
                                        let value = this_value.join(other_value)?;
                                        cells.push(Some(paged::MemoryCell::Value(value)));
                                        continue;
                                    }
                                }
                            }

                            let address = other_page.0 + i as u64;

                            let this_value = self.load(address, 8)?;
                            let other_value = other.load(address, 8)?;
                            cells.push(Some(paged::MemoryCell::Value(this_value.join(&other_value)?)));
                        }
                        RC::new(paged::Page::new_with_cells(cells))
                    },
                // This page does not exist here, clone other page
                None => other_page.1.clone()
            };
            self.0.pages.insert(*other_page.0, page);
        }
        Ok(self)
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

        memory.store(0x100, value.clone()).unwrap();

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

        memory.store(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

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
        let memory = memory.join(&other_memory).unwrap();

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xaabbffdd, 32)));        
    }

    #[test]
    fn ai_memory_little_endian() {
        let mut memory: Memory<KSet> = Memory::new(Endian::Little);

        let value = KSet::constant(il::const_(0xAABBCCDD, 32));

        memory.store(0x100, value.clone()).unwrap();

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

        memory.store(0x102, KSet::constant(il::const_(0xFF, 8))).unwrap();

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

        assert_eq!(memory.load(0x100, 32).unwrap(), KSet::constant(il::const_(0xAAFFCCDD, 32)));        
    }
}