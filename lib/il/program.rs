//! A `Program` holds multiple `Function`.

use il::*;
use std::collections::BTreeMap;
use std::fmt;

/// A representation of a program by `il::Function`
#[derive(Clone, Debug, Deserialize, Hash, Serialize)]
pub struct Program {
    // Mapping of function indices (not addresses) to `Function`.
    functions: BTreeMap<u64, Function>,
    // The next index to assign to a function when added to the program.
    next_index: u64
}


impl Program {
    /// Creates a new, empty `Program`.
    pub fn new() -> Program {
        Program {
            functions: BTreeMap::new(),
            next_index: 0
        }
    }

    /// Search for a `Function` by its optional address, assuming one was assigned.
    /// Returns the `Function` if found, or `None` if not found.
    pub fn function_by_address(&self, address: u64) -> Option<&Function> {
        for function in &self.functions {
            if function.1.address() == address {
                return Some(function.1);
            }
        }
        None
    }

    /// Get all `Function` for this `Program`.
    pub fn functions(&self) -> Vec<&Function> {
        let mut v = Vec::new();
        for f in &self.functions {
            let f: &Function = &f.1;
            v.push(f);
        }
        v
    }


    /// Get the underlying BTreeMap holding all `Function` for this `Program`.
    pub fn functions_map(&self) -> &BTreeMap<u64, Function> {
        &self.functions
    }


    /// Get a `Function` by its index.
    ///
    /// A `Function` index is assigned by `Program` and is not the address where the `Function`
    /// was discovered.
    pub fn function(&self, index: u64) -> Option<&Function> {
        match self.functions.get(&index) {
            Some(f) => Some(f),
            None => None
        }
    }


    /// Returns a `Rc<Function>` by it's index.
    pub fn function_rc(&self, index: u64) -> Option<Function> {
        match self.functions.get(&index) {
            Some(f) => Some(f.clone()),
            None => None
        }
    }


    /// Add a `Function` to the `Program`.
    ///
    /// This will also assign an index to the `Function`.
    pub fn add_function(&mut self, mut function: Function) {
        function.set_index(Some(self.next_index));
        self.functions.insert(self.next_index, function);
        self.next_index += 1;
    }
}


impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for function in &self.functions {
            writeln!(f, "{}@{:08X}", function.1.name(), function.0)?
        }
        Ok(())
    }
}