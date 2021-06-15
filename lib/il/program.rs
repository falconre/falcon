//! A `Program` holds multiple `Function`.

use crate::il::*;
use crate::RC;
use std::collections::BTreeMap;
use std::fmt;

/// A representation of a program by `il::Function`
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Program {
    // Mapping of function indices (not addresses) to `Function`.
    functions: BTreeMap<usize, RC<Function>>,
    // The next index to assign to a function when added to the program.
    next_index: usize,
}

impl Program {
    /// Creates a new, empty `Program`.
    pub fn new() -> Program {
        Program {
            functions: BTreeMap::new(),
            next_index: 0,
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
    pub fn functions_map(&self) -> BTreeMap<usize, &Function> {
        self.functions
            .iter()
            .map(|(index, function)| (*index, function.as_ref()))
            .collect::<BTreeMap<usize, &Function>>()
    }

    /// Get a `Function` by its index.
    ///
    /// A `Function` index is assigned by `Program` and is not the address where the `Function`
    /// was discovered.
    pub fn function(&self, index: usize) -> Option<&Function> {
        self.functions.get(&index).map(|f| f.as_ref())
    }

    /// Add a `Function` to the `Program`.
    ///
    /// This will also assign an index to the `Function`.
    pub fn add_function(&mut self, mut function: Function) {
        function.set_index(Some(self.next_index));
        self.functions.insert(self.next_index, RC::new(function));
        self.next_index += 1;
    }

    /// Get a `Function` by its name.
    pub fn function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions
            .iter()
            .find(|(_, function)| function.name() == name)
            .map(|(_, function)| function.as_ref())
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
