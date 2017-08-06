//! An `Array` is designed to represent memory locations.
//!
//! Arrays are used to represent memory. Typically, we will just use one array to represent
//! all of addressable memory space. Using a variable to explicitly identify memory allows for
//! things like, "Versioned," memory, or applying SSA to memory accesses.
//!
//! Falcon's IL does not support things like passing an `Array` in a `Scalar`, or
//! an index into to an `Array` through a `Scalar`. This prevents certain interesting types
//! of analyses, and may change in future iterations of the IL.

use std::fmt;
use il::*;

/// An Array in Falcon IL
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Array {
    name: String,
    size: u64,
    ssa: Option<u32>
}


impl Array {
    /// Create a new array.
    ///
    /// Size is the size of the `Array` in bytes. This does not trigger an allocation, but
    /// sets the, "Size," of the `Array`.
    pub fn new<S>(name: S, size: u64) -> Array where S: Into<String> {
        Array {
            name: name.into(),
            size: size,
            ssa: None
        }
    }

    /// Get the size of the `Array`.
    pub fn size(&self) -> u64 {
        self.size
    }
}


impl Variable for Array {
    fn name(&self) -> &str {
        &self.name
    }

    /// An identifier uniquely identifies the variable in the form
    /// `<name>[]#<ssa>`
    fn identifier(&self) -> String {
        format!(
            "{}[]{}",
            self.name,
            match self.ssa {
                Some(ssa) => format!("#{}", ssa),
                None => String::new()
        })
    }

    fn ssa(&self) -> Option<u32> {
        self.ssa
    }

    fn set_ssa(&mut self, ssa: Option<u32>) {
        self.ssa = ssa;
    }

    fn multi_var_clone(&self) -> MultiVar {
        MultiVar::Array(self.clone())
    }
}



impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}