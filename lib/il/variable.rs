use il::*;
use std::fmt;


pub trait Variable : fmt::Debug + fmt::Display {
    fn ssa(&self) -> Option<u32>;
    fn set_ssa(&mut self, ssa: Option<u32>);
    fn name(&self) -> &str;
    fn identifier(&self) -> String;
    fn multi_var_clone(&self) -> MultiVar;
}


/// Holds multiple types of variables.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MultiVar {
    Array(Array),
    Scalar(Scalar)
}


impl Variable for MultiVar {
    fn identifier(&self) -> String {
        match *self {
            MultiVar::Array(ref array) => array.identifier(),
            MultiVar::Scalar(ref scalar) => scalar.identifier()
        }
    }

    fn name(&self) -> &str {
        match *self {
            MultiVar::Array(ref array) => array.name(),
            MultiVar::Scalar(ref scalar) => scalar.name()
        }
    }

    fn ssa(&self) -> Option<u32> {
        match *self {
            MultiVar::Array(ref array) => array.ssa(),
            MultiVar::Scalar(ref scalar) => scalar.ssa()
        }
    }

    fn set_ssa(&mut self, ssa: Option<u32>) {
        match *self {
            MultiVar::Array(ref mut array) => array.set_ssa(ssa),
            MultiVar::Scalar(ref mut scalar) => scalar.set_ssa(ssa)
        }
    }

    fn multi_var_clone(&self) -> MultiVar {
        self.clone()
    }
}


impl<'v> Into<MultiVar> for &'v Variable {
    fn into(self) -> MultiVar {
        self.multi_var_clone()
    }
}


impl fmt::Display for MultiVar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MultiVar::Array(ref array) => array.fmt(f),
            MultiVar::Scalar(ref scalar) => scalar.fmt(f)
        }
    }
}