use il::*;
use serde;
use std::cell::RefCell;
use std::hash::Hash;
use std::fmt;
use std::rc::Rc;


pub trait Variable : Clone + serde::de::DeserializeOwned + fmt::Debug + 
                     fmt::Display + Eq + Hash + Ord + PartialEq + PartialOrd +
                     serde::Serialize {
    fn bits(&self) -> usize;
    fn ssa(&self) -> Option<u32>;
    fn set_ssa(&mut self, ssa: Option<u32>);
}


/// Holds multiple types of variables.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MultiVar {
    Array(Array),
    Scalar(Scalar)
}


impl Variable for MultiVar {
    fn bits(&self) -> usize {
        match *self {
            MultiVar::Array(ref array) => array.bits(),
            MultiVar::Scalar(ref scalar) => scalar.bits()
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
}


impl fmt::Display for MultiVar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MultiVar::Array(ref array) => array.fmt(f),
            MultiVar::Scalar(ref scalar) => scalar.fmt(f)
        }
    }
}