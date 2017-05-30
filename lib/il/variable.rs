use il::*;
use std::cell::RefCell;
use std::rc::Rc;


#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Variable {
    Array(Rc<RefCell<Array>>),
    Scalar(Rc<RefCell<Scalar>>)
}


impl Variable {
    pub fn array(array: Rc<RefCell<Array>>) -> Variable {
        Variable::Array(array)
    }

    pub fn scalar(scalar: Rc<RefCell<Scalar>>) -> Variable {
        Variable::Scalar(scalar)
    }

    pub fn name(&self) -> String {
        match *self {
            Variable::Array(ref array) => array.borrow().name().to_string(),
            Variable::Scalar(ref scalar) => scalar.borrow().name().to_string()
        }
    }

    pub fn bits(&self) -> usize {
        match *self {
            Variable::Array(_) => 8,
            Variable::Scalar(ref scalar) => scalar.borrow().bits()
        }
    }

    pub fn ssa(&self) -> Option<u32> {
        match *self {
            Variable::Array(ref array) => array.borrow().ssa(),
            Variable::Scalar(ref scalar) => scalar.borrow().ssa()
        }
    }

    pub fn set_ssa(&mut self, ssa: Option<u32>) {
        match *self {
            Variable::Array(ref mut array) => array.borrow_mut().set_ssa(ssa),
            Variable::Scalar(ref mut scalar) => scalar.borrow_mut().set_ssa(ssa)
        }
    }
}


impl ::std::fmt::Display for Variable {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            Variable::Array(ref array) => array.borrow().fmt(f),
            Variable::Scalar(ref scalar) => scalar.borrow().fmt(f)
        }
    }
}