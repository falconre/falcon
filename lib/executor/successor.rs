use executor::engine::Engine;
use il;


#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Raise(il::Expression)
}


#[derive(Clone)]
pub struct Successor {
    engine: Engine,
    type_: SuccessorType
}


impl Successor {
    pub(crate) fn new(engine: Engine, type_: SuccessorType) -> Successor {
        Successor {
            engine: engine,
            type_: type_
        }
    }


    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }


    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}


impl Into<Engine> for Successor {
    fn into(self) -> Engine {
        self.engine
    }
}