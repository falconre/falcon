use executor::engine::Engine;
use il;


#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Raise(il::Expression)
}


#[derive(Clone)]
pub struct Successor<'s> {
    engine: Engine<'s>,
    type_: SuccessorType
}


impl<'s> Successor<'s> {
    pub(crate) fn new(engine: Engine<'s>, type_: SuccessorType) -> Successor<'s> {
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


impl<'e> Into<Engine<'e>> for Successor<'e> {
    fn into(self) -> Engine<'e> {
        self.engine
    }
}