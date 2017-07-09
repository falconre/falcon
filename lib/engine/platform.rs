use il;
use engine::engine::*;

pub trait Platform {
    fn raise(
        &self,
        expression: &il::Expression,
        engine: SymbolicEngine
    ) -> Vec<SymbolicSuccessor>;
}


#[derive(Clone)]
pub struct PlatformCGC;


/// For the CGC Platform, we will always translate system calls as such:
/// terminate:  1
/// transmit:   2
/// receive:    3
/// fdwait:     4
/// allocate:   5
/// deallocate: 6
/// random:     7

impl PlatformCGC {
    pub fn raise(&self, expression: &il::Expression, engine: SymbolicEngine)
        -> Vec<SymbolicSuccessor> {
        
        /*
        if let Expression::Constant(ref c) = *expression {
            match c.value() {
                0 => Vec::new(),
                1 => vec![SymbolicSuccessor(engine, SuccessorType::FallThrough)],
                2 => {
                    let ebx = 
                }
            }
        }
        */

        Vec::new()
    }
}