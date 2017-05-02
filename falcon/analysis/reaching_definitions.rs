use analysis::fixed_point::*;
use il::*;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq)]
struct ReachChain {
    chain: BTreeMap<Variable, (u64, u64)>
}


impl FixedPointAnalysis<ReachChain> for ReachChain {
    fn initial(block: &Block) -> ReachChain {
        ReachChain {
            chain: BTreeMap::new()
        }
    }

    fn trans(block: &Block, state: &ReachChain) -> ReachChain {
        state.clone()
    }

    fn join(state0: &ReachChain, state1: &ReachChain)
    -> ReachChain {
        state0.clone()
    }
}