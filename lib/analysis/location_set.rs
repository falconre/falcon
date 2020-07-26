/// A Partially-Ordered set of program locations for data-flow analysis.
use crate::il;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::collections::HashSet;

/// A partially-ordered set of `RefProgramLocation` used in analyses
#[derive(Clone, Debug, Default)]
pub struct LocationSet {
    pub locations: HashSet<il::ProgramLocation>,
}

impl LocationSet {
    pub fn new() -> LocationSet {
        LocationSet {
            locations: HashSet::new(),
        }
    }

    pub fn contains(&self, location: &il::ProgramLocation) -> bool {
        self.locations.contains(location)
    }

    pub fn insert(&mut self, location: il::ProgramLocation) {
        self.locations.insert(location);
    }

    pub fn len(&self) -> usize {
        self.locations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    pub fn locations(&self) -> &HashSet<il::ProgramLocation> {
        &self.locations
    }

    pub fn remove(&mut self, location: &il::ProgramLocation) {
        self.locations.remove(location);
    }
}

impl PartialOrd for LocationSet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.locations.len().cmp(&other.locations.len()) {
            Ordering::Equal => {
                for rpl in &self.locations {
                    if !other.locations.contains(rpl) {
                        return None;
                    }
                }
                Some(Ordering::Equal)
            }
            Ordering::Less => {
                for rpl in &self.locations {
                    if !other.locations.contains(rpl) {
                        return None;
                    }
                }
                Some(Ordering::Less)
            }
            Ordering::Greater => {
                for rpl in &other.locations {
                    if !self.locations.contains(rpl) {
                        return None;
                    }
                }
                Some(Ordering::Greater)
            }
        }
    }
}

impl PartialEq for LocationSet {
    fn eq(&self, other: &Self) -> bool {
        Some(Ordering::Equal) == self.partial_cmp(other)
    }
}
