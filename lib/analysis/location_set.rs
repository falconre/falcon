/// A Partially-Ordered set of program locations for data-flow analysis.
use crate::il;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::collections::HashSet;

/// A partially-ordered set of `RefProgramLocation` used in analyses
#[derive(Clone, Debug)]
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
        if self.locations.len() == other.locations.len() {
            for rpl in &self.locations {
                if !other.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Equal)
        } else if self.locations.len() < other.locations.len() {
            for rpl in &self.locations {
                if !other.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Less)
        } else {
            for rpl in &other.locations {
                if !self.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Greater)
        }
    }
}

impl PartialEq for LocationSet {
    fn eq(&self, other: &Self) -> bool {
        if let Some(ordering) = self.partial_cmp(other) {
            if ordering == Ordering::Equal {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}
