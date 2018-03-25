/// A Partially-Ordered set of program locations for data-flow analysis.

use il;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::collections::HashSet;


/// A partially-ordered set of `RefProgramLocation` used in analyses
#[derive(Clone, Debug)]
pub struct LocationSet<'r> {
    pub locations: HashSet<il::RefProgramLocation<'r>>
}

impl<'r> LocationSet<'r> {
    pub fn new() -> LocationSet<'r> {
        LocationSet {
            locations: HashSet::new()
        }
    }

    pub fn contains(&self, location: &il::RefProgramLocation<'r>) -> bool {
        self.locations.contains(location)
    }

    pub fn insert(&mut self, location: il::RefProgramLocation<'r>) {
        self.locations.insert(location);
    }

    pub fn len(&self) -> usize {
        self.locations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    pub fn locations(&self) -> &HashSet<il::RefProgramLocation<'r>> {
        &self.locations
    }

    pub fn remove(&mut self, location: &il::RefProgramLocation<'r>) {
        self.locations.remove(location);
    }
}


impl<'r> PartialOrd for LocationSet<'r> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.locations.len() == other.locations.len() {
            for rpl in &self.locations {
                if !other.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Equal)
        }
        else if self.locations.len() < other.locations.len() {
            for rpl in &self.locations {
                if !other.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Less)
        }
        else {
            for rpl in &other.locations {
                if !self.locations.contains(rpl) {
                    return None;
                }
            }
            Some(Ordering::Greater)
        }
    }
}


impl<'r> PartialEq for LocationSet<'r> {
    fn eq(&self, other: &Self) -> bool {
        if let Some(ordering) = self.partial_cmp(other) {
            if ordering == Ordering::Equal {
                true
            }
            else {
                false
            }
        }
        else {
            false
        }
    }
}