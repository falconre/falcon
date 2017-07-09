//! A lattice for tracking `il::Constant` values.

use error::*;
use executor;
use il;
use il::Expression;
use std::collections::{BTreeMap, BTreeSet};
use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt;
use std::ops::BitOr;


/// A lattice of `il::Constant` values
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LatticeValue {
    Join, // Top
    Values(BTreeSet<il::Constant>),
    Meet // Bottom
}

use self::LatticeValue::*;


impl LatticeValue {
    /// Joins the values of the `other` lattice with this lattice by performing
    /// a set union.
    pub fn join(self, other: &LatticeValue) -> LatticeValue {
        match self {
            Join => Join,
            Values(lhs) => {
                match *other {
                    Join => other.clone(),
                    Values(ref rhs) => {
                        #[cfg(debug_assertions)]
                        for v in lhs.iter() {
                            for r in rhs.iter() {
                                if v.bits() != r.bits() {
                                    panic!("Joining Lattice Value with varying bit-sizes");
                                }
                            }
                        }
                        LatticeValue::Values(lhs.bitor(rhs))
                    },
                    Meet => Values(lhs)
                }
            },
            Meet => other.clone()
        }
    }

    /// Attempts to figure out the bit-size of this LatticeValue by returning
    /// the bit-size of the first il::Constant value, or None if Join/Meet
    pub fn bits(&self) -> Option<usize> {
        match *self {
            Join |
            Meet => None,
            Values(ref v) => match v.iter().next() {
                Some(c) => Some(c.bits()),
                None => None
            }
        }
    }

    /// Takes one `il::Constant` and creates a `LatticeValue::Values` with that
    /// constant as the sole value.
    pub fn value(value: il::Constant) -> LatticeValue {
        let mut set = BTreeSet::new();
        set.insert(value);
        Values(set)
    }

    /// Swaps the endianness of the values held in the `LatticeValue`, and
    /// returns the result as a new LatticeValue
    pub fn endian_swap(&self) -> Result<LatticeValue> {
        match *self {
            Join => Ok(Join),
            Meet => Ok(Meet),
            Values(ref values) => {
                let mut swapped: BTreeSet<il::Constant> = BTreeSet::new();
                // We're creating a LatticeAssignments for eval. Admittedly not
                // the best solution
                for value in values.iter() {
                    let expr = executor::swap_bytes(&value.clone().into())?;
                    let const_ = executor::constants_expression(&expr)?; 
                    swapped.insert(const_);
                }
                Ok(LatticeValue::Values(swapped))
            }
        }
    }
}

impl Ord for LatticeValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match *self {
            Join => {
                match *other {
                    Join => Ordering::Equal,
                    _ => Ordering::Less
                }
            },
            Values(ref values) => {
                match *other {
                    Join => Ordering::Greater,
                    Values(ref other_values) => values.cmp(other_values),
                    Meet => Ordering::Less
                }
            },
            Meet => {
                match *other {
                    Meet => Ordering::Equal,
                    _ => Ordering::Greater
                }
            }
        }
    }
}

impl PartialOrd for LatticeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for LatticeValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Join => write!(f, "Join"),
            Values(ref values) => {
                write!(f, "({})", values.iter()
                                     .map(|c| format!("{}", c))
                                     .collect::<Vec<String>>()
                                     .join(", "))
            },
            Meet => write!(f, "Meet")
        }
    }
}



fn lattice_value_binop<F>(lhs: &LatticeValue, rhs: &LatticeValue, op: F) -> LatticeValue
where F: Fn(il::Constant, il::Constant) -> Expression {
    match *lhs {
        Join => LatticeValue::Join,
        Values(ref lhs_) => {
            match *rhs {
                Join => LatticeValue::Join,
                Values(ref rhs_) => {
                    let mut sum = BTreeSet::new();
                    for l in lhs_.iter() {
                        for r in rhs_.iter() {
                            let expr = op(l.clone(), r.clone());
                            if let Ok(c) = executor::constants_expression(&expr) {
                                sum.insert(c);
                            }
                        }
                    }
                    LatticeValue::Values(sum)
                },
                Meet => LatticeValue::Meet
            }
        },
        Meet => LatticeValue::Meet
    }
}


fn lattice_extend_op<F>(rhs: &LatticeValue, op: F) -> LatticeValue
where F: Fn(il::Constant) -> Expression {
    match *rhs {
        Join |
        Meet => rhs.clone(),
        Values(ref rhs_) => {
            let mut sum = BTreeSet::new();
            for r in rhs_ {
                let expr = op(r.clone());
                if let Ok(c) = executor::constants_expression(&expr) {
                    sum.insert(c);
                }
            }
            LatticeValue::Values(sum)
        }
    }
}


#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LatticeMemoryValue {
    bits: usize,
    value: LatticeValue
}


impl LatticeMemoryValue {
    pub fn new(bits: usize) -> LatticeMemoryValue {
        LatticeMemoryValue {
            bits: bits,
            value: LatticeValue::Meet
        }
    }

    pub fn new_with_value(bits: usize, value: LatticeValue) -> LatticeMemoryValue {
        LatticeMemoryValue {
            bits: bits,
            value: value
        }
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    pub fn bytes(&self) -> usize {
        if self.bits & 0x7 != 0 {
            (self.bits / 8) + 1
        }
        else {
            self.bits / 8
        }
    }

    /// Truncate all values in the LatticeMemoryValue to a given bit-width
    /// and returns the result as a new LatticeMemoryValue
    pub fn trun(&self, bits: usize) -> LatticeMemoryValue {
        let mut lmv = LatticeMemoryValue::new(bits);

        lmv.value = match self.value {
            Join => Join,
            Meet => Meet,
            Values(_) => {
                lattice_extend_op(&self.value, |rhs: il::Constant| {
                    Expression::trun(bits, rhs.into()).unwrap()
                })
            }
        };

        lmv
    }


    /// Extract the values in the LatticeMemoryValue and return the
    /// result as a new LatticeMemoryValue
    pub fn extract(&self, offset: usize, bits: usize) -> LatticeMemoryValue {
        let mut lmv = LatticeMemoryValue::new(bits);

        lmv.value = match self.value {
            Join => Join,
            Meet => Meet,
            Values(_) => {
                let lv = lattice_value_binop(
                    &self.value,
                    &LatticeValue::value(il::const_(offset as u64, self.value.bits().unwrap())),
                    |lhs: il::Constant, rhs: il::Constant| {
                        Expression::shr(lhs.into(), rhs.into()).unwrap()
                    }
                );
                lattice_extend_op(&lv, |rhs: il::Constant| {
                    Expression::trun(bits, rhs.into()).unwrap()
                })
            } 
        };

        lmv
    }

    /// Concatenate another `LatticeMemoryValue` to the end of this
    /// `LatticeMemoryValue`, and return the result as a new 
    /// `LatticeMemoryValue`
    pub fn concat(&self, other: &LatticeMemoryValue) -> LatticeMemoryValue {
        let bits_sum = self.bits + other.bits();
        let mut lmv = LatticeMemoryValue::new(self.bits + other.bits());

        lmv.value = match self.value {
            Join => Join,
            Meet => Meet,
            Values(_) => {
                match other.value {
                    Join => Join,
                    Meet => Meet,
                    Values(_) => {
                        // zext both lhs and rhs to the sum bit width
                        let lv_lhs = lattice_extend_op(&self.value,
                            |rhs: il::Constant| {
                                Expression::zext(bits_sum, rhs.into()).unwrap()
                            });
                        let lv_rhs = lattice_extend_op(&other.value,
                            |rhs: il::Constant| {
                                Expression::zext(bits_sum, rhs.into()).unwrap()
                            });
                        // shift rhs left
                        let lv_rhs = lattice_value_binop(
                            &lv_rhs,
                            &LatticeValue::value(il::const_(self.bits as u64, bits_sum)),
                            |lhs: il::Constant, rhs: il::Constant| {
                                Expression::shl(lhs.into(), rhs.into()).unwrap()
                            });
                        // or the two together
                        lattice_value_binop(
                            &lv_lhs,
                            &lv_rhs,
                            |lhs: il::Constant, rhs: il::Constant| {
                                Expression::or(lhs.into(), rhs.into()).unwrap()
                            })
                    }
                }
            }
        };

        lmv
    }
}

impl fmt::Display for LatticeMemoryValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(:{}, {})", self.bits, self.value)
    }
}


/// A mapping of addresses to values
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LatticeMemory {
    memory: BTreeMap<u64, LatticeMemoryValue>
}


impl LatticeMemory {
    pub fn new() -> LatticeMemory {
        LatticeMemory {
            memory: BTreeMap::new()
        }
    }


    /// Joins two `LatticeMemory`s together
    pub fn join(mut self, other: &LatticeMemory, max: usize) -> LatticeMemory {
        for entry in &other.memory {
            let address = entry.0.clone();
            let lmv = entry.1;

            // If we have any segments which overlap directly, or after,
            // we will combine those first.
            let (mut lmv, insert, remove) = {
                let mut remove: Vec<u64> = Vec::new();
                let mut insert: Vec<(u64, LatticeMemoryValue)> = Vec::new();

                // Every entry which has a start address that lands within
                // where the value we are inserting will lang.
                let forward = self.memory.range(address..(address + lmv.bytes() as u64));

                let mut lmv = lmv.clone();

                // Deal with all values which start at, or after, the value we
                // are inserting
                for f in forward {
                    let forward_address = f.0.clone();
                    let forward_lmv = f.1;

                    // if this fits entirely within the current lmv
                    if forward_address + (forward_lmv.bytes() as u64) <= address + (lmv.bytes() as u64) {
                        let mut forward_lv = forward_lmv.value.clone();
                        // ensure forward_lv is the same bit size
                        if forward_lmv.bits() != lmv.bits() {
                            forward_lv = lattice_extend_op(
                                &forward_lv,
                                |rhs: il::Constant| {
                                    Expression::zext(lmv.bits(), rhs.into()).unwrap()
                                }
                            );
                        }
                        // shift the forward_lv into place
                        if forward_address > address {
                            forward_lv = lattice_value_binop(
                                &forward_lv,
                                &LatticeValue::value(il::const_(
                                    (forward_address - address) * 8,
                                    lmv.bits()
                                )),
                                |lhs: il::Constant, rhs: il::Constant| {
                                    Expression::shr(lhs.into(), rhs.into()).unwrap()
                                }
                            );
                        }

                        // Join
                        let lv = lmv.value.clone();
                        let lv = lv.join(&forward_lv);
                        let lv = match lv {
                            Join => Join,
                            Meet => Meet,
                            Values(values) => if values.len() > max {
                                Join
                            } else {
                                Values(values)
                            }
                        };
                        lmv = LatticeMemoryValue::new_with_value(lmv.bits(), lv);

                        // Add this forward_lmv to the remove set
                        remove.push(forward_address);
                    }
                    // This forward_lmv doesn't fit completely, and we have overlap
                    // We need to
                    // 1) Join the relevant LatticeValue sets
                    // 2) Remove this forward_lmv
                    // 3) Insert a new forward_lmv that just includes the trailing portion
                    else {
                        // Start by extracting the relevant portion of the forward_lmv
                        let offset = ((forward_address - address) * 8) as usize;
                        let length = if lmv.bits() - offset > forward_lmv.bits() {
                            forward_lmv.bits()
                        }
                        else {
                            lmv.bits() - offset
                        };
                        let join_forward_lmv = forward_lmv.extract(offset, length);
                        let mut join_forward_lv = join_forward_lmv.value.clone();

                        // Extend this to the needed length
                        if join_forward_lmv.bits() < lmv.bits() {
                            join_forward_lv = lattice_extend_op(
                                &join_forward_lv,
                                |rhs: il::Constant| {
                                    Expression::zext(lmv.bits(), rhs.into()).unwrap()
                                }
                            );
                        }

                        // Shift this right to where it should be
                        if forward_address < address {
                            join_forward_lv = lattice_value_binop(
                                &join_forward_lv,
                                &LatticeValue::value(il::const_(
                                    (forward_address - address) * 8,
                                    lmv.bits()
                                )),
                                |lhs: il::Constant, rhs: il::Constant| {
                                    Expression::shr(lhs.into(), rhs.into()).unwrap()
                                }
                            );
                        }

                        // Join
                        let lv = lmv.value.clone();
                        let lv = lv.join(&join_forward_lv);
                        let lv = match lv {
                            Join => Join,
                            Meet => Meet,
                            Values(values) => if values.len() > max {
                                Join
                            } else {
                                Values(values)
                            }
                        };
                        lmv = LatticeMemoryValue::new_with_value(lmv.bits(), lv);

                        // Now we need to extract the portion that comes after
                        let offset = (((address + lmv.bytes() as u64) - forward_address) * 8) as usize;
                        let length = forward_lmv.bits() - offset;
                        let forward_lmv = forward_lmv.extract(offset, length);

                        // set our remove/insert sets
                        remove.push(forward_address);
                        insert.push(((address + lmv.bytes() as u64), forward_lmv));
                    }
                }

                (lmv, insert, remove)
            };

            for r in remove {
                self.memory.remove(&r);
            }

            for i in insert {
                if i.1.bits() == 0 {
                    panic!("insert 0 bits forward");
                }
                self.memory.insert(i.0, i.1);
            }

            // deal with all values which start before the value we are
            // inserting but overlap it.
            let (lmv, insert, remove) = {
                let mut insert: Vec<(u64, LatticeMemoryValue)> = Vec::new();
                let mut remove: Vec<u64> = Vec::new();

                let previous = self.memory.range((address - 32)..address);

                if let Some(previous) = previous.last() {
                    let pre_addr = previous.0.clone();
                    let pre_lmv = previous.1;

                    // If this doesn't overlap, we do nothing
                    if pre_addr + (pre_lmv.bytes() as u64) <= address {
                        (lmv, insert, remove)
                    }

                    // We need to
                    // 1) Isolate the segment before this
                    // 2) Combine the segments that overlap
                    else {

                        // 1) Isolate the non-overlapping portion
                        let non_length = (address - pre_addr) as usize * 8;
                        let pre_extract = pre_lmv.trun(non_length);
                        remove.push(pre_addr);
                        insert.push((pre_addr, pre_extract));

                        // 2) Combine the segments that overlap
                        // Extract the overlapping portion from the first set
                        let pre_offset = (address - pre_addr) as usize * 8;
                        let pre_length = pre_lmv.bits() - pre_offset as usize;
                        let pre_extract = pre_lmv.extract(pre_offset, pre_length);

                        // Extend it as needed
                        let mut pre_lv = pre_extract.value.clone();
                        if pre_extract.bits() < lmv.bits() {
                            pre_lv = lattice_extend_op(
                                &pre_lv,
                                |rhs: il::Constant| {
                                    Expression::zext(lmv.bits(), rhs.into()).unwrap()
                                }
                            );
                        }

                        // Combine this with the lmv
                        let lv = lmv.value.clone();
                        let lv = lv.join(&pre_lv);
                        lmv = LatticeMemoryValue::new_with_value(lmv.bits(), lv);

                        (lmv, insert, remove)
                    }
                }
                else {
                    (lmv, insert, remove)
                }
            };

            for r in remove {
                self.memory.remove(&r);
            }

            for i in insert {
                if i.1.bits() == 0 {
                    trace!("{:?}", i);
                    panic!("insert 0 bits backwards");
                }
                self.memory.insert(i.0, i.1);
            }
            if lmv.bits() == 0 {
                panic!("insert 0 bits");
            }
            self.memory.insert(address, lmv);
        }

        self
    }

    /// Helper function to store a LatticeMemoryValue at the given address.
    ///
    /// Properly adjusts other adjacent values as necessary.
    fn store_(&mut self, address: u64, mv: LatticeMemoryValue) {
        // First we search for an overlappying LatticeMemoryValue before.
        let overlapping = {
            let mut overlapping: Vec<(u64, LatticeMemoryValue)> = Vec::new();

            // Search up to 32 bytes back
            let previous = self.memory.range((address - 32)..address);

            if let Some(previous) = previous.last() {
                let addr = previous.0;
                let lmv = previous.1;
                if addr + lmv.bytes() as u64 - 1 >= address {
                    let trun = lmv.trun((address - addr) as usize * 8);
                    overlapping.push((addr.clone(), trun));
                }
            }

            overlapping
        };

        // If we have an overlapping LatticeMemoryValue, we replace it with
        // the truncated value
        for overlap in overlapping {
            if overlap.1.bits() == 0 {
                panic!("storing overlapping value with bits=0");
            }
            self.memory.insert(overlap.0, overlap.1);
        }

        // No we look to see if this overlaps any other LatticeMemory forward
        let (drop, forward_overlapping) = {
            let mut forward_overlapping: Vec<(u64, u64, LatticeMemoryValue)> = Vec::new();
            let mut drop: Vec<u64> = Vec::new();

            let forward = self.memory
                          .range(address..(address + mv.bytes() as u64))
                          .collect::<Vec<(&u64, &LatticeMemoryValue)>>();

            for f in forward.iter() {
                let addr = f.0;
                let lmv = f.1;
                // If we will completely overwrite this value, drop it
                if addr + lmv.bytes() as u64 <= address + mv.bytes() as u64 {
                    drop.push(addr.clone());
                }
                // Otherwise, extract the relevant portions and rebase it
                else {
                    let offset = ((address + mv.bytes() as u64) - addr) * 8;
                    let bits = lmv.bits() as u64 - offset;
                    let oldaddr = addr;
                    let newaddr = address + mv.bytes() as u64;
                    let extracted = lmv.extract(offset as usize, bits as usize);
                    forward_overlapping.push((oldaddr.clone(), newaddr, extracted));
                }
            }

            (drop, forward_overlapping)
        };

        for d in drop {
            self.memory.remove(&d);
        }

        for overlap in forward_overlapping {
            self.memory.remove(&overlap.0);
            if overlap.2.bits() == 0 {
                panic!("forward_overlapping bits=0");
            }
            self.memory.insert(overlap.1, overlap.2);
        }

        // Insert our value
        if mv.bits() == 0 {
            panic!("insert mv with bits=0");
        }
        self.memory.insert(address, mv);
    }


    /// Store a value in big-endian into the `LatticeMemory`.
    ///
    /// The value received here is big-endian. If it needs to be
    /// little-endian, you should swap it before passing to this function.
    pub fn store(
        &mut self,
        address: &LatticeValue,
        value: LatticeValue,
        bits: usize,
        max: usize
    ) {
        if bits == 0 {
            panic!("0 bits for store");
        }

        match *address {
            Join |
            Meet => {}, // TODO is this the right thing to do here?
            Values(ref addresses) => {
                // If we just create a new LatticeMemory, and join it with ourself,
                // this is effectively a store.
                let mut lmv = LatticeMemory::new();
                for addr in addresses {
                    lmv.memory.insert(
                        addr.value() as u64,
                        LatticeMemoryValue::new_with_value(bits, value.clone())
                    );
                    /*
                    self.store_(
                        addr.value() as u64,
                        LatticeMemoryValue::new_with_value(bits, value.clone())
                    );
                    */
                }
                *self = self.clone().join(&lmv, max);
            }
        }
    }


    /// Helper function to store a LatticeMemoryValue at the given address.
    ///
    /// If there are not enough values in memory to create a complete value
    /// of the desired bit-width, returns None
    fn load_(&self, address: u64, bits: usize) -> Option<LatticeValue> {
        let mut lmv_result: Option<LatticeMemoryValue> = None;

        // If there's a value at this address...
        if let Some(lmv) = self.memory.get(&address) {
            if lmv.bits() == bits {
                return Some(lmv.value.clone());
            }
            else if lmv.bits() > bits {
                return Some(lmv.trun(bits).value.clone());
            }
            else {
                lmv_result = Some(lmv.clone());
            }
        }

        // There was no value at this address, look for an overlapping value
        // at a previous address
        if lmv_result.is_none() {
            // Search up to 32 bytes back
            let previous = self.memory.range((address - 32)..address);

            if let Some(previous) = previous.last() {
                let addr = previous.0;
                let lmv = previous.1;
                // The value must completely encompass the value we are trying
                // to return
                if addr + lmv.bytes() as u64 >= address + (bits / 8) as u64 {
                    let offset = (address - addr) as usize * 8;
                    return Some(lmv.extract(offset, bits).value.clone());
                }
            }

            // Nope, return None
            return None;
        }
        // We read a value, but it didn't contain enough bits for our load
        else if let Some(mut lmv_result) = lmv_result {
            // While our result isn't large enough
            while lmv_result.bits() < bits {
                // Look for a value at the next address
                let next_addr = address + lmv_result.bytes() as u64;
                if let Some(lmv) = self.memory.get(&next_addr) {
                    // Is it too large?
                    if lmv.bits() > bits - lmv_result.bits() {
                        // We just need to truncate, concat, and we're done
                        let lmv = lmv.trun(bits - lmv_result.bits());
                        return Some(lmv_result.concat(&lmv).value.clone());
                    }
                    // Is it just right?
                    else if lmv.bits() == bits - lmv_result.bits() {
                        return Some(lmv_result.concat(&lmv).value.clone());
                    }
                    // If it's too small, concat it and keep looping
                    else {
                        lmv_result = lmv_result.concat(&lmv);
                    }
                }
                else {
                    // There isn't another value to complete our result
                    return None;
                }
            }
            return Some(lmv_result.value.clone());
        }
        // No value at this address
        else {
            None
        }
    }


    /// Load a value from the `LatticeMemory`. The value returned will be
    /// big-endian. If you need a little-endian value, swap it after the load.
    pub fn load(
        &mut self,
        address: &LatticeValue,
        bits: usize
    ) -> Option<LatticeValue> {
        let mut lv_result: Option<LatticeValue> = None;

        match address {
            &Join |
            &Meet => {}, // TODO is this the right thing to do here?
            &Values(ref addresses) => {
                for addr in addresses {
                    let address_u64 = addr.value();
                    let lv = self.load_(address_u64, bits);
                    if let Some(lv) = lv {
                        match lv_result {
                            Some(lvr) => {
                                lv_result = Some(lvr.join(&lv));
                            },
                            None => {
                                lv_result = Some(lv);
                            }
                        }
                    }
                }
            }
        }

        lv_result
    }
}


/// A mapping of scalars and memory addresses to their lattice values
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LatticeAssignments {
    scalars: BTreeMap<il::Scalar, LatticeValue>,
    memory: LatticeMemory,
    /// The max number of elements for each LatticeValue before converting it
    /// to Join
    max: usize
}


impl LatticeAssignments {
    /// Creates a new LatticeAssignments
    ///
    /// `max` is the maximum number of values a `LatticeValue::Values`s will
    /// hold before being transformed into `LatticeValue::Join`
    pub fn new(max: usize) -> LatticeAssignments {
        LatticeAssignments {
            scalars: BTreeMap::new(),
            memory: LatticeMemory::new(),
            max: max
        }
    }

    /// Get the `LatticeValue` for a scalar
    // pub fn value(&self) -> &BTreeMap<il::Scalar, LatticeValue> {
    //     &self.variables
    // }

    /// Get max number of values a `LatticeValue` can have before Join
    pub fn max(&self) -> usize {
        self.max
    }

    pub fn join(mut self, other: &LatticeAssignments) -> LatticeAssignments {
        // for every assignment in the other LatticeAssignment
        for assignment in &other.scalars {
            let scalar = assignment.0;
            let mut lattice_value = assignment.1.clone();

            // If the scalars exists here
            if let Some(lv) = self.scalars.get(scalar) {
                // Join the two values
                let lv = lv.clone().join(&lattice_value);
                // If the join is a vlue (not Meet/Join)
                lattice_value = match lv {
                    Join => Join,
                    Meet => Meet,
                    Values(values) => {
                        if values.len() > self.max {
                            Join
                        }
                        else {
                            Values(values)
                        }
                    }
                }
            }

            self.scalars.insert(scalar.clone(), lattice_value);
        }

        self.memory = self.memory.join(&other.memory, self.max);

        self
    }

    /// Set the `LatticeValue` for an `il::Scalar`
    pub fn set(&mut self, scalar: il::Scalar, value: LatticeValue) {
        self.scalars.insert(scalar, value);
    }

    /// Get the `LatticeValue` for an `il::Scalar`.
    pub fn get(&self, scalar: &il::Scalar) -> Option<&LatticeValue> {
        self.scalars.get(scalar)
    }

    pub fn store(&mut self, address: &LatticeValue, value: LatticeValue, bits: usize) {
        self.memory.store(address, value, bits, self.max);
    }

    pub fn load(
        &mut self,
        address: &LatticeValue,
        bits: usize
    ) -> Option<LatticeValue> {
        self.memory.load(address, bits)
    }

    /// Evaluates an `il::Expression`, using the values in this
    /// `LatticeAssignments` for scalars.
    pub fn eval(&self, expr: &Expression) -> LatticeValue {
        let lattice_value = self.eval_(expr);
        if let Values(ref values) = lattice_value {
            if values.len() > self.max {
                return LatticeValue::Join;
            }
        }
        lattice_value
    }

    fn eval_(&self, expr: &Expression) -> LatticeValue {
        match *expr {

            Expression::Scalar(ref scalar) => {
                match self.scalars.get(scalar) {
                    Some(lattice_value) => lattice_value.clone(),
                    None => LatticeValue::Meet
                }
            },

            Expression::Constant(ref constant) =>
                LatticeValue::value(constant.clone()),

            Expression::Add(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::add(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Sub(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::sub(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Mul(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::mul(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Divu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::divu(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Modu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::modu(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Divs(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::divs(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Mods(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::mods(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::And(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::and(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Or(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::or(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Xor(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::xor(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Shl(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::shl(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Shr(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::shr(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Cmpeq(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpeq(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Cmpneq(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpneq(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Cmplts(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmplts(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Cmpltu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpltu(lhs.into(), rhs.into()).unwrap()
                )
            },

            Expression::Zext(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| {
                        Expression::zext(bits, rhs.into()).unwrap()
                    }
                )
            },

            Expression::Sext(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| Expression::sext(bits, rhs.into()).unwrap()
                )
            },

            Expression::Trun(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| Expression::trun(bits, rhs.into()).unwrap()
                )
            }
        }
    }
}