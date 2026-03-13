use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// JE rel8 (a.k.a. JZ): Conditional jump if equal (ZF=1).
/// Per AMD64 manual Vol.3: Jcc tests a condition code (based on RFLAGS) and jumps
/// to the target address if the condition is met; otherwise falls through.
/// The short form (opcode 74h) takes a signed 8-bit relative displacement,
/// measured from the end of the Jcc instruction.
///
/// Encoding: `je $+0x10` assembled at address 0 produces 0x74, 0x0e.
///   - $+0x10 means target = current_address + 0x10 = 0 + 0x10 = 0x10
///   - The instruction is 2 bytes long, so rel8 = target - (address + 2) = 0x10 - 0x02 = 0x0e
///   - Target address (taken) = 0x10
///   - Fall-through address (not taken) = 0x02
///
/// Jcc is block-terminating. The block should have exactly 2 successors:
/// one for the taken branch (target) and one for the fall-through.
#[test]
fn je_short_translates_with_two_successors() {
    // je $+0x10  (assembled at address 0)  =>  74 0e
    let bytes: Vec<u8> = vec![0x74, 0x0e];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .expect("je short should translate successfully");

    // Block length should be 2 bytes (the short je instruction)
    assert_eq!(
        result.length(),
        2,
        "je short should produce a 2-byte block, got {}",
        result.length()
    );

    // Jcc is conditional, so there should be exactly 2 successors
    // (one taken branch, one fall-through)
    let successors = result.successors();
    assert_eq!(
        successors.len(),
        2,
        "je short should have exactly 2 successors, got {}",
        successors.len()
    );

    // Collect the successor addresses
    let addresses: Vec<u64> = successors.iter().map(|s| s.0).collect();

    // One successor should be the fall-through address (0x02 = address + instruction length)
    assert!(
        addresses.contains(&0x02),
        "je short should have a fall-through successor at 0x02, got {:?}",
        addresses
    );

    // One successor should be the taken-branch target (0x10)
    assert!(
        addresses.contains(&0x10),
        "je short should have a taken-branch successor at 0x10, got {:?}",
        addresses
    );

    // Both successors should have conditions (Some), since one is the taken
    // condition and the other is the negated (fall-through) condition
    for (addr, cond) in successors {
        assert!(
            cond.is_some(),
            "successor at 0x{:x} should have a condition, but got None",
            addr
        );
    }
}
