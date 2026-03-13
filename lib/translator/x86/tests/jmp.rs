use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// JMP rel8: Unconditional short jump.
/// Per AMD64 manual Vol.3: JMP transfers control unconditionally to the target address.
/// The short form (opcode EBh) takes a signed 8-bit relative displacement, measured
/// from the end of the JMP instruction.
///
/// Encoding: `jmp short $+0x10` assembled at address 0 produces 0xeb, 0x0e.
///   - $+0x10 means target = current_address + 0x10 = 0 + 0x10 = 0x10
///   - The instruction is 2 bytes long, so rel8 = target - (address + 2) = 0x10 - 0x02 = 0x0e
///   - Target address = 0x10
///
/// JMP is block-terminating. The block should have exactly 1 unconditional successor
/// at the target address (0x10). An unconditional successor has no condition (None).
#[test]
fn jmp_short_translates_with_correct_successor() {
    // jmp short $+0x10  (assembled at address 0)  =>  eb 0e
    let bytes: Vec<u8> = vec![0xeb, 0x0e];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .expect("jmp short should translate successfully");

    // Block length should be 2 bytes (the short jmp instruction)
    assert_eq!(
        result.length(),
        2,
        "jmp short should produce a 2-byte block, got {}",
        result.length()
    );

    // JMP is unconditional, so there should be exactly 1 successor
    let successors = result.successors();
    assert_eq!(
        successors.len(),
        1,
        "jmp short should have exactly 1 successor, got {}",
        successors.len()
    );

    // The successor should point to address 0x10 (target of the jump)
    assert_eq!(
        successors[0].0, 0x10,
        "jmp short successor should target 0x10, got 0x{:x}",
        successors[0].0
    );

    // The successor should be unconditional (condition = None)
    assert!(
        successors[0].1.is_none(),
        "jmp short successor should be unconditional (None), got {:?}",
        successors[0].1
    );
}
