use super::*;

// =============================================================================
// LOOP — Loop with ECX/RCX Counter
// AMD64 manual: Decrements the count register (RCX in 64-bit mode), then jumps
// to the target if the count register is non-zero.
// LOOP does NOT affect any flags.
//
// LOOP is a block-terminating instruction (conditional branch), so we use
// translation-only testing: verify that the translator successfully translates
// the instruction without errors.
// =============================================================================

/// Translate a LOOP instruction and verify it succeeds.
/// `loop -2` loops to self (rel8 = 0xFE = -2).
/// Encoding: e2 fe
#[test]
fn loop_translates_successfully() {
    use crate::memory;
    use crate::translator::x86::Amd64;
    use crate::translator::Translator;

    // loop -2 (loop to address 0x0000, i.e. itself); nop
    let bytes: Vec<u8> = vec![0xe2, 0xfe, 0x90];

    let mut backing = memory::backing::Memory::new(Endian::Little);
    backing.set_memory(
        0,
        bytes,
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ,
    );

    let function = Amd64::new().translate_function(&backing, 0);
    assert!(
        function.is_ok(),
        "LOOP instruction should translate successfully, got error: {:?}",
        function.err()
    );
}
