use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// UD2: Undefined instruction (intentional).
/// Per AMD64 manual Vol.3: UD2 generates an invalid-opcode exception (#UD).
/// It is used as a marker for unreachable code or to intentionally trigger a trap.
/// ud2 = 0x0f, 0x0b (2 bytes: two-byte opcode 0F 0Bh).
/// In Falcon, UD2 is translated as an intrinsic.
#[test]
fn ud2_translates() {
    // ud2  =>  0f 0b
    let bytes: Vec<u8> = vec![0x0f, 0x0b];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "ud2 should translate successfully: {:?}",
        result.err()
    );
}
