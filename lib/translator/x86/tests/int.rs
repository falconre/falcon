use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// INT imm8: Software interrupt.
/// Per AMD64 manual Vol.3: INT generates a software interrupt using the specified
/// interrupt vector number (imm8). The processor saves state and transfers control
/// to the interrupt handler.
/// int 0x80 = 0xcd, 0x80 (2 bytes: opcode CDh + imm8).
/// In Falcon, INT is translated as an intrinsic operation.
#[test]
fn int_0x80_translates() {
    // int 0x80  =>  cd 80
    let bytes: Vec<u8> = vec![0xcd, 0x80];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "int 0x80 should translate successfully: {:?}",
        result.err()
    );
}
