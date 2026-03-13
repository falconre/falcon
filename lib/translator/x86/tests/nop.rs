use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// NOP: No operation.
/// Per AMD64 manual Vol.3: NOP performs no operation. No registers or flags are modified.
/// nop = 0x90 (1 byte, opcode 90h).
/// NOP is not block-terminating, so the block simply contains the instruction and
/// falls through. We verify the translation succeeds and the block length is 1.
#[test]
fn nop_translates_and_block_length() {
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x90];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .expect("nop should translate successfully");

    // NOP is a single-byte instruction, so the block length should be 1
    assert_eq!(
        result.length(),
        1,
        "nop should produce a 1-byte block, got {}",
        result.length()
    );
}
