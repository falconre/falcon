use super::*;

/// CALL rbx: indirect call through register.
/// Per AMD64 manual: RSP = RSP - 8, [RSP] = address of next instruction (return address),
/// RIP = target. No flags affected.
/// call rbx = 0xff 0xd3 (FF /2, ModRM 11 010 011).
/// This is a block-terminating instruction (branch), so we use translation-only testing
/// to verify the instruction translates successfully.
#[test]
fn call_rbx_translates() {
    // call rbx  =>  ff d3
    let bytes: Vec<u8> = vec![0xff, 0xd3];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "call rbx should translate successfully: {:?}",
        result.err()
    );
}

/// CALL rbx: verify translation produces correct block length.
/// Per AMD64 manual: CALL r/m64 is encoded as FF /2.
/// call rbx (ff d3) is 2 bytes long.
#[test]
fn call_rbx_block_length() {
    // call rbx  =>  ff d3
    let bytes: Vec<u8> = vec![0xff, 0xd3];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();

    // The block should be exactly 2 bytes (the length of `call rbx`)
    assert_eq!(
        result.length(),
        2,
        "call rbx should produce a 2-byte block"
    );
}

/// CALL rbx: verify the instruction count.
/// A single call instruction should produce exactly one instruction in the block.
#[test]
fn call_rbx_instruction_count() {
    // call rbx  =>  ff d3
    let bytes: Vec<u8> = vec![0xff, 0xd3];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();

    // Should contain exactly one instruction (the call)
    assert_eq!(
        result.instructions().len(),
        1,
        "call rbx block should contain exactly 1 instruction"
    );
}

/// CALL rax: indirect call through rax.
/// Per AMD64 manual: CALL r/m64 is encoded as FF /2.
/// call rax = 0xff 0xd0 (FF /2, ModRM 11 010 000).
/// Verifies a different register target also translates.
#[test]
fn call_rax_translates() {
    // call rax  =>  ff d0
    let bytes: Vec<u8> = vec![0xff, 0xd0];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "call rax should translate successfully: {:?}",
        result.err()
    );
}
