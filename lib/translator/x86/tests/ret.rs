use super::*;

/// RET: return from procedure (near return).
/// Per AMD64 manual: RIP = [RSP], then RSP = RSP + 8. No flags affected.
/// ret = 0xc3.
/// RET is a block-terminating instruction (branch to popped address), so we use
/// translation-only testing to verify it translates successfully.
#[test]
fn ret_translates() {
    // ret  =>  c3
    let bytes: Vec<u8> = vec![0xc3];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "ret should translate successfully: {:?}",
        result.err()
    );
}

/// RET: verify translation produces correct block length.
/// Per AMD64 manual: RET (near, no operand) is a single-byte instruction (0xC3).
#[test]
fn ret_block_length() {
    // ret  =>  c3
    let bytes: Vec<u8> = vec![0xc3];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();

    // The block should be exactly 1 byte
    assert_eq!(result.length(), 1, "ret should produce a 1-byte block");
}

/// RET: verify instruction count.
/// A single ret instruction should produce exactly one instruction in the block.
#[test]
fn ret_instruction_count() {
    // ret  =>  c3
    let bytes: Vec<u8> = vec![0xc3];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();

    // Should contain exactly one instruction (the ret)
    assert_eq!(
        result.instructions().len(),
        1,
        "ret block should contain exactly 1 instruction"
    );
}

/// RET: block should have no known static successors.
/// Per AMD64 manual: RET pops the return address from the stack and jumps to it.
/// Since the target is dynamic (loaded from memory), there are no statically-known successors.
#[test]
fn ret_no_successors() {
    // ret  =>  c3
    let bytes: Vec<u8> = vec![0xc3];

    let translator = Amd64::new();
    let result = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();

    // RET jumps to a dynamic address (popped from stack), so no static successors
    assert!(
        result.successors().is_empty(),
        "ret should have no static successors, got {:?}",
        result.successors()
    );
}
