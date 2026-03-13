use super::*;

/// LODSB with DF=0: loads byte from [RSI] into AL, increments RSI by 1.
/// Per AMD64 manual: LODSB loads the byte at [RSI] into AL.
/// If DF=0, RSI is incremented by 1. No flags are affected.
/// lodsb = 0xac.
#[test]
fn lodsb_df_clear() {
    // lodsb  =>  ac
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xac, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0x0, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0xAB, 8))],
    );

    let driver = step_to(driver, 0x1);

    // AL should contain the byte loaded from [RSI]
    // LODSB loads into AL only; check low byte via rax masked
    assert_scalar(&driver, "rax", 0xAB);
    // RSI incremented by 1 (DF=0)
    assert_scalar(&driver, "rsi", 0x2001);
}

/// LODSB with DF=1: loads byte from [RSI] into AL, decrements RSI by 1.
/// Per AMD64 manual: If DF=1, RSI is decremented by 1.
/// No flags are affected.
#[test]
fn lodsb_df_set() {
    // lodsb  =>  ac
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xac, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2010, 64)),
            ("rax", il::const_(0x0, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![(0x2010, il::const_(0x7E, 8))],
    );

    let driver = step_to(driver, 0x1);

    // AL should contain 0x7E
    assert_scalar(&driver, "rax", 0x7E);
    // RSI decremented by 1 (DF=1)
    assert_scalar(&driver, "rsi", 0x200F);
}

/// LODSB: only AL is modified; upper bytes of RAX should be preserved.
/// Per AMD64 manual: LODSB loads into AL (byte), the upper 56 bits of
/// RAX should be unchanged (unlike 32-bit ops which zero-extend).
#[test]
fn lodsb_preserves_upper_rax() {
    // lodsb  =>  ac
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xac, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0xFFFFFFFFFFFF0000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0x42, 8))],
    );

    let driver = step_to(driver, 0x1);

    // Only AL (bits 7:0) should change to 0x42; upper bytes preserved
    // Expected RAX = 0xFFFFFFFFFFFF0042
    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFF0042);
}

/// LODSB: source memory should remain unchanged after load.
/// Per AMD64 manual: LODS reads memory; it does not modify it.
#[test]
fn lodsb_memory_unchanged() {
    // lodsb  =>  ac
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xac, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0x0, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0xBB, 8))],
    );

    let driver = step_to(driver, 0x1);

    // Source memory at 0x2000 should still contain the original byte
    assert_eq!(
        load_memory(&driver, 0x2000, 8),
        0xBB,
        "source memory should remain unchanged after LODSB"
    );
}
