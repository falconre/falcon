use super::*;

/// CMPSB with equal bytes: compares [RSI] with [RDI], sets ZF=1.
/// Per AMD64 manual: CMPSB computes [RSI] - [RDI] and sets flags.
/// If DF=0, RSI and RDI are incremented by 1.
/// Equal bytes: [RSI] - [RDI] = 0, so ZF=1, CF=0, SF=0, OF=0.
/// cmpsb = 0xa6.
#[test]
fn cmpsb_equal() {
    // cmpsb  =>  a6
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa6, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![
            (0x2000, il::const_(0x42, 8)),
            (0x3000, il::const_(0x42, 8)),
        ],
    );

    let driver = step_to(driver, 0x1);

    // ZF=1 because bytes are equal ([RSI] - [RDI] = 0)
    assert_flag(&driver, "ZF", 1);
    // CF=0 because no borrow
    assert_flag(&driver, "CF", 0);
    // SF=0 because result is zero
    assert_flag(&driver, "SF", 0);
    // OF=0 because no signed overflow
    assert_flag(&driver, "OF", 0);
    // RSI incremented by 1 (DF=0)
    assert_scalar(&driver, "rsi", 0x2001);
    // RDI incremented by 1 (DF=0)
    assert_scalar(&driver, "rdi", 0x3001);
}

/// CMPSB with unequal bytes, [RSI] > [RDI]: sets ZF=0.
/// Per AMD64 manual: CMPSB computes [RSI] - [RDI].
/// 0x80 - 0x40 = 0x40 (unsigned: no borrow). Signed: 0x80 is -128,
/// 0x40 is 64; -128 - 64 = -192 overflows 8-bit signed range, OF=1.
/// Result 0x40 is positive in 8-bit => SF=0.
#[test]
fn cmpsb_src_greater() {
    // cmpsb  =>  a6
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa6, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![
            (0x2000, il::const_(0x80, 8)),
            (0x3000, il::const_(0x40, 8)),
        ],
    );

    let driver = step_to(driver, 0x1);

    // ZF=0 because bytes differ
    assert_flag(&driver, "ZF", 0);
    // CF=0 because 0x80 >= 0x40 (no unsigned borrow)
    assert_flag(&driver, "CF", 0);
    // Result 0x40 => SF=0 (bit 7 is 0)
    assert_flag(&driver, "SF", 0);
    // Signed: -128 - 64 = -192, overflows 8-bit signed range => OF=1
    assert_flag(&driver, "OF", 1);
    // RSI and RDI incremented by 1
    assert_scalar(&driver, "rsi", 0x2001);
    assert_scalar(&driver, "rdi", 0x3001);
}

/// CMPSB with [RSI] < [RDI] unsigned: borrow occurs, CF=1.
/// Per AMD64 manual: 0x10 - 0x20 = 0xF0 (wraps), CF=1 (borrow).
/// Result 0xF0 has bit 7 set => SF=1. No signed overflow => OF=0.
#[test]
fn cmpsb_src_less() {
    // cmpsb  =>  a6
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa6, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![
            (0x2000, il::const_(0x10, 8)),
            (0x3000, il::const_(0x20, 8)),
        ],
    );

    let driver = step_to(driver, 0x1);

    // ZF=0 because bytes differ
    assert_flag(&driver, "ZF", 0);
    // CF=1 because 0x10 < 0x20 (unsigned borrow)
    assert_flag(&driver, "CF", 1);
    // Result 0xF0 has bit 7 set => SF=1
    assert_flag(&driver, "SF", 1);
    // Signed: 16 - 32 = -16, fits in [-128,127] => OF=0
    assert_flag(&driver, "OF", 0);
    // RSI and RDI incremented by 1
    assert_scalar(&driver, "rsi", 0x2001);
    assert_scalar(&driver, "rdi", 0x3001);
}

/// CMPSB with DF=1: RSI and RDI should be decremented by 1.
/// Per AMD64 manual: If DF=1, RSI and RDI are decremented by operand size.
#[test]
fn cmpsb_df_set() {
    // cmpsb  =>  a6
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa6, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2010, 64)),
            ("rdi", il::const_(0x3010, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![
            (0x2010, il::const_(0xAA, 8)),
            (0x3010, il::const_(0xAA, 8)),
        ],
    );

    let driver = step_to(driver, 0x1);

    // ZF=1 because bytes are equal
    assert_flag(&driver, "ZF", 1);
    // RSI decremented by 1 (DF=1)
    assert_scalar(&driver, "rsi", 0x200F);
    // RDI decremented by 1 (DF=1)
    assert_scalar(&driver, "rdi", 0x300F);
}
