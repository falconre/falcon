use super::*;

/// MOVSB with DF=0: copies byte from [RSI] to [RDI], increments both by 1.
/// Per AMD64 manual: MOVSB moves byte at [RSI] to [RDI].
/// If DF=0, RSI and RDI are incremented by the operand size (1 for byte).
/// No flags are affected.
/// movsb = 0xa4.
#[test]
fn movsb_df_clear() {
    // movsb  =>  a4
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa4, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0x42, 8))],
    );

    let driver = step_to(driver, 0x1);

    // Byte should be copied from [RSI] to [RDI]
    assert_eq!(
        load_memory(&driver, 0x3000, 8),
        0x42,
        "memory at 0x3000 should contain byte copied from 0x2000"
    );
    // RSI incremented by 1 (DF=0)
    assert_scalar(&driver, "rsi", 0x2001);
    // RDI incremented by 1 (DF=0)
    assert_scalar(&driver, "rdi", 0x3001);
}

/// MOVSB with DF=1: copies byte from [RSI] to [RDI], decrements both by 1.
/// Per AMD64 manual: If DF=1, RSI and RDI are decremented by operand size (1).
/// No flags are affected.
#[test]
fn movsb_df_set() {
    // movsb  =>  a4
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa4, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2010, 64)),
            ("rdi", il::const_(0x3010, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![(0x2010, il::const_(0x7F, 8))],
    );

    let driver = step_to(driver, 0x1);

    // Byte should be copied from [RSI] to [RDI]
    assert_eq!(
        load_memory(&driver, 0x3010, 8),
        0x7F,
        "memory at 0x3010 should contain byte copied from 0x2010"
    );
    // RSI decremented by 1 (DF=1)
    assert_scalar(&driver, "rsi", 0x200F);
    // RDI decremented by 1 (DF=1)
    assert_scalar(&driver, "rdi", 0x300F);
}

/// MOVSQ with DF=0: copies qword from [RSI] to [RDI], increments both by 8.
/// Per AMD64 manual: MOVSQ moves qword at [RSI] to [RDI].
/// If DF=0, RSI and RDI are incremented by 8 (qword size).
/// No flags are affected.
/// movsq = 0x48, 0xa5 (REX.W prefix + opcode).
#[test]
fn movsq_df_clear() {
    // movsq  =>  48 a5
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x48, 0xa5, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0xDEADBEEFCAFEBABE, 64))],
    );

    let driver = step_to(driver, 0x2);

    // Qword should be copied from [RSI] to [RDI]
    assert_eq!(
        load_memory(&driver, 0x3000, 64),
        0xDEADBEEFCAFEBABE,
        "memory at 0x3000 should contain qword copied from 0x2000"
    );
    // RSI incremented by 8 (DF=0, qword)
    assert_scalar(&driver, "rsi", 0x2008);
    // RDI incremented by 8 (DF=0, qword)
    assert_scalar(&driver, "rdi", 0x3008);
}

/// MOVSB with DF=0: verify source memory is unchanged after copy.
/// Per AMD64 manual: MOVS copies data; it does not clear the source.
#[test]
fn movsb_source_unchanged() {
    // movsb  =>  a4
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xa4, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rdi", il::const_(0x3000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0xAB, 8))],
    );

    let driver = step_to(driver, 0x1);

    // Source memory at 0x2000 should still contain the original byte
    assert_eq!(
        load_memory(&driver, 0x2000, 8),
        0xAB,
        "source memory should remain unchanged after MOVSB"
    );
    // Destination should have the copy
    assert_eq!(
        load_memory(&driver, 0x3000, 8),
        0xAB,
        "destination should contain the copied byte"
    );
}
