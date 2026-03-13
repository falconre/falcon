use super::*;

/// LODSD with DF=0: loads dword from [RSI] into EAX (zero-extends to RAX),
/// increments RSI by 4.
/// Per AMD64 manual: LODSD loads 32 bits from [RSI] into EAX. Writing a
/// 32-bit register in 64-bit mode zero-extends the result to 64 bits (RAX).
/// If DF=0, RSI is incremented by 4. No flags are affected.
/// lodsd = 0xad.
#[test]
fn lodsd_df_clear() {
    // lodsd  =>  ad
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xad, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0x12345678, 32))],
    );

    let driver = step_to(driver, 0x1);

    // EAX = 0x12345678, zero-extended to RAX = 0x0000000012345678
    assert_scalar(&driver, "rax", 0x12345678);
    // RSI incremented by 4 (DF=0, dword)
    assert_scalar(&driver, "rsi", 0x2004);
}

/// LODSD with DF=1: loads dword from [RSI] into EAX, decrements RSI by 4.
/// Per AMD64 manual: If DF=1, RSI is decremented by 4.
/// No flags are affected.
#[test]
fn lodsd_df_set() {
    // lodsd  =>  ad
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xad, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2010, 64)),
            ("rax", il::const_(0x0, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![(0x2010, il::const_(0xAABBCCDD, 32))],
    );

    let driver = step_to(driver, 0x1);

    // EAX = 0xAABBCCDD, zero-extended to RAX
    assert_scalar(&driver, "rax", 0xAABBCCDD);
    // RSI decremented by 4 (DF=1, dword)
    assert_scalar(&driver, "rsi", 0x200C);
}

/// LODSD: 32-bit write to EAX must zero-extend upper 32 bits of RAX.
/// Per AMD64 manual: Writing to a 32-bit register in 64-bit mode
/// zero-extends the result into the full 64-bit register.
/// Start with RAX=0xFFFFFFFFFFFFFFFF, load 0x00000001 into EAX.
/// After: RAX=0x0000000000000001 (upper 32 bits zeroed).
#[test]
fn lodsd_zero_extends_rax() {
    // lodsd  =>  ad
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xad, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0x00000001, 32))],
    );

    let driver = step_to(driver, 0x1);

    // Upper 32 bits of RAX must be zeroed by the 32-bit EAX write
    assert_scalar(&driver, "rax", 0x0000000000000001);
}

/// LODSD: source memory should remain unchanged after load.
/// Per AMD64 manual: LODS reads memory; it does not modify it.
#[test]
fn lodsd_memory_unchanged() {
    // lodsd  =>  ad
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xad, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsi", il::const_(0x2000, 64)),
            ("rax", il::const_(0x0, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x2000, il::const_(0xDEADBEEF, 32))],
    );

    let driver = step_to(driver, 0x1);

    // Source memory should still contain the original dword
    assert_eq!(
        load_memory(&driver, 0x2000, 32),
        0xDEADBEEF,
        "source memory should remain unchanged after LODSD"
    );
}
