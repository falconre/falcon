use super::*;

/// CMPXCHG rbx, rcx: equal case (RAX == dest).
/// Per AMD64 manual: Compare RAX with dest (rbx). If equal, ZF=1 and dest <- src (rcx).
/// RAX is unchanged. Flags set per CMP of RAX vs dest (subtraction RAX - dest).
///
/// RAX = 0x0000000000001234, RBX = 0x0000000000001234, RCX = 0x00000000ABCD0000.
/// RAX == RBX, so: ZF=1, RBX <- RCX = 0x00000000ABCD0000, RAX unchanged.
/// CMP result: RAX - RBX = 0 => CF=0, OF=0, ZF=1, SF=0.
#[test]
fn cmpxchg_equal() {
    // cmpxchg rbx, rcx  =>  48 0f b1 cb  (REX.W + 0F B1 /r, ModRM cb = 11 001 011)
    // nop               =>  90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xb1, 0xcb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000001234, 64)),
            ("rbx", il::const_(0x0000000000001234, 64)),
            ("rcx", il::const_(0x00000000ABCD0000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // RAX == RBX (equal case): dest (rbx) gets src (rcx), RAX unchanged
    assert_scalar(&driver, "rax", 0x0000000000001234);
    assert_scalar(&driver, "rbx", 0x00000000ABCD0000);
    // RCX should be unchanged (it was the source operand)
    assert_scalar(&driver, "rcx", 0x00000000ABCD0000);

    // Flags from CMP (RAX - RBX = 0x1234 - 0x1234 = 0)
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "SF", 0);
}

/// CMPXCHG rbx, rcx: not-equal case (RAX != dest).
/// Per AMD64 manual: Compare RAX with dest (rbx). If not equal, ZF=0 and RAX <- dest.
/// Dest (rbx) is unchanged. Flags set per CMP of RAX vs dest (subtraction RAX - dest).
///
/// RAX = 0x0000000000000001, RBX = 0x0000000000000005, RCX = 0xAAAAAAAAAAAAAAAA.
/// RAX != RBX, so: ZF=0, RAX <- RBX = 0x0000000000000005, RBX unchanged.
/// CMP result: RAX - RBX = 0x1 - 0x5 = underflow => CF=1, SF=1, OF=0.
#[test]
fn cmpxchg_not_equal() {
    // cmpxchg rbx, rcx  =>  48 0f b1 cb  (REX.W + 0F B1 /r, ModRM cb = 11 001 011)
    // nop               =>  90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xb1, 0xcb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rbx", il::const_(0x0000000000000005, 64)),
            ("rcx", il::const_(0xAAAAAAAAAAAAAAAA, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // RAX != RBX (not-equal case): RAX gets dest (rbx), dest unchanged
    assert_scalar(&driver, "rax", 0x0000000000000005);
    assert_scalar(&driver, "rbx", 0x0000000000000005);
    // RCX should be unchanged (it was the source operand, not used)
    assert_scalar(&driver, "rcx", 0xAAAAAAAAAAAAAAAA);

    // Flags from CMP (RAX - RBX = 0x1 - 0x5):
    // Unsigned borrow: 1 < 5 => CF=1
    // Result (mod 2^64) = 0xFFFFFFFFFFFFFFFC, MSB=1 => SF=1
    // No signed overflow (small positive - small positive) => OF=0
    // Result != 0 => ZF=0
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "SF", 1);
    assert_flag(&driver, "OF", 0);
}
