use super::*;

/// PUSH rax: pushes 64-bit register onto stack.
/// Per AMD64 manual: RSP = RSP - 8, then [RSP] = src. No flags affected.
/// push rax = 0x50 (opcode 50+rd, rd=0 for rax).
/// Set RSP=0x2000, RAX=0xDEADBEEFCAFEBABE. After: RSP=0x1FF8, mem[0x1FF8]=0xDEADBEEFCAFEBABE.
#[test]
fn push_rax() {
    // push rax  =>  50
    // nop       =>  90
    let bytes: Vec<u8> = vec![0x50, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rsp", il::const_(0x2000, 64)),
            ("rax", il::const_(0xDEADBEEFCAFEBABE, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // RSP decremented by 8
    assert_scalar(&driver, "rsp", 0x1FF8);
    // Value of RAX stored at new RSP
    assert_eq!(
        load_memory(&driver, 0x1FF8, 64),
        0xDEADBEEFCAFEBABE,
        "memory at new RSP should contain pushed RAX value"
    );
    // RAX unchanged
    assert_scalar(&driver, "rax", 0xDEADBEEFCAFEBABE);
}

/// PUSH rbx: pushes a different 64-bit register.
/// Per AMD64 manual: RSP = RSP - 8, then [RSP] = src. No flags affected.
/// push rbx = 0x53 (opcode 50+rd, rd=3 for rbx).
/// Set RSP=0x2000, RBX=0x0000000000000042. After: RSP=0x1FF8, mem[0x1FF8]=0x42.
#[test]
fn push_rbx() {
    // push rbx  =>  53
    // nop       =>  90
    let bytes: Vec<u8> = vec![0x53, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rsp", il::const_(0x2000, 64)),
            ("rbx", il::const_(0x0000000000000042, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // RSP decremented by 8
    assert_scalar(&driver, "rsp", 0x1FF8);
    // Value of RBX stored at new RSP
    assert_eq!(
        load_memory(&driver, 0x1FF8, 64),
        0x0000000000000042,
        "memory at new RSP should contain pushed RBX value"
    );
    // RBX unchanged
    assert_scalar(&driver, "rbx", 0x0000000000000042);
}

/// PUSH rax: push zero value.
/// Per AMD64 manual: RSP = RSP - 8, then [RSP] = src. No flags affected.
/// Verifies correct behavior when pushed value is zero.
#[test]
fn push_rax_zero() {
    // push rax  =>  50
    // nop       =>  90
    let bytes: Vec<u8> = vec![0x50, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rsp", il::const_(0x2000, 64)),
            ("rax", il::const_(0x0, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // RSP decremented by 8
    assert_scalar(&driver, "rsp", 0x1FF8);
    // Zero stored at new RSP
    assert_eq!(
        load_memory(&driver, 0x1FF8, 64),
        0x0,
        "memory at new RSP should contain pushed zero value"
    );
}

/// PUSH rax: push value with all bits set (0xFFFFFFFFFFFFFFFF).
/// Per AMD64 manual: RSP = RSP - 8, then [RSP] = src. No flags affected.
/// Verifies all 64 bits are stored correctly.
#[test]
fn push_rax_all_ones() {
    // push rax  =>  50
    // nop       =>  90
    let bytes: Vec<u8> = vec![0x50, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rsp", il::const_(0x2000, 64)),
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // RSP decremented by 8
    assert_scalar(&driver, "rsp", 0x1FF8);
    // All-ones value stored at new RSP
    assert_eq!(
        load_memory(&driver, 0x1FF8, 64),
        0xFFFFFFFFFFFFFFFF,
        "memory at new RSP should contain 0xFFFFFFFFFFFFFFFF"
    );
}
