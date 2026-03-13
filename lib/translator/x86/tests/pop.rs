use super::*;

/// POP rax: pops 64-bit value from stack into register.
/// Per AMD64 manual: dest = [RSP], then RSP = RSP + 8. No flags affected.
/// pop rax = 0x58 (opcode 58+rd, rd=0 for rax).
/// Set RSP=0x1FF8, mem[0x1FF8]=0xDEADBEEFCAFEBABE. After: RAX=0xDEADBEEFCAFEBABE, RSP=0x2000.
#[test]
fn pop_rax() {
    // pop rax  =>  58
    // nop      =>  90
    let bytes: Vec<u8> = vec![0x58, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1FF8, 64)),
            ("rax", il::const_(0x0, 64)),
        ],
        vec![(0x1FF8, il::const_(0xDEADBEEFCAFEBABE, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RAX receives popped value
    assert_scalar(&driver, "rax", 0xDEADBEEFCAFEBABE);
    // RSP incremented by 8
    assert_scalar(&driver, "rsp", 0x2000);
}

/// POP rbx: pops 64-bit value into a different register.
/// Per AMD64 manual: dest = [RSP], then RSP = RSP + 8. No flags affected.
/// pop rbx = 0x5b (opcode 58+rd, rd=3 for rbx).
#[test]
fn pop_rbx() {
    // pop rbx  =>  5b
    // nop      =>  90
    let bytes: Vec<u8> = vec![0x5b, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1FF8, 64)),
            ("rbx", il::const_(0x0, 64)),
        ],
        vec![(0x1FF8, il::const_(0x0000000000000042, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RBX receives popped value
    assert_scalar(&driver, "rbx", 0x0000000000000042);
    // RSP incremented by 8
    assert_scalar(&driver, "rsp", 0x2000);
}

/// POP rax: pop zero value from stack.
/// Per AMD64 manual: dest = [RSP], then RSP = RSP + 8. No flags affected.
/// Verifies correct behavior when popped value is zero.
#[test]
fn pop_rax_zero() {
    // pop rax  =>  58
    // nop      =>  90
    let bytes: Vec<u8> = vec![0x58, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1FF8, 64)),
            ("rax", il::const_(0xAAAAAAAAAAAAAAAA, 64)),
        ],
        vec![(0x1FF8, il::const_(0x0, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RAX receives zero
    assert_scalar(&driver, "rax", 0x0);
    // RSP incremented by 8
    assert_scalar(&driver, "rsp", 0x2000);
}

/// POP rax: pop all-ones value from stack.
/// Per AMD64 manual: dest = [RSP], then RSP = RSP + 8. No flags affected.
/// Verifies all 64 bits are loaded correctly.
#[test]
fn pop_rax_all_ones() {
    // pop rax  =>  58
    // nop      =>  90
    let bytes: Vec<u8> = vec![0x58, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1FF8, 64)),
            ("rax", il::const_(0x0, 64)),
        ],
        vec![(0x1FF8, il::const_(0xFFFFFFFFFFFFFFFF, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RAX receives all-ones
    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFFF);
    // RSP incremented by 8
    assert_scalar(&driver, "rsp", 0x2000);
}
