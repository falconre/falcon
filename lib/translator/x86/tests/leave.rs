use super::*;

/// LEAVE: restore stack frame. Equivalent to MOV RSP, RBP; POP RBP.
/// Per AMD64 manual: RSP = RBP, then RBP = [RSP], then RSP = RSP + 8.
/// No flags affected.
/// leave = 0xc9.
/// Set RBP=0x2000, mem[0x2000]=0x0000000000003000 (saved RBP).
/// After: RSP=0x2008, RBP=0x3000.
#[test]
fn leave_basic() {
    // leave  =>  c9
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xc9, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1000, 64)),
            ("rbp", il::const_(0x2000, 64)),
        ],
        vec![(0x2000, il::const_(0x0000000000003000, 64))],
    );

    let driver = step_to(driver, 0x1);

    // After LEAVE: RSP = old RBP + 8 = 0x2000 + 8 = 0x2008
    assert_scalar(&driver, "rsp", 0x2008);
    // RBP = value popped from [old RBP] = mem[0x2000] = 0x3000
    assert_scalar(&driver, "rbp", 0x0000000000003000);
}

/// LEAVE: verify RSP takes RBP's value before pop.
/// Per AMD64 manual: first RSP = RBP, then POP RBP (reads from new RSP = old RBP).
/// Set RBP=0x3000, RSP=0x1000 (different from RBP).
/// mem[0x3000]=0x00000000DEADBEEF (saved frame pointer at RBP).
/// After: RSP=0x3008, RBP=0xDEADBEEF.
#[test]
fn leave_rsp_from_rbp() {
    // leave  =>  c9
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xc9, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x1000, 64)),
            ("rbp", il::const_(0x3000, 64)),
        ],
        vec![(0x3000, il::const_(0x00000000DEADBEEF, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RSP = old RBP + 8 = 0x3000 + 8 = 0x3008
    assert_scalar(&driver, "rsp", 0x3008);
    // RBP = mem[old RBP] = mem[0x3000] = 0xDEADBEEF
    assert_scalar(&driver, "rbp", 0x00000000DEADBEEF);
}

/// LEAVE: verify with zero saved frame pointer.
/// Per AMD64 manual: RSP = RBP, then POP RBP.
/// mem[RBP] = 0 (null frame pointer, common for outermost frame).
/// After: RSP = old RBP + 8, RBP = 0.
#[test]
fn leave_null_saved_rbp() {
    // leave  =>  c9
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xc9, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rsp", il::const_(0x5000, 64)),
            ("rbp", il::const_(0x4000, 64)),
        ],
        vec![(0x4000, il::const_(0x0, 64))],
    );

    let driver = step_to(driver, 0x1);

    // RSP = old RBP + 8 = 0x4000 + 8 = 0x4008
    assert_scalar(&driver, "rsp", 0x4008);
    // RBP = mem[old RBP] = mem[0x4000] = 0
    assert_scalar(&driver, "rbp", 0x0);
}
