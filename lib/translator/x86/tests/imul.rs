use super::*;

/// IMUL rbx (one-operand, 64-bit signed multiply): RDX:RAX = RAX * RBX (signed).
/// Small positive: RAX=7, RBX=3 → result=21, fits in lower 64 bits sign-extended.
/// Expected: RDX=0, RAX=21, CF=0, OF=0.
#[test]
fn imul_r64_one_operand_small_positive() {
    // imul rbx; nop → 48 f7 eb 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xeb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(7, 64)),
            ("rbx", il::const_(3, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 21);
    assert_scalar(&driver, "rdx", 0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
}

/// IMUL rbx (one-operand, 64-bit signed multiply): negative result.
/// RAX = -3 (0xFFFFFFFFFFFFFFFD), RBX = 4 → signed result = -12.
/// -12 as 128-bit signed = RDX:RAX where RDX=0xFFFFFFFFFFFFFFFF, RAX=0xFFFFFFFFFFFFFFF4.
/// The result fits in 64 bits sign-extended (sign bit of RAX matches all of RDX),
/// so CF=0, OF=0.
#[test]
fn imul_r64_one_operand_negative_result() {
    // imul rbx; nop → 48 f7 eb 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xeb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFFFD, 64)), // -3
            ("rbx", il::const_(4, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFF4); // -12
    assert_scalar(&driver, "rdx", 0xFFFFFFFFFFFFFFFF);  // sign extension of negative result
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
}

/// IMUL rax, rbx (two-operand, 64-bit signed multiply): rax = rax * rbx (truncated).
/// RAX=10, RBX=20 → RAX=200. Result fits in 64 bits signed, so CF=0, OF=0.
#[test]
fn imul_r64_two_operand_simple() {
    // imul rax, rbx; nop → 48 0f af c3 90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xaf, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(10, 64)),
            ("rbx", il::const_(20, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_scalar(&driver, "rax", 200);
}
