use super::*;

/// BSR rax, rbx: find highest set bit in a non-zero source.
/// rbx = 0x80 (bit 7 is the highest set bit).
/// Per AMD64 manual: ZF = 0 (source is non-zero), rax = 7 (index of highest set bit).
#[test]
fn bsr_finds_highest_set_bit() {
    // bsr rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xbd, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xDEAD, 64)),
            ("rbx", il::const_(0x80, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "ZF", 0);
    assert_scalar(&driver, "rax", 7);
}

/// BSR rax, rbx: source is zero.
/// rbx = 0. Per AMD64 manual: ZF = 1, dest is undefined (we do not check rax).
#[test]
fn bsr_zero_source() {
    // bsr rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xbd, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xDEAD, 64)),
            ("rbx", il::const_(0, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "ZF", 1);
    // dest is undefined when source is zero per the AMD64 manual,
    // so we do not assert rax.
}
