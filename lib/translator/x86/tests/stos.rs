use super::*;

/// STOSB with DF=0: stores AL to [RDI], increments RDI by 1.
/// Per AMD64 manual: STOSB stores the byte in AL at [RDI].
/// If DF=0, RDI is incremented by 1. No flags are affected.
/// stosb = 0xaa.
#[test]
fn stosb_df_clear() {
    // stosb  =>  aa
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xaa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x55, 64)),
            ("DF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // AL (low byte of RAX = 0x55) stored at [RDI]
    assert_eq!(
        load_memory(&driver, 0x3000, 8),
        0x55,
        "memory at 0x3000 should contain AL value"
    );
    // RDI incremented by 1 (DF=0)
    assert_scalar(&driver, "rdi", 0x3001);
}

/// STOSB with DF=1: stores AL to [RDI], decrements RDI by 1.
/// Per AMD64 manual: If DF=1, RDI is decremented by 1.
/// No flags are affected.
#[test]
fn stosb_df_set() {
    // stosb  =>  aa
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xaa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rdi", il::const_(0x3010, 64)),
            ("rax", il::const_(0xCC, 64)),
            ("DF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // AL (low byte of RAX = 0xCC) stored at [RDI]
    assert_eq!(
        load_memory(&driver, 0x3010, 8),
        0xCC,
        "memory at 0x3010 should contain AL value"
    );
    // RDI decremented by 1 (DF=1)
    assert_scalar(&driver, "rdi", 0x300F);
}

/// STOSB: only the low byte of RAX (AL) should be stored, not upper bytes.
/// Per AMD64 manual: STOSB stores exactly one byte from AL.
/// RAX=0xAABBCCDD11223344, only 0x44 should be stored.
#[test]
fn stosb_only_low_byte() {
    // stosb  =>  aa
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xaa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0xAABBCCDD11223344, 64)),
            ("DF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // Only AL (0x44) should be stored, not upper bytes
    assert_eq!(
        load_memory(&driver, 0x3000, 8),
        0x44,
        "STOSB should store only AL (low byte of RAX)"
    );
    // RDI incremented by 1
    assert_scalar(&driver, "rdi", 0x3001);
}

/// STOSB: RAX should remain unchanged after the store.
/// Per AMD64 manual: STOS does not modify RAX/EAX/AX/AL.
#[test]
fn stosb_rax_unchanged() {
    // stosb  =>  aa
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xaa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0xDEADBEEF, 64)),
            ("DF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // RAX should be unchanged
    assert_scalar(&driver, "rax", 0xDEADBEEF);
}
