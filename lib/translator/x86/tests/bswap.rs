use super::*;

/// BSWAP rax: byte-swap a 64-bit register.
/// rax = 0x0123456789ABCDEF
/// Result = 0xEFCDAB8967452301 (bytes reversed)
/// No flags affected by BSWAP.
#[test]
fn bswap_rax_64() {
    // bswap rax; nop
    // Encoding: REX.W(48) 0F C8+rd (rd=0 for rax); nop=90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0123456789ABCDEF, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xEFCDAB8967452301);
}

/// BSWAP rax: byte-swap with sequential byte pattern for easy verification.
/// rax = 0x0102030405060708
/// Result = 0x0807060504030201 (bytes reversed)
#[test]
fn bswap_rax_sequential() {
    // bswap rax; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0102030405060708, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0807060504030201);
}
