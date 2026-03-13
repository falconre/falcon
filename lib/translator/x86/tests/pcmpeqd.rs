use super::*;

#[test]
fn pcmpeqd_all_equal() {
    // pcmpeqd xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x76, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes.clone(),
        vec![
            (
                "xmm0",
                mk128const(0x0000_0000_1111_1111, 0x2222_2222_3333_3333),
            ),
            (
                "xmm1",
                mk128const(0x0000_0000_1111_1111, 0x2222_2222_3333_3333),
            ),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_xmm(&driver, "xmm0", 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff);
}

#[test]
fn pcmpeqd_partial_match() {
    // pcmpeqd xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x76, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            (
                "xmm0",
                mk128const(0x0000_0000_1111_1111, 0x2232_2222_3333_3333),
            ),
            (
                "xmm1",
                mk128const(0x0000_0000_1111_1111, 0x2222_2222_3333_3333),
            ),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_xmm(&driver, "xmm0", 0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff);
}
