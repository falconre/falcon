use super::*;

#[test]
fn pcmpeqb_mixed() {
    // pcmpeqb xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x74, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            (
                "xmm0",
                mk128const(0x0000_0000_1111_1111, 0x2222_2222_3333_3333),
            ),
            (
                "xmm1",
                mk128const(0x0000_0000_1111_1111, 0x5555_5555_0011_3322),
            ),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_xmm(&driver, "xmm0", 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_ff00);
}
