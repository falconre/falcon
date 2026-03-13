use super::*;

#[test]
fn pmovmskb_mixed() {
    // pmovmskb edx, xmm4
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xd7, 0xd4, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![(
            "xmm4",
            mk128const(0x00ff_00ff_0000_0000, 0xffff_ffff_ff00_ff00),
        )],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_eq!(
        driver
            .state()
            .get_scalar("rdx")
            .unwrap()
            .value_u64()
            .unwrap(),
        0b0101_0000_1111_1010
    );
}
