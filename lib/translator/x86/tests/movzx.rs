use super::*;

#[test]
fn movd_to_xmm() {
    // movd xmm1, esi
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x6e, 0xce, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            (
                "xmm1",
                mk128const(0x0000_0000_1111_1111, 0x2222_2222_3333_3333),
            ),
            ("rsi", il::const_(0x1111_2222_dead_beef, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_eq!(driver.state().get_scalar("xmm1").unwrap().bits(), 128);

    assert!(eval(
        &il::Expression::cmpeq(
            driver.state().get_scalar("xmm1").unwrap().clone().into(),
            mk128const(0x0000_0000_0000_0000, 0x0000_0000_dead_beef).into()
        )
        .unwrap()
    )
    .unwrap()
    .is_one());
}
