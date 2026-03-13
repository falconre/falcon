use super::*;

#[test]
fn ror_basic() {
    // ror r8, 0x11
    // nop
    let bytes: Vec<u8> = vec![0x49, 0xc1, 0xc8, 0x11, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("r8", il::const_(0x7fdfffffed200001, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_eq!(
        driver.state().get_scalar("r8").unwrap(),
        &il::const_(0xbfeffffff690, 64)
    );
}
