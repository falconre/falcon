use super::*;

#[test]
fn rol_basic() {
    // rol rax, 0x11
    // nop
    let bytes: Vec<u8> = vec![0x48, 0xc1, 0xc0, 0x11, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xbfeffffffd00, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_eq!(
        driver.state().get_scalar("rax").unwrap(),
        &il::const_(0x7fdffffffa000001, 64)
    );
}
