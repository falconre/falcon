use super::*;

/// XCHG rax, rbx: exchange values of two registers.
/// Per AMD64 manual: temp <- rax; rax <- rbx; rbx <- temp. No flags affected.
#[test]
fn xchg_rax_rbx() {
    // xchg rax, rbx  =>  48 93  (REX.W + XCHG rAX,r64 short form, opcode 90+rb where rb=3)
    // nop            =>  90
    let bytes: Vec<u8> = vec![0x48, 0x93, 0x90];

    let rax_init: u64 = 0x1111111111111111;
    let rbx_init: u64 = 0x2222222222222222;

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(rax_init, 64)),
            ("rbx", il::const_(rbx_init, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // After XCHG: rax = old rbx, rbx = old rax
    assert_scalar(&driver, "rax", rbx_init);
    assert_scalar(&driver, "rbx", rax_init);
}
