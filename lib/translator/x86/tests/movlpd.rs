use super::*;

/// MOVLPD xmm0, [rax]: load 64-bit from memory into low quadword of XMM.
/// Per AMD64 manual: xmm0[63:0] <- mem64, xmm0[127:64] unchanged.
/// No flags affected.
#[test]
fn movlpd_xmm0_mem() {
    // movlpd xmm0, [rax]  =>  66 0f 12 00  (66 0F 12 /r, ModRM mod=00 reg=xmm0 rm=rax)
    // nop                  =>  90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x12, 0x00, 0x90];

    let addr: u64 = 0x1000;
    let mem_value: u64 = 0xAAAABBBBCCCCDDDD;
    let xmm0_lo_init: u64 = 0x1111222233334444;
    let xmm0_hi_init: u64 = 0x5555666677778888;

    let mut memory = Memory::new(Endian::Little);
    memory.store(addr, il::const_(mem_value, 64)).unwrap();

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(xmm0_hi_init, xmm0_lo_init)),
            ("rax", il::const_(addr, 64)),
        ],
        memory,
    );

    let driver = step_to(driver, 0x4);

    // Low quadword updated from memory, high quadword unchanged
    assert_xmm(&driver, "xmm0", xmm0_hi_init, mem_value);
}
