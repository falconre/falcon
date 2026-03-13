use super::*;

/// MOVQ xmm0, rax: move 64-bit value from GPR to low quadword of XMM.
/// Per AMD64 manual (MOVQ with 66 REX.W 0F 6E): dest[63:0] <- src, dest[127:64] <- 0.
/// The upper 64 bits of xmm0 must be zeroed.
#[test]
fn movq_xmm0_rax_upper_zeroed() {
    // movq xmm0, rax  =>  66 48 0f 6e c0  (66 REX.W 0F 6E /r, ModRM mod=11 reg=xmm0 rm=rax)
    // nop             =>  90
    let bytes: Vec<u8> = vec![0x66, 0x48, 0x0f, 0x6e, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)),
            ("rax", il::const_(0xDEADBEEFCAFEBABE, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // xmm0 low 64 = rax value, xmm0 high 64 = 0
    assert_xmm(&driver, "xmm0", 0x0000000000000000, 0xDEADBEEFCAFEBABE);
}
