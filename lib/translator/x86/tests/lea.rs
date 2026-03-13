use super::*;
use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

#[test]
fn lea_basic() {
    // lea ecx, [rax - 0x3]
    let bytes: Vec<u8> = vec![0x8d, 0x48, 0xfd];

    let translator = Amd64::new();

    let _ = translator
        .translate_block(&bytes, 0, &Options::new())
        .unwrap();
}

/// LEA rax, [rbx + 0x100]: simple base + displacement addressing.
/// Per AMD64 manual: LEA computes the effective address and stores it in dest.
/// No memory access, no flags affected.
/// rax = rbx + 0x100
#[test]
fn lea_base_plus_disp() {
    // lea rax, [rbx + 0x100]  =>  48 8d 83 00 01 00 00
    //   (REX.W + LEA r64,m + ModRM mod=10 reg=rax rm=rbx + disp32=0x100)
    // nop                     =>  90
    let bytes: Vec<u8> = vec![0x48, 0x8d, 0x83, 0x00, 0x01, 0x00, 0x00, 0x90];

    let rbx_val: u64 = 0x0000000000002000;

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0, 64)), ("rbx", il::const_(rbx_val, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x7);

    // rax = rbx + 0x100 = 0x2000 + 0x100 = 0x2100
    assert_scalar(&driver, "rax", 0x2100);
    // rbx unchanged
    assert_scalar(&driver, "rbx", rbx_val);
}

/// LEA rax, [rbx + rcx*4 + 0x10]: complex SIB addressing mode.
/// Per AMD64 manual: LEA computes effective address = base + index*scale + displacement.
/// No memory access, no flags affected.
/// rax = rbx + rcx*4 + 0x10
#[test]
fn lea_sib_complex() {
    // lea rax, [rbx + rcx*4 + 0x10]  =>  48 8d 44 8b 10
    //   (REX.W + LEA r64,m + ModRM mod=01 reg=rax rm=100(SIB) + SIB scale=10 index=rcx base=rbx + disp8=0x10)
    // nop                             =>  90
    let bytes: Vec<u8> = vec![0x48, 0x8d, 0x44, 0x8b, 0x10, 0x90];

    let rbx_val: u64 = 0x0000000000001000;
    let rcx_val: u64 = 0x0000000000000008;

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0, 64)),
            ("rbx", il::const_(rbx_val, 64)),
            ("rcx", il::const_(rcx_val, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // rax = rbx + rcx*4 + 0x10 = 0x1000 + 0x8*4 + 0x10 = 0x1000 + 0x20 + 0x10 = 0x1030
    assert_scalar(&driver, "rax", 0x1030);
    // rbx and rcx unchanged
    assert_scalar(&driver, "rbx", rbx_val);
    assert_scalar(&driver, "rcx", rcx_val);
}
