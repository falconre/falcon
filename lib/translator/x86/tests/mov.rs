use super::*;

/// MOV rax, rbx: register-to-register move.
/// Per AMD64 manual: dest <- src, no flags affected.
/// rax should receive rbx's value; rbx unchanged.
#[test]
fn mov_reg_to_reg() {
    // mov rax, rbx  =>  48 89 d8  (REX.W + MOV r/m64,r64 + ModRM)
    // nop           =>  90
    let bytes: Vec<u8> = vec![0x48, 0x89, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xAAAAAAAAAAAAAAAA, 64)),
            ("rbx", il::const_(0x123456789ABCDEF0, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // rax = rbx's original value
    assert_scalar(&driver, "rax", 0x123456789ABCDEF0);
    // rbx unchanged
    assert_scalar(&driver, "rbx", 0x123456789ABCDEF0);
}

/// MOV rax, [rbx]: load 64-bit value from memory at address in rbx.
/// Per AMD64 manual: dest <- [src], no flags affected.
#[test]
fn mov_memory_load() {
    // mov rax, [rbx]  =>  48 8b 03  (REX.W + MOV r64,r/m64 + ModRM mod=00 reg=rax rm=rbx)
    // nop             =>  90
    let bytes: Vec<u8> = vec![0x48, 0x8b, 0x03, 0x90];

    let addr: u64 = 0x1000;
    let mem_value: u64 = 0xDEADBEEFCAFEBABE;

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![("rax", il::const_(0, 64)), ("rbx", il::const_(addr, 64))],
        vec![(addr, il::const_(mem_value, 64))],
    );

    let driver = step_to(driver, 0x3);

    // rax should contain the value loaded from memory
    assert_scalar(&driver, "rax", mem_value);
    // rbx unchanged
    assert_scalar(&driver, "rbx", addr);
}
