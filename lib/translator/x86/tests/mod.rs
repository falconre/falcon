use crate::architecture;
use crate::architecture::Endian;
use crate::executor::*;
use crate::il;
use crate::memory;
use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};
use crate::RC;

mod adc;
mod add;
mod and;
mod bsf;
mod bsr;
mod bswap;
mod bt;
mod btc;
mod btr;
mod bts;
mod call;
mod cbw;
mod cdq;
mod cdqe;
mod cjmp;
mod clc;
mod cld;
mod cli;
mod cmc;
mod cmovcc;
mod cmp;
mod cmpxchg;
mod cmpsb;
mod cwd;
mod cwde;
mod dec;
mod div;
mod idiv;
mod imul;
mod inc;
mod int;
mod jmp;
mod lea;
mod leave;
mod lodsb;
mod lodsd;
mod loop_;
mod mov;
mod movhpd;
mod movlpd;
mod movq;
mod movs;
mod movsx;
mod movzx;
mod mul;
mod neg;
mod nop;
mod not;
mod or;
mod paddq;
mod pcmpeqb;
mod pcmpeqd;
mod pmovmskb;
mod pminub;
mod pop;
mod por;
mod pshufd;
mod pslldq;
mod psrldq;
mod psubb;
mod psubq;
mod punpcklbw;
mod punpcklwd;
mod push;
mod pxor;
mod ret;
mod rol;
mod ror;
mod sahf;
mod sar;
mod sbb;
mod scasb;
mod scasw;
mod setcc;
mod shl;
mod shld;
mod shr;
mod shrd;
mod stc;
mod std_;
mod sti;
mod stos;
mod sub;
mod sub_test;
mod syscall_;
mod sysenter;
mod ud2;
mod xadd;
mod xchg;
mod xor;

fn init_amd64_driver(
    instruction_bytes: Vec<u8>,
    scalars: Vec<(&str, il::Constant)>,
    memory_: Memory,
) -> Driver {
    let mut backing = memory::backing::Memory::new(Endian::Little);
    backing.set_memory(
        0,
        instruction_bytes,
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ,
    );

    let function = Amd64::new().translate_function(&backing, 0).unwrap();

    let location = if function
        .control_flow_graph()
        .block(0)
        .unwrap()
        .instructions()
        .is_empty()
    {
        il::ProgramLocation::new(Some(0), il::FunctionLocation::EmptyBlock(0))
    } else {
        il::ProgramLocation::new(Some(0), il::FunctionLocation::Instruction(0, 0))
    };

    let mut program = il::Program::new();
    program.add_function(function);

    let mut state = State::new(memory_);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(
        RC::new(program),
        location,
        state,
        RC::new(architecture::Amd64::new()),
    )
}

fn step_to(mut driver: Driver, target_address: u64) -> Driver {
    loop {
        driver = driver.step().unwrap();
        if let Some(address) = driver.location().apply(driver.program()).unwrap().address() {
            if address == target_address {
                return driver;
            }
        }
    }
}

fn mk128const(lo: u64, hi: u64) -> il::Constant {
    eval(
        &il::Expression::or(
            il::Expression::shl(
                il::Expression::zext(128, il::expr_const(lo, 64)).unwrap(),
                il::expr_const(64, 128),
            )
            .unwrap(),
            il::Expression::zext(128, il::expr_const(hi, 64)).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

/// Convenience: create driver with pre-populated memory at given addresses.
fn init_amd64_driver_with_memory(
    instruction_bytes: Vec<u8>,
    scalars: Vec<(&str, il::Constant)>,
    memory_writes: Vec<(u64, il::Constant)>,
) -> Driver {
    let mut memory = Memory::new(Endian::Little);
    for (addr, val) in memory_writes {
        memory.store(addr, val).unwrap();
    }
    init_amd64_driver(instruction_bytes, scalars, memory)
}

/// Assert a scalar register has the expected u64 value.
fn assert_scalar(driver: &Driver, name: &str, expected: u64) {
    let val = driver.state().get_scalar(name).unwrap();
    assert_eq!(
        val.value_u64().unwrap(),
        expected,
        "scalar {} expected 0x{:x}, got 0x{:x}",
        name,
        expected,
        val.value_u64().unwrap()
    );
}

/// Assert a 1-bit flag has the expected value (0 or 1).
fn assert_flag(driver: &Driver, name: &str, expected: u64) {
    let val = driver.state().get_scalar(name).unwrap();
    assert_eq!(
        val.value_u64().unwrap(),
        expected,
        "flag {} expected {}, got {}",
        name,
        expected,
        val.value_u64().unwrap()
    );
}

/// Assert a 128-bit XMM register equals the given lo/hi qwords.
fn assert_xmm(driver: &Driver, name: &str, lo: u64, hi: u64) {
    let val = driver.state().get_scalar(name).unwrap();
    assert_eq!(val.bits(), 128, "expected {} to be 128 bits", name);
    let expected = mk128const(lo, hi);
    assert!(
        eval(
            &il::Expression::cmpeq(val.clone().into(), expected.into())
                .unwrap()
        )
        .unwrap()
        .is_one(),
        "{} expected lo=0x{:016x} hi=0x{:016x}",
        name,
        lo,
        hi
    );
}

/// Load a value from executor memory.
fn load_memory(driver: &Driver, address: u64, bits: usize) -> u64 {
    driver
        .state()
        .memory()
        .load(address, bits)
        .unwrap()
        .unwrap()
        .value_u64()
        .unwrap()
}
