use architecture;
use architecture::Endian;
use executor::*;
use il;
use memory;
use translator::x86::Amd64;
use translator::Translator;
use RC;

fn init_amd64_driver<'d>(
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
        .len()
        == 0
    {
        il::ProgramLocation::new(Some(0), il::FunctionLocation::EmptyBlock(0))
    } else {
        il::ProgramLocation::new(Some(0), il::FunctionLocation::Instruction(0, 0))
    };

    // println!("{}", function.control_flow_graph().graph().dot_graph());

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

#[test]
fn lea() {
    // lea ecx, [rax - 0x3]
    let bytes: Vec<u8> = vec![0x8d, 0x48, 0xfd];

    let translator = Amd64::new();

    let _ = translator.translate_block(&bytes, 0).unwrap();
}

#[test]
fn pcmpeqd() {
    // pcmeqd xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x76, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes.clone(),
        vec![
            ("xmm0", mk128const(0x00000000_11111111, 0x22222222_33333333)),
            ("xmm1", mk128const(0x00000000_11111111, 0x22222222_33333333)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert!(eval(
        &il::Expression::cmpeq(
            driver.state().get_scalar("xmm0").unwrap().clone().into(),
            mk128const(0xffffffff_ffffffff, 0xffffffff_ffffffff).into()
        )
        .unwrap()
    )
    .unwrap()
    .is_one());

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x00000000_11111111, 0x22322222_33333333)),
            ("xmm1", mk128const(0x00000000_11111111, 0x22222222_33333333)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert!(eval(
        &il::Expression::cmpeq(
            driver.state().get_scalar("xmm0").unwrap().clone().into(),
            mk128const(0xffffffff_ffffffff, 0x00000000_ffffffff).into()
        )
        .unwrap()
    )
    .unwrap()
    .is_one());
}

#[test]
fn pcmpeqb() {
    // pcmeqb xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x74, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes.clone(),
        vec![
            ("xmm0", mk128const(0x00000000_11111111, 0x22222222_33333333)),
            ("xmm1", mk128const(0x00000000_11111111, 0x55555555_00113322)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert!(eval(
        &il::Expression::cmpeq(
            driver.state().get_scalar("xmm0").unwrap().clone().into(),
            mk128const(0xffffffff_ffffffff, 0x00000000_0000ff00).into()
        )
        .unwrap()
    )
    .unwrap()
    .is_one());
}

#[test]
fn pmovmskb() {
    // pcmeqb xmm0, xmm1
    // nop
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xd7, 0xd4, 0x90];

    let driver = init_amd64_driver(
        bytes.clone(),
        vec![("xmm4", mk128const(0x00ff00ff_00000000, 0xffffffff_ff00ff00))],
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
        0b01010000_11111010
    );
}
