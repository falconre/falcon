use executor::*;
use il::*;
use std::rc::Rc;
use translator::mips::*;
use types::Endian;


fn init_driver_block<'d>(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    memory: memory::Memory,
    arch: &'d ::translator::Arch
) -> driver::Driver<'d> {
    let mut bytes = vec![0x00, 0x00, 0x00, 0x00];
    bytes.append(&mut instruction_bytes.to_vec());
    bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00]);

    let block_translation_result = Mips::new().translate_block(&bytes, 0).unwrap();
    let control_flow_graph = block_translation_result.control_flow_graph();
    let function = Function::new(0, control_flow_graph.clone());
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(0, FunctionLocation::EmptyBlock(0));

    let mut engine = engine::Engine::new(memory);
    for scalar in scalars {
        engine.set_scalar(scalar.0, scalar.1);
    }

    driver::Driver::new(Rc::new(program), location, engine, arch)
}


fn init_driver_function<'d>(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    mut memory: memory::Memory,
    arch: &'d ::translator::Arch
) -> driver::Driver<'d> {
    for i in 0..instruction_bytes.len() {
        memory.store(i as u64, expr_const(instruction_bytes[i] as u64, 8))
              .unwrap();
    }

    let function = arch.translate_function(&memory, 0).unwrap();
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(0, FunctionLocation::Instruction(0, 0));

    let mut engine = engine::Engine::new(memory);
    for scalar in scalars {
        engine.set_scalar(scalar.0, scalar.1);
    }

    driver::Driver::new(Rc::new(program), location, engine, arch)
}


fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    memory: memory::Memory,
    result_scalar: &str
) -> Constant {

    let arch = Mips::new();

    let mut driver = init_driver_block(instruction_bytes, scalars, memory, &arch);
    let num_blocks = driver.program()
                           .function(0)
                           .unwrap()
                           .control_flow_graph()
                           .blocks()
                           .len();

    loop {
        driver = driver.step().unwrap();
        if let Some(index) = driver.location().block_index() {
            if index == num_blocks as u64 - 1 {
                break;
            }
        }
    }

    return driver.engine()
                 .symbolize_and_eval(driver.engine().get_scalar(result_scalar).unwrap())
                 .unwrap();
}


fn get_raise(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    memory: memory::Memory
) -> Option<Expression> {

    let arch = Mips::new();

    let mut driver = init_driver_block(instruction_bytes, scalars, memory, &arch);
    let num_blocks = driver.program()
                           .function(0)
                           .unwrap()
                           .control_flow_graph()
                           .blocks()
                           .len();

    loop {
        driver = driver.step().unwrap();
        let location = driver.location().apply(driver.program()).unwrap();
        if let Some(instruction) = location.instruction() {
            if let Operation::Raise { ref expr } = *instruction.operation() {
                return Some(expr.clone());
            }
        }
        if let Some(index) = driver.location().block_index() {
            if index == num_blocks as u64 - 1 {
                break;
            }
        }
    }

    None
}


fn step_to<'d>(mut driver: driver::Driver<'d>, target_address: u64)
-> driver::Driver<'d> {

    loop {
        driver = driver.step().unwrap();
        if let Some(address) = driver.location()
                                     .apply(driver.program())
                                     .unwrap()
                                     .address() {
            if address == target_address {
                return driver;
            }
        }
    }
}


#[test]
fn add() {
    // add $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x20];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(1, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", expr_const(0x7fffffff, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big)
    ).unwrap();
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", expr_const(0xffffffff, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big)
    ).unwrap();
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }
}


#[test]
fn addi() {
    // addi $a0, $a1, 0x1234
    let instruction_bytes = &[0x20, 0xa4, 0x12, 0x34];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1235);


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", expr_const(0x7fffffff, 32))],
        memory::Memory::new(Endian::Big)
    ).unwrap();
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }
}


#[test]
fn addiu() {
    // addiu $a0, $a1, 0x1234
    let instruction_bytes = &[0x24, 0xa4, 0x12, 0x34];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1235);

    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(0x7fffffff, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x80001233);
}


#[test]
fn addu() {
    // addu $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x21];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(1, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(0x7fffffff, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x80000000);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(0xffffffff, 32)),
             ("$a2", expr_const(1, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
}


#[test]
fn and() {
    // and $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x24];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(0x8000ffff, 32)),
             ("$a2", expr_const(0x1234, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);
}


#[test]
fn andi() {
    // andi $a0, $a1, 0x1234
    let instruction_bytes = &[0x30, 0xa4, 0x12, 0x34];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", expr_const(0x8000ffff, 32))],
        memory::Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);
}


#[test]
fn b() {

    /*
    b target
    ori $a0, $a0, 0
    ori $a0, $a0, 1
    ori $a0, $a0, 1
    target :
    ori $a0, $a0, 2
    jr $ra
    nop
    */
    let instruction_bytes = &[
        0x10, 0x00, 0x00, 0x03,
        0x34, 0x84, 0x00, 0x00,
        0x34, 0x84, 0x00, 0x01,
        0x34, 0x84, 0x00, 0x01,
        0x34, 0x84, 0x00, 0x02,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ];
    
    let arch = Mips::new();

    let driver = init_driver_function(
        instruction_bytes,
        vec![("$a0", expr_const(0, 32))],
        memory::Memory::new(Endian::Big),
        &arch
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(
        eval(driver.engine().get_scalar("$a0").unwrap()).unwrap().value(),
        0x2
    );
}


#[test]
fn bal() {

    /*
    ori $a0, $a0, 0
    bal target
    addi $a0, $a0, 0x1234
    nop
    nop
    target :
    jr $ra
    nop
    */
    let instruction_bytes = &[
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x11, 0x00, 0x03,
        0x20, 0x84, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ];

    let arch = Mips::new();

    let driver = init_driver_function(
        instruction_bytes,
        vec![("$a0", expr_const(0, 32))],
        memory::Memory::new(Endian::Big),
        &arch
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(
        eval(driver.engine().get_scalar("$a0").unwrap()).unwrap().value(),
        0x1234
    );

    assert_eq!(
        eval(driver.engine().get_scalar("$ra").unwrap()).unwrap().value(),
        0xc
    );
}


#[test]
fn beq() {

    /*
    addiu $a0, $zero, 0x10
    addiu $a1, $zero, 0x10
    beq $a0, $a1, 0x14
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = &[
        0x24, 0x04, 0x00, 0x10,
        0x24, 0x05, 0x00, 0x10,
        0x10, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ];

    let arch = Mips::new();

    let driver = init_driver_function(
        instruction_bytes,
        vec![("$a0", expr_const(0, 32))],
        memory::Memory::new(Endian::Big),
        &arch
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(
        eval(driver.engine().get_scalar("$a0").unwrap()).unwrap().value(),
        0x10
    );

    /*
    addiu $a0, $zero, 0x10
    addiu $a1, $zero, 0x20
    beq $a0, $a1, 0x14
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = &[
        0x24, 0x04, 0x00, 0x10,
        0x24, 0x05, 0x00, 0x20,
        0x10, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ];

    let arch = Mips::new();

    let driver = init_driver_function(
        instruction_bytes,
        vec![("$a0", expr_const(0, 32))],
        memory::Memory::new(Endian::Big),
        &arch
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(
        eval(driver.engine().get_scalar("$a0").unwrap()).unwrap().value(),
        0x1244
    );
}