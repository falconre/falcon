use executor::*;
use memory;
use il::*;
use RC;
use translator::mips::*;
use types::{Architecture, Endian};


#[macro_use]
macro_rules! backing {
    ($e: expr) => {
        {
            let v: Vec<u8> = $e.to_vec();
            let mut b = memory::backing::Memory::new(Endian::Big);
            b.set_memory(0, v, memory::MemoryPermissions::EXECUTE);
            b
        }
    }
}


fn init_driver_block<'d>(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory_: Memory<'d>
) -> Driver<'d> {
    let mut bytes = instruction_bytes.to_vec();
    // ori $a0, $a0, $a0
    bytes.append(&mut vec![0x00, 0x84, 0x20, 0x25]);

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(0, bytes.to_vec(),
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ);
    
    let function = Mips::new().translate_function(&backing, 0).unwrap();

    let location = if function.control_flow_graph()
                              .block(0).unwrap()
                              .instructions().len() == 0 {
        ProgramLocation::new(Some(0), FunctionLocation::EmptyBlock(0))
    }
    else {
        ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0))
    };

    let mut program = Program::new();
    program.add_function(function);

    let mut state = State::new(memory_);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(RC::new(program), location, state, Architecture::Mips)
}


fn init_driver_function<'d>(
    backing: &'d memory::backing::Memory,
    scalars: Vec<(&str, Constant)>
) -> Driver<'d> {

    let memory = Memory::new_with_backing(Endian::Big, backing);

    let function = Mips::new().translate_function(&memory, 0).unwrap();
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0));

    let mut state = State::new(memory);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(RC::new(program), location, state, Architecture::Mips)
}


fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
    result_scalar: &str
) -> Constant {

    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

    while driver.location()
                .apply(driver.program()).unwrap()
                .forward().unwrap()
                .len() > 0 {
        driver = driver.step().unwrap();
    }
    // The final step
    // driver = driver.step().unwrap();

    driver.state().get_scalar(result_scalar).unwrap().clone()
}


fn get_raise(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory
) -> Expression {

    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

    loop {
        {
            let location = driver.location().apply(driver.program()).unwrap();
            if let Some(instruction) = location.instruction() {
                if let Operation::Raise { ref expr } = *instruction.operation() {
                    return expr.clone();
                }
            }
        }
        driver = driver.step().unwrap();
    }
}


fn step_to(mut driver: Driver, target_address: u64) -> Driver {

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
        vec![("$a1", const_(1, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", const_(0x7fffffff, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big)
    );
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", const_(0xffffffff, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big)
    );
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
        vec![("$a1", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1235);


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", const_(0x7fffffff, 32))],
        Memory::new(Endian::Big)
    );
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
        vec![("$a1", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1235);

    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0x7fffffff, 32))],
        Memory::new(Endian::Big),
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
        vec![("$a1", const_(1, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0x7fffffff, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x80000000);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0xffffffff, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
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
        vec![("$a1", const_(0x8000ffff, 32)),
             ("$a2", const_(0x1234, 32))],
        Memory::new(Endian::Big),
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
        vec![("$a1", const_(0x8000ffff, 32))],
        Memory::new(Endian::Big),
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
    let instruction_bytes = backing!([
        0x10, 0x00, 0x00, 0x03,
        0x34, 0x84, 0x00, 0x00,
        0x34, 0x84, 0x00, 0x01,
        0x34, 0x84, 0x00, 0x01,
        0x34, 0x84, 0x00, 0x02,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x2);
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
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x11, 0x00, 0x03,
        0x20, 0x84, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1234);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);
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
    let instruction_bytes = backing!([
        0x24, 0x04, 0x00, 0x10,
        0x24, 0x05, 0x00, 0x10,
        0x10, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x10);

    /*
    addiu $a0, $zero, 0x10
    addiu $a1, $zero, 0x20
    beq $a0, $a1, 0x14
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x24, 0x04, 0x00, 0x10,
        0x24, 0x05, 0x00, 0x20,
        0x10, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x14);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1244);
}


#[test]
fn beqz() {
    /*
    addiu $a1, $zero, 0x10
    beqz $a0, 0x10
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x24, 0x05, 0x00, 0x10,
        0x10, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x0);

    /*
    addiu $a1, $zero, 0x10
    beqz $a0, 0x10
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x24, 0x05, 0x00, 0x10,
        0x10, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1235);
}


#[test]
fn bgez() {

    /*
    ori $a0, 0x0000
    bgez $a0, 0x10
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x81, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x0);

    /*
    ori $a0, 0x0000
    bgez $a0, 0x10
    nop
    addi a0, $a0, 0x1234
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x81, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x12, 0x34,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0x1, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bgez $a0,  0x10
    nop
    addi a0, $a0, 0x1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x81, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x84, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xfffffffe, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0xffffffff);
}


#[test]
fn bgezal() {
    /*
    ori $a0, 0x0000
    bgezal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x91, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);

    /*
    ori $a0, 0x0000
    bgezal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x91, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);

    /*
    ori $a0, 0x0000
    bgezal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x91, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xffffffff, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);
}


#[test]
fn bgtz() {
    /*
    ori $a0, 0x0000
    bgtz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x1c, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bgtz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x1c, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);

    /*
    ori $a0, 0x0000
    bgtz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x1c, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xffffffff, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);
}


#[test]
fn blez() {
    /*
    ori $a0, 0x0000
    blez $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x18, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);

    /*
    ori $a0, 0x0000
    blez $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x18, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    blez $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x18, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xffffffff, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
}


#[test]
fn bltz() {
    /*
    ori $a0, 0x0000
    bltz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bltz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bltz $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xffffffff, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
}


#[test]
fn bltzal() {
    /*
    ori $a0, 0x0000
    bltzal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x90, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bltzal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x90, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bltzal $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x04, 0x90, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xffffffff, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);
}


#[test]
fn bne() {
    /*
    ori $a0, 0x0000
    bne $a0, $a1, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x14, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bne $a0, $a1, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x14, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);

    /*
    ori $a0, 0x0000
    bne $a0, $a1, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x14, 0x85, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(1, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);
}


#[test]
fn bnez() {
    /*
    ori $a0, 0x0000
    bnez $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x14, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x1);

    /*
    ori $a0, 0x0000
    bnez $a0, 0x10
    nop
    addiu a1, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x14, 0x80, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x24, 0x05, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(1, 32)), ("$a1", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a1").unwrap().value(), 0x0);
}


#[test]
fn break_ () {
    let result = get_raise(
        &[0x00, 0x00, 0x00, 0x0d],
        vec![("$a1", const_(0x7fffffff, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big)
    );
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "break");
    }
    else {
        panic!("Did not hit break");
    }
}


#[test]
fn clo () {
    /*
    clo $a0, $a1
    */
    let result = get_scalar(
        &[0x70, 0xa4, 0x20, 0x21],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(0xff000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 8);
}


#[test]
fn clz () {
    /*
    clz $a0, $a1
    */
    let result = get_scalar(
        &[0x70, 0xa4, 0x20, 0x20],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(0x08000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 4);
}


#[test]
fn div () {
    /*
    div $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1a],
        vec![("$a0", const_(19, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 4);

    /*
    div $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1a],
        vec![("$a0", const_(19, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 3);

    /*
    div $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1a],
        vec![("$a0", const_(0xffffffec, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xfffffffb);
}


#[test]
fn divu () {
    /*
    divu $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1b],
        vec![("$a0", const_(19, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 4);

    /*
    divu $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1b],
        vec![("$a0", const_(19, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 3);

    /*
    divu $a0, $a1
    */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x1b],
        vec![("$a0", const_(0xffffffec, 32)),
             ("$a1", const_(4, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0x3ffffffb);
}


#[test]
fn j() {
    /*
    ori $a0, 0x0000
    j 0x10
    addiu $a0, $zero, 1
    addiu $a0, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x04,
        0x24, 0x04, 0x00, 0x01,
        0x24, 0x04, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1);
}


#[test]
fn jr() {
    /*
    ori $a0, 0x0000
    jr $a0
    addiu $a0, $a0, 1
    addiu $a0, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x08,
        0x24, 0x84, 0x00, 0x01,
        0x24, 0x04, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xf, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x10);
}


#[test]
fn jal() {
    /*
    ori $a0, 0x0000
    jal 0x10
    addiu $a0, $a0, 1
    addiu $a0, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x04,
        0x24, 0x84, 0x00, 0x01,
        0x24, 0x04, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x1);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);
}


#[test]
fn jalr() {
    /*
    ori $a0, 0x0000
    jal 0x10
    addiu $a0, $a0, 1
    addiu $a0, $zero, 1
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0x00, 0x80, 0xf8, 0x09,
        0x24, 0x84, 0x00, 0x01,
        0x24, 0x04, 0x00, 0x01,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xf, 32))]
    );

    let driver = step_to(driver, 0x10);

    assert_eq!(driver.state().get_scalar("$a0").unwrap().value(), 0x10);
    assert_eq!(driver.state().get_scalar("$ra").unwrap().value(), 0xc);
}


#[test]
fn lb() {
    let mut memory = Memory::new(Endian::Big);
    memory.store(0xdeadbeef, const_(0xdeadbeef, 32)).unwrap();

    let result = get_scalar(
        &[0x80, 0xa4, 0x00, 0xef],
        vec![("$a1", const_(0xdeadbe00, 32))],
        memory,
        "$a0"
    );
    assert_eq!(result.value(), 0xffffffde);
}


#[test]
fn lbu() {
    let mut memory = Memory::new(Endian::Big);
    memory.store(0xdeadbeef, const_(0xdeadbeef, 32)).unwrap();

    let result = get_scalar(
        &[0x90, 0xa4, 0x00, 0xf0],
        vec![("$a1", const_(0xdeadbe00, 32))],
        memory,
        "$a0"
    );
    assert_eq!(result.value(), 0xad);
}


#[test]
fn lh() {
    let mut memory = Memory::new(Endian::Big);
    memory.store(0xdeadbeef, const_(0xdeadbeef, 32)).unwrap();

    let result = get_scalar(
        &[0x84, 0xa4, 0x00, 0xef],
        vec![("$a1", const_(0xdeadbe00, 32))],
        memory,
        "$a0"
    );
    assert_eq!(result.value(), 0xffffdead);
}


#[test]
fn lhu() {
    let mut memory = Memory::new(Endian::Big);
    memory.store(0xdeadbeef, const_(0xdeadbeef, 32)).unwrap();

    let result = get_scalar(
        &[0x94, 0xa4, 0x00, 0xef],
        vec![("$a1", const_(0xdeadbe00, 32))],
        memory,
        "$a0"
    );
    assert_eq!(result.value(), 0xdead);
}


#[test]
fn lui() {
    let result = get_scalar(
        &[0x3c, 0x04, 0x12, 0x34],
        vec![],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x12340000);
}


#[test]
fn lw() {
    let mut memory = Memory::new(Endian::Big);
    memory.store(0xdeadbeef, const_(0xdeadbeef, 32)).unwrap();

    let result = get_scalar(
        &[0x8c, 0xa4, 0x00, 0xef],
        vec![("$a1", const_(0xdeadbe00, 32))],
        memory,
        "$a0"
    );
    assert_eq!(result.value(), 0xdeadbeef);
}


#[test]
fn madd() {
    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x00],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 51);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x00],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 2);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x00],
        vec![("$a0", const_(0x10000000, 32)),
             ("$a1", const_(32, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 4);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x00],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xffffffd8);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x00],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xffffffff);
}


#[test]
fn maddu() {
    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x01],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 51);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x01],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 2);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x01],
        vec![("$a0", const_(0x10000000, 32)),
             ("$a1", const_(32, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 4);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x01],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(4, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xfffffff0);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x01],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(4, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 3);
}


#[test]
fn mfhi() {
    let result = get_scalar(
        &[0x00, 0x00, 0x20, 0x10],
        vec![("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);
}


#[test]
fn mflo() {
    let result = get_scalar(
        &[0x00, 0x00, 0x20, 0x12],
        vec![("$lo", const_(2, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);
}


#[test]
fn move_() {
    let result = get_scalar(
        &[0x00, 0xa0, 0x20, 0x25],
        vec![("$a1", const_(1234, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1234);


    let result = get_scalar(
        &[0x00, 0x00, 0x20, 0x25],
        vec![],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
}


#[test]
fn movn() {
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x0b],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(2, 32)),
             ("$a2", const_(3, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);


    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x0b],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(2, 32)),
             ("$a2", const_(0, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn movz() {
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x0a],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(2, 32)),
             ("$a2", const_(3, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);


    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x0a],
        vec![("$a0", const_(1, 32)),
             ("$a1", const_(2, 32)),
             ("$a2", const_(0, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 2);
}


#[test]
fn msub() {
    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x04],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 49);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x04],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xfffffffe);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x04],
        vec![("$a0", const_(0x10000001, 32)),
             ("$a1", const_(32, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x04],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xffffffd8);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x04],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xffffffff);
}


#[test]
fn msubu() {
    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x05],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 49);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x05],
        vec![("$a0", const_(5, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xfffffffe);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x05],
        vec![("$a0", const_(0x10000001, 32)),
             ("$a1", const_(32, 32)),
             ("$lo", const_(1, 32)),
             ("$hi", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x05],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xffffffd8);

    let result = get_scalar(
        &[0x70, 0x85, 0x00, 0x05],
        vec![("$a0", const_(0xfffffffc, 32)),
             ("$a1", const_(10, 32)),
             ("$lo", const_(0, 32)),
             ("$hi", const_(0, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0x9);
}


#[test]
fn mthi() {
    let result = get_scalar(
        &[0x00, 0x80, 0x00, 0x11],
        vec![("$a0", const_(0xdeadbeef, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xdeadbeef);
}


#[test]
fn mtlo() {
    let result = get_scalar(
        &[0x00, 0x80, 0x00, 0x13],
        vec![("$a0", const_(0xdeadbeef, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 0xdeadbeef);
}


#[test]
fn mul() {
    /* mul $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x70, 0xa6, 0x20, 0x02],
        vec![("$a0", const_(0, 32)),
             ("$a1", const_(7, 32)),
             ("$a2", const_(11, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 77);
}


#[test]
fn mult() {
    /* mult $a0, $a1 */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x18],
        vec![("$a0", const_(11, 32)),
             ("$a1", const_(7, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 77);

    /* mult $a0, $a1 */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x18],
        vec![("$a0", const_(0xffffffff, 32)),
             ("$a1", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 0xffffffff);
}


#[test]
fn multu() {
    /* multu $a0, $a1 */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x19],
        vec![("$a0", const_(11, 32)),
             ("$a1", const_(7, 32))],
        Memory::new(Endian::Big),
        "$lo"
    );
    assert_eq!(result.value(), 77);

    /* mult $a0, $a1 */
    let result = get_scalar(
        &[0x00, 0x85, 0x00, 0x19],
        vec![("$a0", const_(0xffffffff, 32)),
             ("$a1", const_(2, 32))],
        Memory::new(Endian::Big),
        "$hi"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn negu() {
    /* negu $a0, $a1 */
    let result = get_scalar(
        &[0x00, 0x05, 0x20, 0x23],
        vec![("$a1", const_(0xff00ff00, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xff0100);
}


#[test]
fn nop() {
    let bytes = &[0x00, 0x00, 0x00, 0x00];

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(0, bytes.to_vec(),
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ);
    
    let function = Mips::new().translate_function(&backing, 0).unwrap();
    let control_flow_graph = function.control_flow_graph();

    assert_eq!(control_flow_graph.block(0).unwrap().instructions().len(), 0);
}


#[test]
fn nor() {
    /* nor $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x27],
        vec![("$a1", const_(0x0000ff00, 32)),
             ("$a2", const_(0xff000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x00ff00ff);
}


#[test]
fn or() {
    /* or $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x25],
        vec![("$a1", const_(0x0000ff00, 32)),
             ("$a2", const_(0xff000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xff00ff00);
}


#[test]
fn ori() {
    /* ori $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x34, 0xa4, 0x12, 0x34],
        vec![("$a1", const_(0x00ff0000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x00ff1234);
}


#[test]
fn sb() {
    /*
    sb $a0, 0xef($a1)
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0xa0, 0xa4, 0x00, 0xef,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0x41, 32)),
             ("$a1", const_(0xdeadbe00, 32))]
    );

    let driver = step_to(driver, 0x4);

    fn memval(memory: &Memory, address: u64) -> u16 {
        memory.load(address, 8).unwrap().unwrap().value() as u16
    }

    assert_eq!(memval(driver.state().memory(), 0xdeadbeef), 0x41);
}


#[test]
fn sh() {
    /*
    sb $a0, 0xef($a1)
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0xa4, 0xa4, 0x00, 0xef,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xbeef, 32)),
             ("$a1", const_(0xdeadbe00, 32))]
    );

    let driver = step_to(driver, 0x4);

    fn memval(memory: &Memory, address: u64) -> u16 {
        memory.load(address, 16).unwrap().unwrap().value() as u16
    }

    assert_eq!(memval(driver.state().memory(), 0xdeadbeef), 0xbeef);
}


#[test]
fn sll() {
    /* sllv $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x00, 0x05, 0x24, 0x00],
        vec![("$a1", const_(0x1234, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x12340000);
}


#[test]
fn sllv() {
    /* sllv $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x00, 0xc5, 0x20, 0x04],
        vec![("$a1", const_(0x1234, 32)),
             ("$a2", const_(16, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x12340000);
}


#[test]
fn slt() {
    /* slt $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2a],
        vec![("$a1", const_(0x1000, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);

    /* slt $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2a],
        vec![("$a1", const_(0xfff, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);

    /* slt $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2a],
        vec![("$a1", const_(0x1001, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);

    /* slt $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2a],
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn slti() {
    /* slti $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x28, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
    /* slti $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x28, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0xfff, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);
    /* slti $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x28, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x1001, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
    /* slti $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x28, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x80000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);
}


#[test]
fn sltiu() {
    /* sltiu $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x2c, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
    /* sltiu $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x2c, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0xfff, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);
    /* sltiu $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x2c, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x1001, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
    /* sltiu $a0, $a1, 0x1234 */
    let result = get_scalar(
        &[0x2c, 0xa4, 0x10, 0x00],
        vec![("$a1", const_(0x80000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
}


#[test]
fn sltu() {
    /* sltu $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2b],
        vec![("$a1", const_(0x1000, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);

    /* sltu $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2b],
        vec![("$a1", const_(0xfff, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 1);

    /* sltu $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2b],
        vec![("$a1", const_(0x1001, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);

    /* sltu $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xa6, 0x20, 0x2b],
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(0x1000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);
}


#[test]
fn sra() {
    /* sra $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0x05, 0x24, 0x03],
        vec![("$a1", const_(0x12340000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);

    /* sra $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0x05, 0x24, 0x03],
        vec![("$a1", const_(0x80000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xffff8000);
}


#[test]
fn srav() {
    /* srav $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0xc5, 0x20, 0x07],
        vec![("$a1", const_(0x12340000, 32)),
             ("$a2", const_(0x10, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);

    /* srav $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0xc5, 0x20, 0x07],
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(0x10, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xffff8000);
}


#[test]
fn srl() {
    /* srl $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0x05, 0x24, 0x02],
        vec![("$a1", const_(0x12340000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);

    /* srl $a0, $a1, 0x10 */
    let result = get_scalar(
        &[0x00, 0x05, 0x24, 0x02],
        vec![("$a1", const_(0x80000000, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x00008000);
}


#[test]
fn srlv() {
    /* srlv $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xc5, 0x20, 0x06],
        vec![("$a1", const_(0x12340000, 32)),
             ("$a2", const_(0x10, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x1234);

    /* srlv $a0, $a1, $a2 */
    let result = get_scalar(
        &[0x00, 0xc5, 0x20, 0x06],
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(0x10, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x00008000);
}


#[test]
fn sub() {
    // add $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x22];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(1, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", const_(0, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big)
    );
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }


    let result = get_raise(
        instruction_bytes,
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big)
    );
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "IntegerOverflow");
    }
    else {
        panic!("Did not hit overflow");
    }
}


#[test]
fn subu() {
    // add $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x23];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(1, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xffffffff);


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0x80000000, 32)),
             ("$a2", const_(1, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0x7fffffff);
}


#[test]
fn sw() {
    /*
    ori $a0, $a0, 0
    sb $a0, 0xe0($a1)
    jr $ra
    nop
    */
    let instruction_bytes = backing!([
        0x34, 0x84, 0x00, 0x00,
        0xac, 0xa4, 0x00, 0xe0,
        0x03, 0xe0, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00
    ]);

    let driver = init_driver_function(
        &instruction_bytes,
        vec![("$a0", const_(0xdeadbeef, 32)),
             ("$a1", const_(0xdeadbe00, 32))]
    );

    let driver = step_to(driver, 0x8);

    fn memval(memory: &Memory, address: u64) -> u32 {
        memory.load(address, 32).unwrap().unwrap().value() as u32
    }

    assert_eq!(memval(driver.state().memory(), 0xdeadbee0), 0xdeadbeef);
}


#[test]
fn syscall () {
    let result = get_raise(
        &[0x00, 0x00, 0x00, 0x0c],
        vec![],
        Memory::new(Endian::Big)
    );
    if let Expression::Scalar(ref scalar) = result {
        assert_eq!(scalar.name(), "syscall");
    }
    else {
        panic!("Did not hit break");
    }
}


#[test]
fn xor() {
    // xor $a0, $a1, $a2
    let instruction_bytes = &[0x00, 0xa6, 0x20, 0x26];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0xff00ff00, 32)),
             ("$a2", const_(0x0f0f0f0f, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xf00ff00f);
}


#[test]
fn xori() {
    // xor $a0, $a1, 0x0f0f
    let instruction_bytes = &[0x38, 0xa4, 0x0f, 0x0f];


    let result = get_scalar(
        instruction_bytes,
        vec![("$a1", const_(0xff00ff00, 32)),
             ("$a2", const_(0x00000f0f, 32))],
        Memory::new(Endian::Big),
        "$a0"
    );
    assert_eq!(result.value(), 0xff00f00f);
}