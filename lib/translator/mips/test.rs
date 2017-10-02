use executor::*;
use il::*;
use std::rc::Rc;
use translator::mips::*;
use types::Endian;

#[cfg(test)]
fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    memory: memory::Memory,
    result_scalar: &str
) -> Constant {
    
    let mut bytes = vec![0x00, 0x00, 0x00, 0x00];
    bytes.append(&mut instruction_bytes.to_vec());
    bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00]);

    let block_translation_result = Mips::new().translate_block(&bytes, 0).unwrap();
    let control_flow_graph = block_translation_result.control_flow_graph();
    let num_blocks = control_flow_graph.blocks().len();
    let function = Function::new(0, control_flow_graph.clone());
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(0, FunctionLocation::EmptyBlock(0));

    let arch = Mips::new();

    let mut engine = engine::Engine::new(memory);
    for scalar in scalars {
        engine.set_scalar(scalar.0, scalar.1);
    }

    let mut driver = driver::Driver::new(Rc::new(program), location, engine, &arch);

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

#[cfg(test)]
fn get_raise(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Expression)>,
    memory: memory::Memory
) -> Option<Expression> {
    
    let mut bytes = vec![0x00, 0x00, 0x00, 0x00];
    bytes.append(&mut instruction_bytes.to_vec());
    bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00]);

    let block_translation_result = Mips::new().translate_block(&bytes, 0).unwrap();
    let control_flow_graph = block_translation_result.control_flow_graph();
    let num_blocks = control_flow_graph.blocks().len();
    let function = Function::new(0, control_flow_graph.clone());
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(0, FunctionLocation::EmptyBlock(0));

    let arch = Mips::new();

    let mut engine = engine::Engine::new(memory);
    for scalar in scalars {
        engine.set_scalar(scalar.0, scalar.1);
    }

    let mut driver = driver::Driver::new(Rc::new(program), location, engine, &arch);

    loop {
        driver = driver.step().unwrap();
        let location = driver.location().apply(driver.program()).unwrap();
        println!("{}", location);
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
        assert!(false);
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
        assert!(false);
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
        assert!(false);
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