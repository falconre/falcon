use base64;
use falcon;
use falcon::loader::elf::Elf;
use falcon::loader::Loader;
use ketos::{
    CompileError,
    Context,
    Error,
    Interpreter,
    BuiltinModuleLoader, Module, ModuleLoader,
    Name,
    Scope,
    FromValue,
};
use std::path::Path;
use std::rc::Rc;



fn base64_decode(input: &str) -> Result<Vec<u8>, Error> {
    Ok(base64::decode(input).unwrap())
}


fn elf_from_file(filename: &Path) -> Result<Elf, Error> {
    Ok(Elf::from_file(filename).unwrap())
}

// fn elf_function_entries(elf: &Elf)
// -> Result<Vec<falcon::loader::FunctionEntry>, Error> {
//     Ok(elf.function_entries().unwrap())
// }


pub fn run(script: &str) {
    let interp = Interpreter::new();

    ketos_fn! { interp.scope() => "base64-decode" => 
        fn base64_decode(input: &str) -> Vec<u8> }

    ketos_fn! { interp.scope() => "elf-from-file" =>
        fn elf_from_file(filename: &Path) -> Elf }

    // ketos_fn!{ interp.scope() => "elf-function-entries" =>
    //     fn elf_function_entries(elf: &Elf) -> Vec<falcon::loader::FunctionEntry>}

    interp.run_code(script, None).unwrap();
}