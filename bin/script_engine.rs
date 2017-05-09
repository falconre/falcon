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


#[derive(Clone, Debug, ForeignValue, FromValue, FromValueRef, IntoValue)]
struct KElf { elf: Elf }
#[derive(Clone, Debug, ForeignValue, FromValue, FromValueRef, IntoValue)]
struct KFunctionEntry { fe: FunctionEntry }


fn elf_from_file(filename: &Path) -> Result<KElf, Error> {
    Ok(KElf{ elf: Elf::from_file(filename).unwrap() })
}

fn elf_function_entries(kelf: &KElf) -> Vec<KFunctionEntry> {

}


pub fn run(script: &str) {
    let interp = Interpreter::new();

    ketos_fn! { interp.scope() => "base64-decode" => 
        fn base64_decode(input: &str) -> Vec<u8> }

    ketos_fn! { interp.scope() => "elf-from-file" =>
        fn elf_from_file(filename: &Path) -> KElf }

    // ketos_fn!{ interp.scope() => "elf-function-entries" =>
    //     fn elf_function_entries(elf: &Elf) -> Vec<falcon::loader::FunctionEntry>}

    interp.run_code(script, None).unwrap();
}