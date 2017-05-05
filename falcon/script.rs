use base64;
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


fn run_script(script: &str) -> {
    let interp = Interpreter::new();

    ketos_fn! { interp.scope() => "base64-decode" => base64::decode()}
}