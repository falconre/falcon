//! An x86 (i386) specific model for Linux.

use symbolic::*;
use executor;
use error::*;
use il;
use platform::linux;
use platform::Platform;



const SYS_READ:  u32 = 3;
const SYS_WRITE: u32 = 4;
// const SYS_OPEN:  u32 = 5;
// const SYS_CLOSE: u32 = 6;

const STACK_ADDRESS: u64 = 0xb000_0000;
const STACK_SIZE: u64 = 0x0001_0000;
const INITIAL_STACK_POINTER: u64 = STACK_ADDRESS - 0x0000_1000;

const FS_BASE: u64 = 0xbf00_0000;
const FS_SIZE: u64 = 0x0000_8000;
const GS_BASE: u64 = 0xbf00_8000;
const GS_SIZE: u64 = 0x0000_8000;

const KERNEL_VSYSCALL_BYTES: &'static [u8] = &[0x0f, 0x34, 0xc3];
const KERNEL_VSYSCALL_ADDRESS: u64 = 0xbfff_0000;


/// An x86 (i386) specific model for Linux.
#[derive(Clone)]
pub struct LinuxX86 {
    linux: linux::Linux
}


impl LinuxX86 {
    /// Create a new `LinuxX86`.
    pub fn new() -> LinuxX86 {
        LinuxX86 {
            linux: linux::Linux::new()
        }
    }


    fn push(&self, engine: &mut Engine, value: u32)
        -> Result<()> {

        let expr = match engine.get_scalar_only_concrete("esp")? {
            Some(expr) => expr,
            None => bail!("Could not get concrete value for esp")
        };

        let address = expr.value() - 4;

        engine.set_scalar("esp", il::Expression::constant(
            executor::eval(
                &il::Expression::sub(
                    il::Expression::constant(expr),
                    il::expr_const(4, 32)
                )?
            )?
        ));

        engine.memory_mut().store(address, il::expr_const(value as u64, 32))?;

        Ok(())
    }


    fn initialize_stack(&self, engine: &mut Engine)
        -> Result<()> {

        for i in 0..STACK_SIZE {
            engine.memory_mut().store(STACK_ADDRESS - STACK_SIZE + i, il::expr_const(0, 8))?;
        }

        engine.set_scalar("esp", il::expr_const(INITIAL_STACK_POINTER, 32));

        Ok(())
    }


    fn initialize_segments(&self, engine: &mut Engine)
        -> Result<()> {

        for i in 0..FS_SIZE {
            engine.memory_mut().store((FS_BASE as u64 + i), il::expr_const(0, 8))?;
        }

        for i in 0..FS_SIZE {
            engine.memory_mut().store(FS_BASE - FS_SIZE + i, il::expr_const(0, 8))?;
        }

        for i in 0..GS_SIZE {
            engine.memory_mut().store((GS_BASE as u64 + i), il::expr_const(0, 8))?;
        }

        for i in 0..GS_SIZE {
            engine.memory_mut().store(GS_BASE - GS_SIZE + i, il::expr_const(0, 8))?;
        }

        engine.set_scalar("fs_base", il::expr_const(FS_BASE, 32));
        engine.set_scalar("gs_base", il::expr_const(GS_BASE, 32));

        Ok(())
    }


    fn initialize_command_line_arguments(&self, engine: &mut Engine)
        -> Result<()> {

        self.push(engine, 0)?;
        self.push(engine, 0)?;
        Ok(())
    }


    fn initialize_environment_variables(&self, engine: &mut Engine)
        -> Result<()> {

        self.push(engine, 0)?;
        Ok(())
    }


    fn initialize_kernel_vsyscall(&self, engine: &mut Engine)
        -> Result<()> {

        // Set up the KERNEL_VSYSCALL function
        for i in 0..KERNEL_VSYSCALL_BYTES.len() {
            engine.memory_mut().store(
                KERNEL_VSYSCALL_ADDRESS + i as u64,
                il::expr_const(KERNEL_VSYSCALL_BYTES[i] as u64, 8)
            )?;
        }
        // Set up a fake AT_SYSINFO 0x100 bytes ahead of vsyscall
        engine.memory_mut().store(
            KERNEL_VSYSCALL_ADDRESS + 0x100,
            il::expr_const(32, 32) // 32 = AT_SYSINFO
        )?;
        engine.memory_mut().store(
            KERNEL_VSYSCALL_ADDRESS + 0x104,
            il::expr_const(KERNEL_VSYSCALL_ADDRESS, 32)
        )?;
        // Push AT_SYSINFO onto stack
        self.push(engine, (KERNEL_VSYSCALL_ADDRESS + 0x100) as u32)?;
        self.push(engine, 0)?;
        
        // HACK (I think, need to know more about linux vsyscall process)
        // set gs + 0x10 tp KERNEL_VSYSCALL_ADDRESS
        let expr = match engine.get_scalar_only_concrete("gs_base")? {
            Some(expr) => expr,
            None => bail!("Could not get concrete value for gs_base")
        };

        let address = expr.value() + 0x10;

        engine.memory_mut().store(address, il::expr_const(KERNEL_VSYSCALL_ADDRESS, 32))?;

        Ok(())
    }


    fn initialize_miscellaneous(&self, engine: &mut Engine)
        -> Result<()> {

        engine.set_scalar("DF", il::expr_const(0, 1));

        /* SVR4/i386 ABI (pages 3-31, 3-32) says that when the program
        starts %edx contains a pointer to a function
        which might be registered using atexit.
        This provides a mean for the dynamic linker to call
        DT_FINI functions for shared libraries that
        have been loaded before the code runs.
        A value of 0 tells we have no such handler.
        */
        engine.set_scalar("edx", il::expr_const(0, 32));

        Ok(())
    }


    /// Takes a `SymbolicEngine`, most likely freshly initialized from a `Loader`, and
    /// initializes both this `LinuxX86` and the `SymbolicEngine` for execution as an
    /// x86 Linux userland process.
    pub fn initialize(&mut self, engine: &mut Engine) -> Result<()> {

        self.initialize_stack(engine)?;
        self.initialize_segments(engine)?;
        self.initialize_command_line_arguments(engine)?;
        self.initialize_environment_variables(engine)?;
        self.initialize_segments(engine)?;
        self.initialize_kernel_vsyscall(engine)?;
        self.initialize_miscellaneous(engine)?;

        self.linux.open("stdin");
        self.linux.open("stdout");
        self.linux.open("stderr");

        Ok(())
    }
}


impl Platform<LinuxX86> for LinuxX86 {
    fn raise(mut self, expression: &il::Expression, mut engine: Engine)
    -> Result<Vec<(LinuxX86, Engine)>> {

        match *expression {
            il::Expression::Scalar(ref scalar) => if scalar.name() != "sysenter" {
                bail!("Not a sysenter raise for LinuxX86")
            },
            _ => bail!("Raise not a scalar for LinuxX86")
        }


        let eax = match engine.get_scalar_only_concrete("eax")? {
            Some(eax) => eax,
            None => bail!("Could not get concrete eax")
        };

        match eax.value() as u32 {
            SYS_READ => {
                let (ebx, ecx, edx) = {
                    let ebx = match engine.get_scalar_only_concrete("ebx")? {
                        Some(ebx) => ebx,
                        None => bail!("Could not get concrete ebx")
                    };

                    let ecx = match engine.get_scalar("ecx") {
                        Some(ecx) => ecx,
                        None => bail!("Could not get ecx")
                    };

                    let edx = match engine.get_scalar("edx") {
                        Some(edx) => edx,
                        None => bail!("Could not get edx")
                    };

                    (ebx.to_owned(), ecx.to_owned(), edx.to_owned())
                };

                trace!("SYS_READ {} {} {}", ebx, ecx, edx);

                let fd = engine.eval(&ebx.into(), None)?.unwrap();

                // For now, we will concretize ecx/edx
                let address = engine.eval(&ecx, None)?.unwrap();
                if !all_constants(&ecx) {
                    engine.add_constraint(il::Expression::cmpeq(ecx, address.clone().into())?)?;
                }

                let length = engine.eval(&edx, None)?.unwrap();
                if !all_constants(&edx) {
                    engine.add_constraint(il::Expression::cmpeq(edx, length.clone().into())?)?;
                }

                // Get variables for the data we're about to read
                let (result, read) = self.linux.read(fd.value() as i32, length.value() as usize);

                for i in 0..read.len() as u64 {
                    engine.memory_mut().store(address.value() + i, read[i as usize].to_owned().into())?;
                }

                engine.set_scalar("eax", il::expr_const(result as u64, 32));

                Ok(vec![(self, engine)])
            },
            SYS_WRITE => {
                trace!("SYS_WRITE");
                let (ebx, ecx, edx) = {
                    let ebx = match engine.get_scalar_only_concrete("ebx")? {
                        Some(ebx) => ebx,
                        None => bail!("Could not get concrete ebx")
                    };

                    let ecx = match engine.get_scalar("ecx") {
                        Some(ecx) => ecx,
                        None => bail!("Could not get ecx")
                    };

                    let edx = match engine.get_scalar("edx") {
                        Some(edx) => edx,
                        None => bail!("Could not get edx")
                    };

                    (ebx.to_owned(), ecx.to_owned(), edx.to_owned())
                };

                let fd = engine.eval(&ebx.into(), None)?.unwrap();

                // For now, we will concretize ecx/edx
                let address = engine.eval(&ecx, None)?.unwrap();
                if !all_constants(&ecx) {
                    engine.add_constraint(il::Expression::cmpeq(ecx, address.clone().into())?)?;
                }

                let length = engine.eval(&edx, None)?.unwrap();
                if !all_constants(&edx) {
                    engine.add_constraint(il::Expression::cmpeq(edx, length.clone().into())?)?;
                }

                // Get our values out of memory
                let mut v = Vec::new();
                for i in 0..length.value() {
                    match engine.memory().load(address.value() + i, 8)? {
                        Some(expr) => v.push(expr.clone()),
                        None => return Err(
                            ErrorKind::AccessUnmappedMemory(address.value() + i).into()
                        )
                    };
                }

                // Write to the file
                let result = self.linux.write(fd.value() as i32, v);

                engine.set_scalar("eax", il::expr_const(result as u64, 32));

                Ok(vec![(self, engine)])
            },
            _ => bail!("Unhandled system call {}", eax.value())
        }
    }


    fn symbolic_scalars(&self) -> Vec<il::Scalar> {
        self.linux.symbolic_scalars().to_owned()
    }
}