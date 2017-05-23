# Welcome to Falcon
Falcon is a Binary Static Analysis Framework in Rust.

# When will Falcon be stabilized?

When Falcon hits 0.1.0, it will be stable enough for use. Until 0.1.0, I reserve the
right to make breaking changes (though this will not happen often).

# What's being worked?

I'm opening issues to try and track what's coming, so check there. If something needs
to be done, open an issue. Additionally, I'm going through the code base randomly with
[clippy](https://github.com/Manishearth/rust-clippy) 
and making changes to clean things up. Every commit will have some of these until the
codebase is sufficiently rust-idiomatic.

  Rough priorities, in order:

  * Loading of binary formats (Elf) [done]
  * Scripting with [ketos](https://github.com/murarth/ketos) [abandoned]
  * Inter-procedural analysis
  * Constraint generation
  * Constraint solving
  * Flushing out the rest of X86
  * MIPS
  * ARM

# Rust Compatibility

Due to some unknown error with [goblin](https://crates.io/crates/goblin), docs will only
build with nightly. Outside of that, everything works with stable (1.17).

This will get you squared away:

```
rustup run nigthly cargo doc
```

# Falcon Intermediate Language

Falcon IL is an expression-based Intermediate Language.

### `il::ControlFlowGraph`
The core struct in Falcon IL is `il::ControlFlowGraph`.

`il::ControlFlowGraph` vertices are `il::Block`.
`il::ControlFlowGraph` edges are `il::Edge`.

`il::ControlFlowGraph` is a wrapper around `falcon::Graph`, and behaves as you would expect.

### `il::Edge`

`il::Edge` is a directed edge with an optional condition. When conditional branches are 
lifted, their path-guards are translated into conditions over their edges. Edges without
conditions are unconditional.

`il::Edge`` conditions are of type `il::Expression`.

### `il::Block`

Blocks hold `il::Instruction`. Blocks are uniquely-indexed, and the index of a block can 
be used to locate it in the `il::ControlFlowGraph`. Block indices are displayed as `0x{:X}`
by conention.

### `il::Instruction`

Instructions hold an `il::Operation`, and provide a reference point for an Operation in a
block. An instruction can be thought as the separation between the Control-Flow, or
locational, properties of an instruction, and the semantics of the instruction, which are
captures completely within the `il::Operation`.

Instructions are uniquely-indexed per-Block, and are displayed as `{:02X}` by convention.

### `il::Operation`

There are 5 operations:

  * Assign
  * Store
  * Load
  * Brc
  * Phi

Operations take operands, which are either `il::Variable` or `il::Expression`

I plan on adding another Operation in the near future, "Raise," which will
take the place of architecture-specific instructions such as `syscall`.

### `il::Expression`

A typical arithmetic expression. Implemented expression as of this writing are:

Variable, Constant, Add, Sub, Mulu, Divu, Modu, Muls, Divs, Mods, And, Or, Xor, Shl, Shr,
Cmpeq, Cmpneq, Cmplts, Zext, Sext, Trun.
