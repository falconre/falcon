[![Build Status](https://travis-ci.org/endeav0r/falcon.svg?branch=master)](https://travis-ci.org/endeav0r/falcon)

# Welcome to Falcon

Falcon is a Binary Static Analysis Framework in Rust.

Falcon is not the only Binary Analysis Framework in Rust.
[Panopticon](https://github.com/das-labor/panopticon) looks cool, and shows promise. 
I've created RREIL-like ILs for analysis before though, and inspired by 
[Binary Ninja](https://binary.ninja/)'s IL, I wanted an expression-based IL. Panopticon 
is certainly worth checking out.

Falcon is similar in design to jakstab/bindead, in that it has a Fixed Point engine
and analyses are implemented over this engine. See
[Reaching Definitions](https://github.com/endeav0r/falcon/blob/master/lib/analysis/reaching_definitions.rs)
as an example of what this looks like now, or the
[FixedPoint](https://github.com/endeav0r/falcon/blob/master/lib/analysis/fixed_point.rs)
trait.

# Should I use Falcon? / When will Falcon be stabilized?

When Falcon hits 0.1.0, I will deem Falcon stable enough to use, and I will send it to crates.io. *Until Falcon hits 0.1.0 I recommend you do not use it, even for experiments.* As I implement and experiment with things, I occasionally change the underlying IL, and your analyses will break.

When Falcon hits 0.1.0, it may be nice for playing around, but I'm not sure if Falcon will ever be, "Production-ready." I currently do not have plans to implement the verbose-instruction set lifting of BAP, McSema/Remill, VEX IR, GDSL, etc.

Falcon still serves as, "Yet Another Analysis Framework," so if you're looking for more examples/ideas of how people do things, read away.

# But why?

Because I like writing frameworks for program analysis, and rust seemed like a neat language to write a framework in. I also wanted to experiment with an IL for program analysis similar in nature to Binary Ninja's, but with a reduced number of operations. This of Falcon's IL as a mix between Binary Ninja's LLIL and RREIL.

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
  * Symbolic Execution (working)
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

**This is all old news bears. Don't bother until version `0.1.0`.**

### `il::ControlFlowGraph`
The core struct in Falcon IL is `il::ControlFlowGraph`.

`il::ControlFlowGraph` vertices are `il::Block`.
`il::ControlFlowGraph` edges are `il::Edge`.

`il::ControlFlowGraph` is a wrapper around `falcon::Graph`, and behaves as you would expect.

### `il::Edge`

`il::Edge` is a directed edge with an optional condition. When conditional branches are 
lifted, their path-guards are translated into conditions over their edges. Edges without
conditions are unconditional.

`il::Edge` conditions are of type `il::Expression`.

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

There are 6 operations:

  * `Assign` - `dst: Scalar` <- `src: Expression`
  * `Store` - `dst: Array`, `address: Expression` <- `src: Expression`
  * `Load` - `dst: Scalar` <- `address: Expression`, `src: Array`
  * `Brc` - if (`condition: Expression` == 1) goto `dst: Expression`
  * `Phi` - `dst: MultiVar` <- `src: Vec<MultiVar>`
  * `Raise` - raise(`expr: Expression`)

Operations take operands, which are either `il::Variable` or `il::Expression`

`Phi` operations are added by SSA analysis.

`Raise` instructions are used to handle system calls.

### `il::Expression`

Implemented expressions as of this writing are:

  * `Scalar(il::Scalar)`
  * `Constant(il::Constant)`
  * `Add(il::Expression, il::Expression)`
  * `Sub(il::Expression, il::Expression)`
  * `Mul(il::Expression, il::Expression)`
  * `Divu(il::Expression, il::Expression)`
  * `Modu(il::Expression, il::Expression)`
  * `Divs(il::Expression, il::Expression)`
  * `Mods(il::Expression, il::Expression)`
  * `And(il::Expression, il::Expression)`
  * `Or(il::Expression, il::Expression)`
  * `Xor(il::Expression, il::Expression)`
  * `Shl(il::Expression, il::Expression)`
  * `Shr(il::Expression, il::Expression)`
  * `Cmpeq(il::Expression, il::Expression)`
  * `Cmpneq(il::Expression, il::Expression)`
  * `Cmplts(il::Expression, il::Expression)`
  * `Cmpltu(il::Expression, il::Expression)`
  * `Zext(usize, il::Expression)`
  * `Sext(usize, il::Expression)`
  * `Trun(usize, il::Expression)`

We have 4 groups.

#### Terminators

`Scalar`, `Constant`, as expected.

#### Binary Arithmetic Operations

`Add`, `Sub`, `Mul`, `Divu`, `Modu`, `Divs`, `Mods`, `And`, `Or`, `Xor`, `Shl`, `Shr`

These take two `il::Expression`s of the same bit-width, and produce an `il::Expression` of the same bit-width.

#### Binary Comparison Operations

`Cmpeq`, `Cmpneq`, `Cmplts`, `Cmpltu`

These take two `il::Expression`s of the same bit-width, and produce an `il::Expression` of bit-width 1. When the produced expression has a value of 1, this condition evaluates to true. When the produced expression has a value of 0, this condition evaluates to false.

#### Bit-Extension

`Zext`, `Sext`, `Trun`

These take a desired bit-width, and either zero-extend, sign-extend, or truncate the given expression to match that bit-width. It is an error to extend an expression to a size <= its current size, or to truncate to a size >= its current size.