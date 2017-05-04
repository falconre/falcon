# falcon
Binary Static Analysis Library in Rust

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

### `il::Expression`

A typical arithmetic expression. Implemented expression as of this writing are:

Variable, Constant, Add, Sub, Mulu, Divu, Modu, Muls, Divs, Mods, And, Or, Xor, Shl, Shr,
Cmpeq, Cmpneq, Cmplts, Zext, Sext, Trun.
