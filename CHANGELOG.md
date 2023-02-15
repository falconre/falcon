# Changelog

## [0.5.5]

* falcon_capstone now has a vendored option thanks to @marirs and @mnaza. This option won't take effect until [this issue](https://github.com/falconre/falcon_capstone/issues/65) is resolved, but it's coming.
* Moved from the error-chain crate (unmaintained) to thiserror.
* Updated dependencies.

## [0.5.4]

* Minor improvements to constants analysis.
* Added a maximum number of steps field to `fixed_point_forward_options`.

## [0.5.3]

* Just tidying things up

## [0.5.2]

* emmanuel099 Add Arithmetic Shift-Right expression type. This expression type is behind a feature flag until 0.6.0. See [#94](https://github.com/falconre/falcon/pull/94) for more information.
* kawadakk Massive work (>5,000 lines) to implement an arm64 lifter. The lifter will stay for a few months to work out kinks, and then this deserves a 0.6.0 bump.

## [0.5.1]

### Breaking

* Pulled the "Conditional Operation" feature we were going to implement in 0.5.0.

### Fixes

* Remove duplicated function entries.
* bswap operand width is not dependent on disassembly mode.
* Fixed a bug in il::ControlFlowGraph::merge that sometimes caused invalid
graphs to be generated.

## [0.5.0] (Yanked)

### Fixes

* When shifting constants left by very large values, num-bigint would sometimes allocate too much memory and crash. We check for this now, and set the result to 0.

### Breaking
* Added lifter options
* Nop takes a placeholder instruction
* Added Conditional operation
* Added feature "sanity-checks" to abort early on creation of likely bad IL. Used to help check possible lifter errors.
* oblivia-simplex Linting, falcon now passes cargo clippy --all
* capstone4 is now the default capstone.

## [0.4.12] - 17-APR-2020

* emmanuel099 Multiple improvements to the graph library
* emmanuel099 Natural loops detection
* emmanuel099 Use Semi-NCA Algorithm in `compute_immediate_dominators`
* anon8675309 Remove docker network dependency
* anon8675309 Added scripts to get set up outside of Docker
* Use instruction address as temporary scalar index

## [0.4.11] - 24-FEB-2020

* Multiple x86 semantics fix-ups

## [0.4.10] - 15-FEB-2020

* Update goblin to `0.2`

## [0.4.9] - 10-FEB-2020

* emmanuel099 Fixed implementational defect in Graph::edges_in/edges_out
* emmanuel099 Created SSA tranformation

## [0.4.8] - 01-FEB-2020

* jeandudey Ported falcon to Rust 2018 edition.
* emmanuel099 Lifted additional x86 instructions to intrinsics.
* emmanuel099 Fixed computation of dominance frontiers.
* emmanuel099 Drop dedup from scalars and scalars_mut #56

## [0.4.7] - 08-JAN-2020
* Added support for capstone4, thanks to github.com/wuggen. Capstone4 support is
guarded behind the feature "capstone4".
* Minor touchups for new warnings as rust compiler evolves.

## [0.4.6] - 02-NOV-2019
* Close out #48, which was a weird lifting error with odd x86 instructions.
* Created two new methods, `Loader::program_verbose` and
`Loader::program_recursive` to catch errors when individual functions are
lifted. Otherwise, these errors are ignored.

## [0.4.5]
* Upgrade to falcon_capstone 0.3.0 which builds more cleanly and fixes some
bindgen oddness.
