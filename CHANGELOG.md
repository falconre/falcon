# Changelog

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
* Added support for capstone4, thanks to github.com/wuggen. Capstone4 support is guarded behind the feature "capstone4".
* Minor touchups for new warnings as rust compiler evolves.

## [0.4.6] - 02-NOV-2019
* Close out #48, which was a weird lifting error with odd x86 instructions.
* Created two new methods, `Loader::program_verbose` and
`Loader::program_recursive` to catch errors when individual functions are
lifted. Otherwise, these errors are ignored.

## [0.4.5]
* Upgrade to falcon_capstone 0.3.0 which builds more cleanly and fixes some
bindgen oddness.