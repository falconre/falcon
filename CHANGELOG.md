# Changelog

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