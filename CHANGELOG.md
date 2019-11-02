# Changelog

## [0.4.6] - 02-NOV-2019
* Close out #48, which was a weird lifting error with odd x86 instructions.
* Created two new methods, `Loader::program_verbose` and
`Loader::program_recursive` to catch errors when individual functions are
lifted. Otherwise, these errors are ignored.

## [0.4.5]
* Upgrade to falcon_capstone 0.3.0 which builds more cleanly and fixes some
bindgen oddness.