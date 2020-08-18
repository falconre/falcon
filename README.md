[![Build Status](https://travis-ci.org/falconre/falcon.svg?branch=master)](https://travis-ci.org/falconre/falcon)
[![Crates.io Version](https://img.shields.io/crates/v/falcon.svg)](https://crates.io/crates/falcon/)
[![Documentation](https://docs.rs/falcon/badge.svg)](https://docs.rs/falcon/)
[![irc.freenode.net#rust-falcon](https://img.shields.io/badge/freenode-%23rust--falcon-blue.svg?style=flat)](irc://irc.freenode.net/#rust-falcon)

# Welcome to Falcon

Falcon is a formal binary analysis framework in Rust.

* Expression-based IL with strong influences from RREIL and [Binary Ninja](https://binary.ninja)'s LLIL.
* Semantically-equivalent binary translators for 32/64-bit x86, Mips, and Mipsel.
* Lifters for ELF and PE via [goblin](https://github.com/m4b/goblin).
* Fixed-point engine for data-flow analysis and abstract interpretation.
* Performant memory models for analysis.
* A concrete executor over Falcon IL.

# Building

* Several scripts to get you up-and-running with Falcon can be found in the `scripts/` directory.
* Dependencies are capstone and clang.
* Falcon works out of the box with capstone4.

# Questions / Support

* There is an infrequently checked IRC channel at irc.freenode.net#rust-falcon.
* There is a more frequently checked [Gitter](https://gitter.im/rust-falcon/Lobby).
* You can also find me in the Binary Ninja slack under the name "endeavor".
