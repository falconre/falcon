[![Build Status](https://travis-ci.org/falconre/falcon.svg?branch=master)](https://travis-ci.org/falconre/falcon)
[![Crates.io Version](https://img.shields.io/crates/v/falcon.svg)](https://crates.io/crates/falcon/)

# Welcome to Falcon

Falcon is a formal binary analysis framework in Rust.

* Expression-based IL with strong influences from RREIL and [Binary Ninja](https://binary.ninja)'s LLIL.
* Semantically-equivalent binary translators for 32/64-bit x86, Mips, and Arm64.
* Lifters for ELF and PE via [goblin](https://github.com/m4b/goblin).
* Fixed-point engine for data-flow analysis and abstract interpretation.
* Performant memory models for analysis.
* A concrete executor over Falcon IL.

# Building

* Several scripts to get you up-and-running with Falcon can be found in the `scripts/` directory.
* Dependencies are capstone (4.0.2) and clang.

# Questions / Support

* We have a [Gitter](https://gitter.im/rust-falcon/Lobby). This is the most reliable way to contact us.
* You can also find me in the Binary Ninja slack under the name "endeavor".