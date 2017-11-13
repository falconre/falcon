[![Build Status](https://travis-ci.org/falconre/falcon.svg?branch=master)](https://travis-ci.org/falconre/falcon)
[![Coverage Status](https://coveralls.io/repos/github/falconre/falcon/badge.svg)](https://coveralls.io/github/falconre/falcon)
[![Crates.io Version](https://img.shields.io/crates/v/falcon.svg)](https://crates.io/crates/falcon/)
[![Documentation](https://docs.rs/falcon/badge.svg)](https://docs.rs/falcon/)
[![irc.freenode.net#rust-falcon](https://img.shields.io/badge/freenode-%23rust--falcon-blue.svg?style=flat)](irc://irc.freenode.net/#rust-falcon)

# Welcome to Falcon

Falcon is a formal binary analysis framework in Rust. Falcon provides a platform for implementing data-flow analysis and abstract interpretation over binary executables.

* Expression-based IL with strong influences from [Binary Ninja](https://binary.ninja)'s' LLIL and RREIL.
* Semantically-equivalent binary translation.
* Fixed-point engine for data-flow analysis and abstract interpretation. Basic analyses provided.
* Lifters for Binary formats (initially Elf) via [goblin](https://github.com/m4b/goblin).

# Questions / Support

* I write about Falcon on my [blog](http://reversing.io/). [Just posts about Falcon](http://reversing.io/tags/falcon/).
* I am idling in irc.freenode.net#rust-falcon.
* You can also find me in the Binary Ninja slack under the name "endeavor".
