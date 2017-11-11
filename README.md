[![Build Status](https://travis-ci.org/falconre/falcon.svg?branch=master)](https://travis-ci.org/falconre/falcon)
[![Coverage Status](https://coveralls.io/repos/github/falconre/falcon/badge.svg)](https://coveralls.io/github/falconre/falcon)
[![Crates.io Version](https://img.shields.io/crates/v/falcon.svg)](https://crates.io/crates/falcon/)
[![Documentation](https://docs.rs/falcon/badge.svg)](https://docs.rs/falcon/)

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

# Is Falcon suitable for use / Is Falcon stable?

As of the `0.2.0` release, I have implemented analyses over Falcon that have found bugs. The IL is stable, the lifters work, and Falcon is a usable platform for static analysis.

While not required, my analyses make heavy use of [gluon](https://github.com/gluon-lang/gluon) bindings in a sister project named [osprey](https://github.com/falconre/osprey). I find rust compile times frustrating for exploratory analysis, and if you wish to use Falcon, I recommed you learn the osprey bindings.

Falcon _is_ suitable for Symbolic Execution, though support for Symbolic Execution has been removed from the public repository.

# Building and Using

Falcon builds and runs on Rust stable.

I push to master for development. If you want to build off a Falcon which does not have unstable API changes, use a tagged release.

You will need the correct dependencies for bindgen to build the capstone bindings. The `Dockerfile` has everything required to get you set up.