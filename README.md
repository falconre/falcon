[![Build Status](https://travis-ci.org/endeav0r/falcon.svg?branch=master)](https://travis-ci.org/endeav0r/falcon)

# Welcome to Falcon

Falcon is a formal binary analysis framework in Rust. Falcon seeks to implement data-flow analysis, abstract interpretation, and constraint solving over compiled, binary executables.

* Currently unstable. See _Should I use Falcon?_ for explanation on when Falcon will be suitable for public digestion.
* Expression-based IL with strong influences from [Binary Ninja](https://binary.ninja) LLIL and RREIL.
* Semantically-equivalent binary translation.
* IL can be translated to smtlib2 (z3) and solved for. Under-pinnings for symbolic execution provided.
* Fixed-point engine for data-flow analysis and abstract interpretation. Basis analyses provided.
* Lifters for Binary formats (initially Elf). This includes run-time linking, assuming dependencies are provided.

# Should I use Falcon? / When will Falcon be stabilized?

When Falcon hits `0.1.0`, all tasks in the current `0.1.0` milestone will be complete, and Falcon will symbolically explore the `simple-0` example. At this time I will consider the IL stable, and any errors in translation/lifting as critical. `0.1.0` will be suitable for use in translating binaries, assuming you can wait for, or contribute, fixes to translation as needed.

There will be some refactoring after `0.1.0`, with a heavy focus on analysis and symbolic execution. More-To-Follow on those items post `0.1.0`.

# Building

As of 1.18, everything, including docs, builds with rust stable.

You will need the correct dependencies for bindgen to build the capstone bindings, as well as `z3` on the commandline. The `Dockerfile` has everything required to get you set up.

Build and run the docker to see the latest output of whatever I'm working on. Things will be cleaned up for `0.1.0`.

For OSX (on which I'm developing), `brew install z3` seems to be enough to make things work, as well as a typical rust install.
