[![Build Status](https://travis-ci.org/falconre/falcon.svg?branch=master)](https://travis-ci.org/falconre/falcon)
[![Coverage Status](https://coveralls.io/repos/github/falconre/falcon/badge.svg)](https://coveralls.io/github/falconre/falcon)

# Welcome to Falcon

Falcon is a formal binary analysis framework in Rust. Falcon seeks to implement data-flow analysis, abstract interpretation, and constraint solving over compiled, binary executables.

* Expression-based IL with strong influences from [Binary Ninja](https://binary.ninja) LLIL and RREIL.
* Semantically-equivalent binary translation.
* IL can be translated to smtlib2 (z3) and solved for. Under-pinnings for symbolic execution provided.
* Fixed-point engine for data-flow analysis and abstract interpretation. Basis analyses provided.
* Lifters for Binary formats (initially Elf). This includes run-time linking, assuming dependencies are provided.

# Questions / Support

* An example project can be found at [github.com/endeav0r/falcon-palindrome](https://github.com/endeav0r/falcon-palindrome), which has an [accompanying blog post](http://reversing.io/posts/2017-08-12/)
* Documentation is available [here](https://files.reversing.io/falcon-docs/0.1.0/falcon/) for the tagged `0.1.0` release. Please run `cargo doc` for the latest documentation.
* I write about Falcon on my [blog](http://reversing.io/). [Just posts about Falcon](http://reversing.io/tags/falcon/).
* I am idling in irc.freenode.net#rust-falcon.
* You can also find me in the Binary Ninja slack under the name "endeavor".

# Should I use Falcon? / When will Falcon be stabilized?

Falcon has hit `0.1.0`. This means:

* "Things are working," but, "Everything has not been flushed out."
* Falcon is capable of producing results for toy binaries.
* I am ready for people to open issues, and receive feedback.

There will most likely be some API changes in the next few releases. If you aren't actively developing on Falcon, I recommend you use a tagged released.

# Building and Using

Falcon builds and runs on Rust stable.

See the [palindrome-example](https://github.com/endeav0r/falcon-palindrome) repository as an example program which uses Falcon.

I push to master for development. If you want to build off a Falcon which does not have underlying API changes, use a tagged release.

You will need the correct dependencies for bindgen to build the capstone bindings, as well as `z3` on the commandline. The `Dockerfile` has everything required to get you set up.

For OSX (on which I'm developing), `brew install z3` seems to be enough to make things work, as well as a typical rust install.

## Steps for OSX
```
brew install capstone
git clone https://github.com/falconre/falcon.git 
cd falcon && cargo test && cargo doc
```
open `target/doc/falcon/index.html` for documenation 
