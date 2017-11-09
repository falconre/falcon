# Issues

## Lifting Issues

### Implemented instruction has incorrect semantics

Please give the instruction in bytes, the given semantics, and the expected semantics.

### Unimplemented Instructions

Instructions over registers > 64-bits in width are not supported. Floating point instructions are not supported.

Please only open issues for instructions that are blocking your analysis. Do not open issues for instructions that are not implemented, but that you are not actively encountering in your analysis.

Please open _one_ issue, and make checkbox cases for the instructions missing from your analysis. Do not open separate issues for each instruction. For example:

#### Issue: Missing x86 instructions

- [ ] instruction_a
- [ ] instruction_b


### Unimplemented Architecture

Please reach out to me directly instead of posting an issue.

## Loader Issues

Please give a sample binary. If you cannot give a sample binary, you need to explain in very specific terms your issue, so that it can be replicated without a binary. If you cannot do this, please understand your issue may be labelled
#wontfix and closed.

# Pull Requests

Your pull request:

* Should increase overall code coverage.
* Should include tests for new functionality.
* Should not decrease code coverage. _It is very unlikely your PR will be accepted if you decrease coverage in already tested code_.
* Must include documentation for each module and function.
* Must pass all existing test cases.

# Implementing New Architectures

If you do not plan on implementing a new architecture, but wish to have an architecture implemented, don't open an issue. Reach out to me directly.

If you do plan on implementing an architecture:

* Do reach out to me directly. I will answer questions and assist.
* Don't open an issue for implementing a new architecture.
* Do fork to your own github repository.
* Do read documentation and talk to me about how architectures should be implemented.
