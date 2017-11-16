# 0.2.1

## Api Breakage

* Changed BTree containers in analysis/use_def to Hash containers.
* Moved store/load methods from `domain::Memory` to `domain::Domain`
* Remove `endian()` method from `Translator` trait.
* Removed required methods for `ai::memory::Memory`, since they overlap with
`ai::domain::Value`.
* `ai::ksets` takes a `CallingConvention` instead of `Endian`.

## Fixes

* Removed unused regex and lazy_static crates.
* Removed `Display + Serialize` trait requirements for `domain::Value`
* Relax trait requirements for `domain::Expression`
* Fixed a bug in `KSetDomain::load`
* `HashSet` for worklist queue in fixed point was wrong. Replaced with VecDeque.
* Memory load with Top/Bottom index should return Bottom in KSet.

## Additions

* Add `stack_pointer` function `types::Architecture`
* Add `locations`, and `blocks_mut` functions to `il::Function`
* Add an `into_` method for `domain::Expression` to help translate expressions between domains.
* Add `symbolize`, `remove_variable`, and `memory_mut` functions to `domain::State`
* Add support for `Mipsel`, as it's only a minor change from Mips.
* Impl `analysis::ai::Interpreter` and add simple `new` method to create a new
abstract interpreter.
* Added calling conventions to analysis.
* Tests.