# 0.2.1

## Api Breakage

* Changed BTree containers in analysis/use_def to Hash containers.
* Moved store/load methods from `domain::Memory` to `domain::Domain`

## Fixes

* Removed unused regex and lazy_static crates.
* Removed `Display + Serialize` trait requirements for `domain::Value`
* Relax trait requirements for `domain::Expression`

## Additions

* Add `remove_variable` function to `domain::State`
* Add `stack_pointer` function `types::Architecture`
* Add `locations` function to `il::Function`
* Add an `into_` method for `domain::Expression` to help translate expressions
between domains.
* Added `symbolize` function to `domain::State`