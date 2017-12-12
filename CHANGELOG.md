# 0.2.1

* Lots of soundness improvements. Many. This is where the majority of this release's time was spent.
* Removed Array from IL. Removed condition from `Operation::Brc`, and renamed `Operation::Brc` to `Operation::Branch`.
* Fixed-point interpreter now enforces partial order, however, the partial order can be, "Forced," which allows us to, "Cheat," in implementing analyses :).
* Lifter changes to more accurately reflect control flow. There was semantically-equivalent but duplicated code in the CFGs.
* Relaxed and simplified trait requirements for implementing abstract interpretations.
* Added calling conventions, and they can be used to improve analyses.
* Changed out almost every use of BTree for HashSet, which has dramatic performance increases.