# AttoLang canonical borrow checker (Rust)

This repository hosts the **shared ownership verification core** for AttoLang. The language contract is canonical, but the fast compiler implementation remains local to each backend: Java/GraalVM, .NET/C#, LLVM/C++, Wasm, and Cranelift/Rust. Forge and the remaining oreslang-source.* compilers are additional conformance targets.

## Hybrid compiler architecture

Compiler-local type inference, ownership state changes and CFG construction can happen **in the same pass**. Repeated serialization, re-parsing and an external Rust process per function are not required. The shared Rust checker is used for independent proof, complex or unknown flows, and differential conformance; only equivalence-proven local fast paths may bypass its per-function invocation. When a local and canonical result disagree, fail closed.

See [hybrid integration design](docs/HYBRID_COMPILER_INTEGRATION.md).

## Current implementation

`src/lib.rs` implements a deterministic, bounded **V0 CFG ownership oracle** with move/copy/drop, shared/exclusive loans, task capture Copy and Send distinctions, conservative suspension and actor-hop fences, branch joins, and exit cleanup-order proposals. It is intentionally not a complete compiler or actor lifetime checker.

```sh
cargo test --all-targets
cargo clippy --all-targets
```

No external Rust dependencies are required. The tests are source-authored and remain **NOT_EXECUTED / NOT_CERTIFIED** until a runner executes this exact commit. The crate does not parse .atto, verify type trait provenance, support cyclic CFG loops, prove pinned continuations, or integrate into production backend code generation. Do not promote host-only assertions to guest compiler certification.

Related work: [AttoLang shared conformance](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/pull/646) and [broader Rust static analysis](https://github.com/ores-truffle-oreslang/oreslang-static-analysis.rs).
