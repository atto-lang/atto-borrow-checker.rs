# AttoLang canonical borrow checker

This is a **draft, conservative Rust ownership/loan oracle**, not a replacement for compiler-integrated borrow checking.

Java/GraalVM, .NET/C#, LLVM/C++, Forge, Wasm and Cranelift remain free to perform ownership checking in their normal typed MIR / CFG passes. The canonical checker and a shared fixture corpus define the common target and detect semantic drift.

The current library accepts a small, typed CFG with Place roots and field projections, Move/Copy/Read/Write/Drop, Reinitialize, shared/exclusive loans, explicit EndLoan, Transfer and Suspend. It rejects unsupported or ambiguous states rather than accepting them. This is **not** yet a complete production AttoLang borrow checker, and it is not connected to any backend or real compiled .atto guest.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for trust boundaries, known gaps, and the full integration plan.

## Local development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --locked
```

**Verification status:** SOURCE_AUTHORED / NOT_EXECUTED until stepful toolchain evidence is available. Do not promote this draft or claim compiler parity from source code or synthetic Rust unit tests.
