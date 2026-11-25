# Shared singleton and symbol region: guarded model-level admission

**Status: Rust source/model tests only; not AttoLang runtime or compiler parity.**

The target language specification defines one shared owning domain for a
`singleton` and for published symbol storage. A shared reader does not
gain mutation authority; mutable singleton state and symbol interning require
one exclusive writer or compatible readers. Guest source uses `.atto`, not
`.ores`, and does not use Scala's `object` keyword as a singleton alias.

`tests/singleton_symbol_shared_ownership_v1.rs` checks the existing
`GuardQueue` and `GuardedActorRegion` models:

- Two distinct reader permits can be admitted while a later writer and reader
  wait in FIFO order. A read permit cannot write; a writer cannot bypass readers.
- A permit cannot be replayed in another shared region even when actor and
  numeric ticket match; holder identities are checked.
- STOP/generation retirement disables stale access and reclamation stays denied
  until the trusted runtime has actually completed physical quiescence.
- A trusted Rust region obtains a genuine nonblocking `try_read`/`try_write`
  guard for scalar model state. This is not an Atto guest heap/stack and does
  not prove kernel nonblocking I/O or lock-free operation.

This test does **not** introduce a singleton or symbol compiler intrinsic,
validate symbol-identity semantics, construct a shared-memory pipe, implement
actor heaps or protected ref32, authenticate externally supplied actor IDs,
or grant a guest access to the Rust test API. The runtime must also enforce
tenant/capability isolation and deny mutable access to immutable symbol
tables except through compiler-approved interning updates.

Run on the **exact complete PR head/tree** with nonzero executed CI job steps:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --all-targets --locked --release
```

## Required parity follow-up

1. Compile the spec's `singleton` and `define pub supervisor` forms and
   `critical-read`/`critical-write` scopes on real Java, LLVM, and .NET backends.
2. Independently derive shared-domain identity and Copy/Send/Share ownership
   witnesses in the three compilers. Run the canonical Rust verifier against
   authenticated typed-MIR inventory; fail closed on disagreement.
3. Exercise same-byte positive and negative `.atto` tests for concurrent
   readers, exclusive writes, stale/foreign handles, symbol interning races,
   tenant isolation, cancellation and physical retirement.
4. Run generated native LLVM O0/O2 sanitizer tests and .NET NativeAOT builds,
   plus actual Java guest execution. Verify actor-private heap/stack domains
   and guarded 32-bit arena offsets separately.

No benchmark, broker feature-parity, or 70% performance claim is supported by
these source-free tests. See language spec chapters 04, 05, 13 and 22.
