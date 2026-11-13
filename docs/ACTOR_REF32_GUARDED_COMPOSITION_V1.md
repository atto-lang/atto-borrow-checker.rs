# Guarded ref32 composition V1 — conservative Rust model

**Status:** canonical Rust *model integration* with source-authored tests; NOT a
native actor heap, singleton/symbol implementation or compiler guest proof.

## One ref32 authority

The merged `actor_arena_ref32_v1::ActorArenaRef32` from PR #18 remains
the **single allocation metadata and checked ref32 authority**. Its guest
offset zero is invalid and its maximum usable allocation capacity is
`u32::MAX`; it reserves the first byte and permits a final byte at offset
`u32::MAX`. The offset is not a native pointer. Actor ID, arena identity,
generation and allocation provenance stay out of band in the private
`Ref32` model representation.

`actor_ref32_guarded_v1::GuardedRef32Arena` composes that existing model
with the existing `actor_state_guard_v1::GuardQueue`:
- All allocations occur before `seal`, and subsequent requests and accesses
  require a sealed arena. This conservative source-free profile is **not** a
  claim that dynamic actor allocation has been implemented.
- One reader/writer queue covers the **whole arena**, so it cannot assume
  two disjoint allocations are independently safe.
- Shared readers can coexist. A queued exclusive writer waits for readers,
  then excludes new readers. A reader cannot authorize a write.
- Tokens from another queue are rejected even if numeric actor/ticket IDs
  match. A valid permit does not override the canonical allocation bounds,
  actor-domain, alignment or generation checks.
- Logical STOP fences both outstanding permits and ref32 references. The
  model refuses reclaim until the **trusted host** reports physical
  quiescence; the host must establish that fact independently.

`checked_offset` returns a 32-bit offset, **never** a native reference or
physical access grant. It does not authenticate numeric actor identities,
grant shared-region capabilities, enforce tenant isolation, hold a physical
`RwLock` through native memory access, allocate backing memory or logical
stacks, or prove pinning/FFI/I/O cancellation. The production host must
authenticate the holder and enforce physical access/reclamation separately.
A successful check is necessary but NOT sufficient to emit a native load.

## Relation to PR #19

PR #19 defines a separately constructible `ActorArena`, `Allocation`,
`Ref32` and `Loan` inventory for *typed-MIR static preflight*. That can
be an independent negative diagnostic oracle; it **must not** become an
alternative runtime representation or replace the opaque, allocation-minted
ref32 authority in PR #18. Its 2^32-byte limit is a raw address-space
bound, not the merged arena's usable nonnull-offset budget. Before merging
that PR, reconcile the public names/bounds and add differential coverage
on null, final-byte, stale-allocation, cross-domain and loan modes.

## Executed evidence needed

On the **exact full PR head/tree**, with a nonzero-step admitted runner:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --all-targets --locked --release
```

The five new `tests/actor_ref32_guarded_v1.rs` cases are model-level tests.
Do not claim they passed until the real Rust toolchain executes them.

The next backend gate is one unchanged `.atto` fixture with detached
`critical-read` scalar followed by mailbox send **after scope exit**,
plus targeted negative cases for mutation under read, escaped loan,
suspension during critical scope, stale refs, wrong domain and double
release. Java/Graal, LLVM O0/O2 with sanitizers, and .NET NativeAOT must
independently parse, type-check, lower and execute; no host-model tests
count as guest execution. The four brokers must additionally prove
nonblocking socket/storage paths and durable protocol semantics before
70% performance comparisons.
