> **AI agent instructions (organization-wide):** Before working on code, issues, or pull requests, read and follow the [organization `AGENTS.md`](https://github.com/atto-lang/.github/blob/main/AGENTS.md), including its **merge-first stealth-development policy**. Honor any repository-local `AGENTS.md`, explicit holds, and GitHub-enforced rules.

# AttoLang canonical borrow checker (Rust)

This repository hosts the **shared ownership verification core** for AttoLang. The language contract is canonical, but the fast compiler implementation remains local to each backend: Java/GraalVM, .NET/C#, LLVM/C++, Wasm, and Cranelift/Rust. Forge and other `atto-source.*` backends are additional conformance targets.

## Canonical naming and specification

[atto-borrow-checker.rs](https://github.com/atto-lang/atto-borrow-checker.rs) is the maintained AttoLang repository. Use `.atto` source, `atto-*` repository names, and [atto-spec](https://github.com/atto-lang/atto-spec) for current language rules (ownership, borrowing, effects, actors, and syntax). Distinguish proposed and parser-only features from independently executed compiler support in [atto-platform-conformance](https://github.com/atto-lang/atto-platform-conformance). Naming migration does not by itself rename implementation artifacts, guarantee backend compatibility or certify guest execution.

## Hybrid compiler architecture

Compiler-local type inference, ownership state changes and CFG construction can happen **in the same pass**. Repeated serialization, re-parsing and an external Rust process per function are not required. The shared Rust checker is used for independent proof, complex or unknown flows, and differential conformance; only equivalence-proven local fast paths may bypass its per-function invocation. When a local and canonical result disagree, fail closed.

See [hybrid integration design](docs/HYBRID_COMPILER_INTEGRATION.md).

## Current implementation

`actor_arena_ref32_v1` models nonzero 32-bit arena-relative offsets, per-actor/arena/generation identity, allocation extents and alignment, overflow-denial, and stale-retirement rejection. Its independent Rust tests are **model-only**: there is no actual native heap, pointer, physical shared-memory guard, compiler lowering, or quiescence proof in this module. Backend integrations must retain arena/domain/generation metadata outside the 32-bit guest offset, verify each access, and separately enforce loan and physical-retirement rules.


`src/lib.rs` implements a deterministic, bounded **V0 CFG ownership oracle** with move/copy/drop, shared/exclusive loans, task capture Copy and Send distinctions, conservative suspension and actor-hop fences, branch joins, and exit cleanup-order proposals. It is intentionally not a complete compiler or actor lifetime checker.

`cyclic_v1` reconciles the field-sensitive loop analysis from PR #2 without
replacing V0 or its typed-MIR/shadow contracts. It supports nominal field
projections, MAY/MUST joins, checked move/reinitialization loops, compatible
readers and exclusive writes through live loans. Preflight graph limits,
deduplicated work queues, charged analysis work and retained-state limits bound
the checker. This model has **no destructor cleanup plan or complete MIR
inventory wrapper** yet; a successful report cannot authorize lowering a V0
program that V0 rejects. See [cyclic model boundaries](docs/ARCHITECTURE.md).

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --all-targets --locked --release
```

No external Rust dependencies are required. The reconciled baseline has executed local Rust tests; see [integration evidence and remaining work](docs/INTEGRATION_BASELINE.md). These are library/model tests, **not guest compiler certification**. The crate does not parse .atto, verify type trait/layout provenance, prove pinned continuations, or integrate into production backend code generation. V0/MIR V1 still reject cyclic CFGs. Do not promote host-only assertions to guest compiler certification.

V0 preflights a cumulative 100,000-operation limit as well as per-block and
edge limits, before semantic scanning or shadow publication. MIR uses the same
cumulative limit. Boundary tests admit exactly 100,000 operations and reject
100,001. An independent straight-line specification checks both solvers against
all 66,430 sequences of zero through five operations over nine read/write,
loan, drop and suspension operations. This exhausts that finite subset only;
it does not certify arbitrary loops, projections, compiler adapters or guests.

V0 now also distinguishes actor-owned mailbox moves and Copy+Send snapshots from explicit immutable publication and runtime-owned guarded promotion. A three-phase actor-mail transaction (`ActorSendPrepare`, `ActorSendCommit`, `ActorSendAbort`) models exclusive pending-owner escrow and sender rollback across CFG paths; it does **not** implement actual mailbox admission or runtime cancellation fencing. These are **static ownership handoff preflights**, not shared memory access grants or proof of actual per-actor heap placement. See [actor/shared ownership boundaries](docs/ACTOR_SHARED_OWNERSHIP_BOUNDARIES_V1.md) and [the dedicated negative tests](tests/actor_shared_boundaries_v1.rs).

`mir_v1::verify_mir_with_shadow_v0` validates the full operation inventory and input budgets before canonical verification, and publishes observations only after the entire CFG succeeds. Native compiler adapters remain responsible for independently deriving the complete typed inventory.

Related work: [AttoLang platform conformance](https://github.com/atto-lang/atto-platform-conformance) and [Rust static analysis](https://github.com/atto-lang/atto-static-analysis.rs).
