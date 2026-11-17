# Attested master verifier and safe dual-engine integration V1

**Status:** experimental compiler-facing Rust model. A PASS here is not independently authenticated source, AOT emission, native runtime ownership, or backend conformance.

## Architecture

The production Java, LLVM/C++, .NET/C#, Wasm, Forge, Cranelift and other frontends **retain their native ownership checker in the compiler's type/IR pass**. The Rust master checker runs as a stricter, independently implemented semantic verification oracle in strict builds and differential CI. It must never be used to hide native compiler disagreement.

## Stricter evidence boundary

`master_evidence_v1::verify_strict(function, manifest, resolver)` runs the existing complete typed MIR and ownership-bang inventory gate and V0 semantic checker *before* invoking the trusted `EvidenceResolver`. Source/MIR failures invoke zero callbacks and produce no proof.

The resolver must independently attest a reproducible `Producer` source unit/function and each exact instruction/source node/owner/obligation tuple:

- `CopyTrait` and `SendTrait` for true trait facts on `Init`.
- `OwnedAuthority` and `BorrowedLoanRoot` for ownership-bang source sites.
- `MutablePlace` for mutable loans (including non-bang MIR borrows).
- `FrozenSync` for immutable publication.
- `DetachedOwnedCopy` for detached values copied through a loan.

Requested obligations are bounded, deduplicated, deterministic, and denied on any missing or rejected proof. This is a *separate attestation interface*, not cryptographic authentication: a malicious, allow-all resolver does **not** make bad source provenance legitimate. The compiler owner must implement it using a genuinely independent parsed/typed AST + nominal layout/alias/effect proof path; never implement it as `return true` or as a self-confirming echo of MIR bits. Binding `producer.compiler_git_sha` and `producer.source_sha256` requires checking actual source bytes and toolchain elsewhere.

## Safe cross-check of the two Rust models

`master_dual_v1::verify_dual_profile` runs the strict witness gate **and** an additional `cyclic_v1::check` on an explicitly representable intersection:

- All roots must be initialized in a single contiguous entry-block prelude; no later allocation or reinitialization.
- Root-only reads, writes, drops, shared/exclusive borrows, loan-bound reads/writes, releases, suspension, and returns have exact translations.
- V0 alone produces the destructor cleanup proposal. `cyclic_v1` adds conservative MAY/MUST loan/move checks and never manufactures a V0 cleanup receipt.
- Both verifiers must accept. Any reject blocks this profile; there is no fallback accepting a permissive result.
- `copy!` and `take!` *already work through the strict V0 gate*, but their fresh-owner minting cannot currently be represented by `cyclic_v1`. Dual mode rejects them with `E_DUAL_UNMODELED_OPERATION`. Deep copying, shared regions, actor send/escrow, reference handles, exceptional cleanup, field projections with unproven layout, and cyclic CFGs remain unsupported in dual mode. They must retain individually appropriate proven profiles and cannot inherit dual status.

This is intentionally **phase 1**, not an assertion that the V0 and cyclic state machines have been fully merged. Future work must add minting/initialization/cleanup effects to a *single* ownership lattice, then enable loops and projected fields only with complete destructor/unwind proofs.

## Tests and CI

The `tests/master_attested_dual_v1.rs` model corpus checks independent evidence rejection (Copy, Send, mutable place, source root authority, immutable Sync, detached copy), zero callback publication on invalid MIR, stable producer-bound request inventories, dual-engine positive loan accesses, and negative transfer, fresh minting, late initialization, actor send, loop and loan escape.

Required exact-head:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --all-targets --locked --release
```

Only nonempty real runner steps on a SHA/tree-exact source revision count. The results are Rust-host model tests; run actual compiled AttoLang positive/negative guests and AOT profiles separately before claiming compiler parity.
