# Ownership-bang canonical Rust oracle V1

**Status:** experimental, source-model only. This contract is not a compiled AttoLang guest, authenticated backend adapter, physical heap/lifetime proof or cross-backend certification.

## Architecture decision

The Rust crate is the **leader/reference** for the ownership rules, deep CFG auditing, adversarial verification and differential conformance. It is **not** an always-on foreign process through which every backend statement must pass.

All compiler implementations retain a **native, same-pass borrow checker** while resolving types and creating typed HIR/MIR:

- Java/GraalVM: Java type checker + ownership checker.
- LLVM: C++ compiler semantic/ownership pass.
- .NET NativeAOT: C# semantic/ownership pass.
- Wasm, Forge, Cranelift, JS, RS and other compiler frontends: their own corresponding native pass.

The native checker must deny everything the authoritative contract denies. A native implementation may reject a feature not yet modeled, but must not accept it through lossy conversion or a guessed trait. In strict builds/CI, an independently collected immutable typed-MIR inventory is sent to the Rust verifier. An ownership rule mismatch blocks code generation and is filed as a conformance bug. If the Rust checker does not model a feature, there is **no automatic Rust PASS**; a separate explicit profile and proof are required.

## Bang syntax and exact lowering

| Atto source | Exact canonical MIR operation | Gate |
| --- | --- | --- |
| `copy! x` | `Op::Copy { from, into }` | source owned, transitive Copy proof |
| `copy! borrowed_x` | `Op::CopyThrough { owner, loan, into }` | attached active loan to the canonical root, Copy proof and independent no-borrowed-referents **detached-value** proof; destination becomes **owned** |
| `take! x` | `Op::Move { from, into }` | exclusive owned authority, no live loans, no use after move |
| `borrow! x` | `Op::Borrow { kind: Shared, .. }` | authenticated addressable owned place; multiple readers |
| `borrow! mut x` | `Op::Borrow { kind: Mutable, .. }` | writable place and exclusive loan, no competing loan |
| `share! x` | `Op::PublishFrozen { owner, region, sync_proven: true }` | owned root, separate Send/Sync/freeze proofs, consume old owner |

The same typed meaning holds for the compact spellings and legacy `rt` aliases. Only the compiler's tokenizer/parser enforces adjacency of verb and `!`, precedence, postfix grouping, operand evaluation exactly once, spacing, and the special canonical `borrow! mut` order. The `Spelling` enum is a semantic provenance label, **not a lexer**. It never relaxes ownership checks.

**Critical sharing rule:** a borrowed argument, borrowed field projection, borrowed scalar, actor-state root, unknown/computed root or untracked alias cannot be upgraded to shared authority by applying `share!`. A snapshot is only independently ownable when `copy!` has actually copied a `Copy` value through an active loan into a fresh owner. The mutable borrow is not a secret ownership transfer.

This initial `share!` profile models immutable/frozen publication only. A separately synchronized `rt mut share` / `SharedMutex<T>` operation, mutable shared regions and reference-counted handle operations require their **own** explicit profile; they must not be silently treated as `PublishFrozen`.

## Usage

The compiler constructs the existing `mir_v1::MirFunction` using real typed ownership instructions, then a **separate source-site census**:

```rust
use atto_borrow_checker::ownership_bang_v1::{
    verify_bang_mir, BangManifest, CONTRACT_VERSION,
};

let manifest = BangManifest {
    version: CONTRACT_VERSION.to_owned(),
    sites: compiler_derived_bang_sites,
    source_bang_instruction_ids: independent_source_bang_census,
};
let proof = verify_bang_mir(&typed_mir, &manifest)?;
```

The Rust bridge checks bounded, unique source IDs; exact site-to-MIR source node and operation mapping; canonical authority and operand shape; matching source census; and the existing complete MIR instruction/effect inventory before a `Proof` is returned. It **cannot authenticate** caller-owned source-site lists, nominal traits, field disjointness, frozen Sync witnesses, guest codegen, parser correctness or hashes supplied by an untrusted producer. Use a distinct census generated from the actual parsed/typed AST, not by mapping the supplied sites. The compiler must bind both inventories to the same exact source/CFG graph and independently verify emitted-code effects and exceptional/cancellation edges.

The V0 graph uses canonical alias roots only; a projected place must have a compiler-proven alias root. Arbitrary dynamic indices, union aliasing, partial moves, NLL reborrowing and unsafe foreign lifetimes are **not supported by this V1 adapter**. Deny them until a dedicated authoritative profile exists.

## Loan-bound access

V0 now also models `ReadThrough { owner, loan }` and `CopyThrough { owner, loan, into }`. Both require a live matching loan. `CopyThrough` requires `Copy` **and** an explicit compiler-attested detached-value/escape proof to exclude copies of references or borrowed handles. It creates a fresh owned snapshot, while leaving the original loan and root intact; loan IDs cannot be manufactured after release. `WriteThrough` remains exclusive-mutable-only. Generic owner reads cannot authorize reading through an expired loan.

The full models remain intentionally different:
- V0/typed MIR: acyclic, root-only ownership, loan-bound access, deterministic cleanup proposal. No true NLL, exceptional cleanup, or pinned suspend.
- `cyclic_v1`: field-sensitive cyclic MAY/MUST dataflow, but no V0 cleanup/MIR-inventory composition.
- Actor arenas/guards: source-free allocation, runtime lease, generation and fairness models, not verified compiler guest access.
- Future canonical analysis: interprocedural ownership, closures, NLL, reborrows, unsafe FFI summaries, destructors, panic/raise/throw cleanup, actor critical scopes, pin/await/select and cancellation, hot load/actor durable revive.

Never combine a PASS from one partial model with a PASS from another to infer a universal PASS.

## Required proof gates

1. Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --all-targets --locked` and `cargo test --all-targets --locked --release` at the **exact** Rust PR head with nonempty job steps.
2. Differential-test the real compiler-local AST/typed MIR over canonical and compact/legacy ownership aliases, mutable-borrow ordering, lexer adjacency, nested postfixed operands, malformed code and source-node identities.
3. Execute positive and **specific negative** `.atto` fixtures on Java/Graal, LLVM O0/O2, .NET NativeAOT, Wasm, Forge and the other target backends when supported. Prove compile-time rejection, not parser-only refusal or host-only model PASS.
4. Independently audit emitted moves, copies, loan uses, suspend/return/exception/drop/actor-send events, and provenance. Deny unsupported effects.
5. Only promote new optimization fast-path profiles after reviewed differential corpus, exact build SHAs, execution steps, no skipped tests, and owned runtime safety evidence.

Related specification: [ownership-bang aliases](https://github.com/ores-truffle-oreslang/attolang-language-spec.md/pull/67).
