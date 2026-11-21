# Borrow-checker conformance plan

**Status: harness implemented (L1 canonical side + L3 tooling); no backend has
submitted results yet.** Every backend is `NOT_EXECUTED` until it runs the
steps below on an exact head.

## Model

Each `atto-lang/atto-source.*` compiler keeps its **own** borrow checker,
running in the same pass as its ordinary type/CFG construction (see
[hybrid integration](HYBRID_COMPILER_INTEGRATION.md)). This repository is
the **master** checker. It does not replace those in-pass checkers. It gives
them one shared definition of "correct" and independently re-verifies what
they decided.

```text
                    atto-spec (language rules)
                              │
   atto-platform-conformance  │   atto-borrow-checker.rs (this repo)
   .atto source corpus (BCV1) │   graph corpus · registry · wire · CLI
              │               │               │
              ▼               ▼               ▼
  ┌──────────────── each atto-source.<backend> ────────────────┐
  │ parse → types → in-pass ownership check → codegen           │
  │                     │                                       │
  │        L1 graph adapter     L3 export: local verdict + MIR  │
  └─────────────┬──────────────────────────┬────────────────────┘
                ▼                          ▼
     atto-borrow-conform graph-results   atto-borrow-conform cross-check
```

| Owns | Repository |
|---|---|
| Language rules | `atto-spec` (chapter 04, implicit-argument-borrow-v1, ownership-vocabulary-v1) |
| Source `.atto` fixtures + per-backend execution receipts (L2) | `atto-platform-conformance` (`contracts/borrow-checker-v1.tsv`, `fixtures/borrow-checker-v1/`) |
| Canonical semantics, graph corpus (L1), code registry, wire format, cross-check (L3) | **this repo** |
| In-pass checker, L1 adapter, L3 exporter | each `atto-source.*` |

Source fixtures stay in platform-conformance, because that repo already holds
the BCV1 matrix and its receipts. This repo consumes those fixtures by path.
It does not copy them.

## The three levels

### L1: graph conformance (engine vs. canonical, exact codes)

`conformance/graph-cases-v1.json` holds 59 source-free ownership graphs, each
with an expected verdict and an **exact** canonical code. The categories are
moves, copies, loans, suspension, actors (including the prepare/commit/abort
mail transaction), tasks, freeze, share, weak, pin, deep copy, joins, loops,
exits, identities and effects. The canonical checker must pass all of them
(`tests/conformance_v1.rs`).

A backend writes a small **graph adapter**: it feeds each case's ops directly
into its native ownership engine, bypassing the parser, and emits one
`atto-borrow-graph-results-v1` line per case. That tests the backend's real
lattice code, not a JS model of it. If the engine cannot represent an op, it
must answer `unsupported`. Guessing is not allowed.

```sh
atto-borrow-conform graph-results conformance/graph-cases-v1.json llvm-results.jsonl
```

This level suits engines with an explicit event API (LLVM `OwnershipCfg`,
Forge `ownership_v1.hpp`, Rust/Cranelift). AST-driven checkers such as Java's
`OwnershipChecker` may skip it and rely on L2 and L3.

### L2: source conformance (compiler vs. BCV1 oracle, family codes)

Each backend compiles the BCV1 `.atto` fixtures. A `PASS` row must compile and
return 42. A `REJECT` row must emit the intended ownership diagnostic and **no
artifact**. Platform-conformance's `bin/run_borrow_checker_matrix.rs` already
does this with exact-tree provenance. This plan adds one requirement: the
reject code must **conform** under the registry below, meaning it is either the
canonical code or one of its families. Free-text messages alone do not count.

### L3: cross-verification (master re-checks each backend's decision)

While compiling, each backend exports one `atto-borrow-backend-report-v1` line
per function. The line holds the backend's own verdict, plus either the
`atto-borrow-mir-v1` graph it derived or an honest `mirUnavailable` reason. The
master re-verifies the graph:

```sh
atto-borrow-conform cross-check java-report.jsonl
```

| Class | Meaning | Fails? |
|---|---|---|
| `AGREE` | same verdict; the reject code conforms | no |
| `BACKEND_PERMISSIVE` | backend accepted what canonical rejects: **unsound** | **always** |
| `CODE_MISMATCH` | both reject, but for unrelated reasons | yes |
| `ADAPTER_DEFECT` | exported graph is malformed (identity reuse, bad inventory) | yes |
| `BACKEND_STRICTER` | backend rejected what canonical accepts | yes, unless `--allow-stricter` |
| `OUT_OF_SCOPE` | canonical model limit or budget (loops, divergent joins, FFI) | no; not evidence |
| `NON_OWNERSHIP_REJECT` | backend rejected for syntax/type reasons | no; not evidence |
| `NOT_EXPORTED` | no MIR exported | no, unless `--require-mir` |

When the local and canonical results disagree, **fail closed** (hybrid design
safety rule). A strict compiler build blocks codegen on any failing class.

## Diagnostic registry

`conformance_v1::REGISTRY` (print it with `atto-borrow-conform registry`)
classifies every canonical code:

- `SEMANTIC`: a real user ownership error. Each such code lists the
  source-level **families** it may be spelled as, e.g.
  `E_USE_AFTER_MOVE_OR_DROP` → `E_MOVED`, `E_DROPPED`, and
  `E_BORROW_CONFLICT` → `E_BORROW`, `E_SHARE_ALIAS`.
- `MODEL_LIMIT`: a conservative reject of the restricted model, not a
  language rule.
- `ADAPTER`: a malformed graph. A correct frontend can never produce one.
- `BUDGET`: an analysis bound was hit. Fail closed; not evidence.

A test fails if the checker gains a code without a registry row. Backends
must attach a registry code (canonical or family) to every ownership
diagnostic. Today Java emits free text only, and LLVM throws
`"ownership violation: ..."` strings.

## Evidence labels

These match the existing contract vocabulary: `NOT_EXECUTED`,
`SOURCE_AUTHORED`, `HOST_ONLY`, `COMPILER_NEGATIVE_EXECUTED`,
`COMPILED_GUEST_EXECUTED`, `CERTIFIED`.

- An L1 pass is `HOST_ONLY`.
- An L3 `AGREE` over real compiler exports, at an exact compiler head, is
  compiler evidence for that function's **exported graph**. It does not prove
  that the graph is complete or that codegen honors it.
- Only L2 with executed guests can reach `COMPILED_GUEST_EXECUTED`.
- Zero-step CI runs are `NOT_EXECUTED`.

## Per-backend state and first steps (survey of `origin/main`, 2026-11-21)

| Backend | Ownership engine today | Diagnostics | First step |
|---|---|---|---|
| **rs** (`atto-source.rs`) | `tuple_ownership_ir.rs`, `owner_arena.rs`; 6/40 BCV1 verified Rust→Wasm | already `E_MOVED` / `E_BORROW` | L3: dev-depend on this crate in tests, export MIR for BCV1 fixtures |
| **java** | `OwnershipChecker.java` (≈6.7k lines, AST-driven); `BorrowMirAuditV1` observer covers only straight-line Copy-parameter functions | free text | tag diagnostics with registry codes; extend the observer to emit `atto-borrow-backend-report-v1`; L2+L3 |
| **llvm** | `OwnershipCfg.hpp` powerset lattice (joins and loops); `OwnershipChecker.cpp` | `runtime_error` strings | L1 adapter over `OwnershipCfg::Graph`; map `DropIfOwned` → `UnknownEffect` |
| **net** | no standalone ownership module found outside tests | — | locate the checker; L2 first |
| **forge** | `include/atto/ownership_v1.hpp` | — | L1 adapter |
| **cranelift** | `src/frontend.rs` rejects ownership/lifetime syntax at stage 0 (`tests/borrow_mir_negative_admission.rs` `include_str!`s the vendored corpus) | — | link this crate directly; repoint that test at the pinned corpus |
| **wasm** | contract doc only | — | L2 via the shared Rust frontend; worker-transfer fences later |
| **js**, **hdl** | none | — | L2 rejects-only until an engine exists |

### Remove vendored drift

Java, LLVM, .NET, Rust, Cranelift and Forge each carry
`contracts/borrow-mir-v1/semantic-cases.json`. Their case bodies are
identical, but the headers already differ: Java lists 6 backends, the others
list 9. Each repo also checks the file with a source-free Node model, never
against this checker. Replace each copy with a **pinned reference**: this
repo's commit, plus the git blob SHA of `conformance/graph-cases-v1.json`.
The backend's CI verifies the blob and runs its L1 adapter against it. The
old Node tests then become redundant.

## Milestones

1. **M0 (this change)**: corpus moved here and expanded to 59 cases; registry;
   strict dependency-free wire format; `atto-borrow-conform` CLI; tests.
2. **M1 – first real cross-check**: `atto-source.rs` exports L3 reports for
   the BCV1 fixtures, and Java tags codes and exports for its straight-line
   profile. The goal is the first `AGREE` and `BACKEND_*` counts from real
   compiler output.
3. **M2 – L1 adapters**: LLVM and Forge graph adapters; replace the vendored
   copies with pinned references in all six repos.
4. **M3 – canonical coverage**: V0 rejects loops and divergent joins, so most
   real functions will be `OUT_OF_SCOPE`. Extend the canonical model to MAY/MUST
   joins and fixed-point loops, using `cyclic_v1` as the starting point. This
   gives L3 coverage over ordinary control flow. It is the main blocker for
   meaningful cross-verification of LLVM, whose engine already handles joins.
5. **M4 – strict mode**: compilers gain `--borrow-strict`, which runs the
   canonical checker in process (Rust/Cranelift link it; others use a
   persistent worker) and blocks codegen on any failing class. CI matrix: every
   backend × L1/L2/L3 on exact heads, via the authorized mirror carrier while
   hosted Actions are billing-blocked.

## M1 adapter notes: `atto-source.rs` (survey of `src/check.rs` at `7f893323`)

The checker is lexical and AST-driven. Its `FnCx` keeps
`moved: BTreeSet<slot>` and `loans: BTreeMap<loan_slot, ScopedLoan{owner, mutable}>`.
Branch arms union `moved`, and `pop_scope` silently removes loans and moves when
a scope ends. To export MIR faithfully:

- **Owner ids** are `slot + 1`; canonical ids must be nonzero. **Loan ids**
  are the borrowing binder's slot + 1. **Move destinations** come from the
  destination local's slot, or a fresh id above `MAX_LOCALS` for temporaries.
- **Record before check.** The checker returns its first error, so emit each
  event *before* the corresponding check. A rejected function then exports the
  event prefix up to and including the failing op, and canonical has to find
  the same failing op independently. Mark the record
  `note: "prefix-at-local-error"`.
- **Close loans at exit.** `return` exits the lexical scopes that hold live
  loans, so emit `EndBorrow` for every live loan before `Return`. Otherwise
  each function that holds a loan reports a false `E_LOAN_ESCAPE`.
- **Hook sites:**
  - `Var` reads → `Read`;
  - field assignment → `Write`;
  - `consume()` (binding initializer, assignment, argument and return of a
    class local) and `take!` → `Move`;
  - `borrow_binding` → `Borrow`;
  - `pop_scope` loan removal → `EndBorrow`;
  - standalone `drop!` → `Drop`;
  - `new C()` binding → `Init{copy:false, send:false}`;
  - scalar locals → `Init{copy:true}`.
- **Fail closed** with `mirUnavailable` for if/match/loops, calls with
  non-scalar arguments (until the implicit-borrow effect summary is exported),
  closures, actors, `isolated` cleanup bodies and generators. Branches can
  become real CFG blocks once M3 gives canonical joins.
- **Diagnostics** already use `E_MOVED` / `E_BORROW`, so no retagging is
  needed. Expect `BACKEND_STRICTER` for its conservative rejects, e.g.
  `E_BORROW` on "reborrowing a borrowed handle", which the canonical model has
  no op for. Track those as known strictness rather than failures.
