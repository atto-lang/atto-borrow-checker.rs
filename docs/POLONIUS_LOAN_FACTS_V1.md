# Polonius-inspired point-sensitive loan-fact oracle (experimental)

Status: **host Rust fact model only; NOT rustc Polonius Alpha and NOT AttoLang guest certification**.

Rust enabled Polonius Alpha on nightly in August 2026. Its main advance is flow-sensitive lifetime/outlives relationships so that a conditional early return of a borrow does not necessarily forbid mutation in the other branch. Rust's actual alpha analysis uses reachability across a combined CFG + outlives graph, with additional backward liveness traversal and its existing NLL scope/kill logic. This module is a deliberately restricted first step; it is **not algorithmically equivalent** to alpha.

Authoritative references:
- https://blog.rust-lang.org/2026/08/04/enabling-polonius-alpha-on-nightly/
- https://goals.rust-lang.org/2026/polonius.html
- https://doc.rust-lang.org/beta/nightly-rustc/rustc_borrowck/polonius/index.html

## Experimental API

The new public Rust module polonius_facts_v1 has a single function: analyze(&Facts).

Every Point represents an instruction entry. Facts contain:

- successors: complete control-flow edges; exceptional/cancellation edges must not be omitted
- live_origins: a full, independently derived fact for each point
- subset: directed (from_origin, to_origin) loan flow at this point
- issue: unique (origin, loan) IDs added to outgoing facts
- invalidate: loans that conflict with the current point's live entry loans
- kill: loans expired *after* the invalidation check, on outgoing edges

The solver performs a bounded MAY fixed-point analysis, propagates loan facts through transitive point-local subset edges, filters by live origins at each point, detects invalidations, then applies kills/issues for successors. A loan surviving on **any** predecessor must reject an invalidation. Conditional branches can drop loans when their origins are not live there.

This model uses explicit caller-supplied liveness and subset facts. It does not infer them; it does not run Rust's backward origin-reachability pass. There are explicit budgets for points, edges, origins, loans, input facts, accumulated retained facts, local facts and analysis work. It has no runtime allocation or actor-gate authority.

## Critical trust boundary

**Never use a successful Report to widen production language acceptance.**

Omitting a live origin, subset edge, CFG successor, invalidation, or issue can yield an unsafe false acceptance. Only an independently verified complete typed-MIR producer can authorize the evidence, and even then additional ownership checks are required. Every compiler must retain its own integrated borrow checker during the compiler pass rather than launching a Rust subprocess for each function.

Required before production use:
1. Independently derive source-to-MIR and MIR-to-emitted-operations inventories, including exceptional cleanup and cancellation.
2. Add a complete liveness and outlives analysis, including real return references, opaque/FFI effects, reborrows, closure captures and point-sensitive path constraints.
3. Track Place/root identities, field projections, aliasing, shared/exclusive permissions and initialized/moved state in addition to these loan facts.
4. Differentially validate with V0 and cyclic_v1 against real compiled positive and negative AttoLang guests. A discrepancy fails closed; old solvers stay authoritative.
5. Extend to actual Polonius Alpha-style combined CFG/subset reachability, including backwards edges, before claiming semantic equivalence.

## AttoLang-specific invariants remain separate

- borrow! requires shared/exclusive access checks and provenance.
- take! invalidates the original ownership path.
- copy! requires a valid Copy witness; copy!! must independently clone the mutable object graph for actor isolation.
- share! is allowed only under a proven immutable/frozen or explicitly guarded capability.
- ref!/deref!/unref! must retain affine handle generation and lifetime checks.
- await/select require pinned frame and cancellation proofs before retaining loans.
- actor sends, Mailman, Sendable, freeze guards, actor generation and domain boundaries do not become safe because a loan-facts model returned success.
- Unknown or external FFI effects cannot be silently classified as no-op.

## Evidence

The authored test suite in tests/polonius_facts_v1.rs checks branch-local liveness, MAY joins, subset transitivity, kill ordering, cycles, malformed facts, orphan blocks, budget rejection and deterministic fixed-point results.

Exact-head checks required:

    cargo fmt --all -- --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo test --all-targets --locked
    cargo test --all-targets --locked --release

An authored Rust test is not an executed result, and host tests do not prove AttoLang guest behavior. Record the exact branch HEAD, source Git tree, every executed CI step and test outcome before marking validation PASS.

Next: implement the real alpha-like combined-graph loan reachability and an independent typechecker/MIR adapter. Keep this experimental oracle isolated until then.
