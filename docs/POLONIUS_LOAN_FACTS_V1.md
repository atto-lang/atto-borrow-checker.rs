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


## Path-sensitive lifetime inference (second experimental slice)

The first slice required the adapter to supply every point's live_origins
directly. A fabricated empty set could appear to approve an invalid borrow.

The new analyze_with_inferred_liveness(&Facts, &[OriginUse]) rejects caller-
supplied live_origins and derives pointwise liveness by a bounded backwards MAY
fixed point over the supplied CFG, terminal uses and transitive reverse subset
constraints. It then runs the existing forward analyze loan-invalidation pass.
A return of a borrowed value is an OriginUse on its return arm. It does not
create a use on any alternate arm. This reproduces the familiar
HashMap.get_mut -> Some(return borrow) / None(insert, retry) regression.

Important limitations:
- OriginUse is still compiler-supplied, NOT independently complete or
  cryptographically attested. Omission of a return/capture/FFI use can admit
  unsafe data. Until independent typed-MIR source and emission inventories
  exist, these results are diagnostic HOST_ONLY model reports.
- The backwards inference currently lacks SSA region definition/overwrite
  kills, so it can conservatively retain a region too long after reassignment;
  this is a false rejection, not a justification to weaken safety.
- The output does NOT authorize a borrow across await/select, actor hops,
  graph copying, mutable reborrowing, raw pointers, destructor effects or
  exceptional cleanup. Runtime pinning, stack/arena generation fencing and
  Sendable isolation remain separate obligations.
- Function-entry borrowed arguments must be represented as entry issued loans.
  Every return/capture that needs an origin must be an OriginUse.
- Resource budgets apply to origin count, retained facts, CFG edges, input
  use counts and inference work; exhaustion fails closed.

New tests include a full five-point None-branch insertion/relookup flow,
negative mutations on either borrowed arm, join-required borrow preservation,
outlives/subset propagation, loop backedges, malformed source inventories,
and bounded adversarial inputs.

Rust's actual Polonius Alpha uses a more sophisticated combined CFG/outlives
formulation. The new pass is intentionally narrower, and does not claim to
implement Rust's actual algorithm, stabilize AttoLang's syntax, or certify
compiled guests.


## Strict typed-MIR census and SSA edge-phi model (third experimental slice)

The new mir_lifetime_census_v1::verify_closed_census API requires **two**
explicitly separate manifests:

1. expected_events, which a compiler MUST enumerate from independently
   validated source/typed MIR, not from its lowering event stream;
2. observed_events, enumerated by its actual typed-MIR lowering.

Both require unique nonzero event IDs and source-node IDs. Exact, complete
event equality includes every instruction point, CFG edge, loan issue,
invalidation, kill, origin subset and use (including returned borrows).
Unknown or unsupported effect categories are rejected; duplicate point
declarations, dangling CFG edges, malformed origin IDs and census drift
fail closed. The bridge reconstructs the loan facts from the verified
submitted records; consumers cannot silently pass a hand-built graph
with omitted observed effects to this entrypoint.

### SSA phi and overwrite discipline

The experimental PhiEdge event is permitted only at a **dedicated split
point** with one incoming CFG predecessor, one outgoing successor, and no
other loan/mutation/use effects. Each incoming predecessor must have its
own split point. This preserves path-specific transfers into a fresh
SSA phi origin without introducing an unrestricted join-wide subset.
Actual compiler-side SSA definition uniqueness, dominance, dynamic
index/alias disjointness and overwrite kills are **not yet verified**:
SSA origin identities must be minted by the compiler and reused-origin
overwrites must remain unsupported in production integration. Do not
claim full Polonius Alpha or true SSA dominance validation on this evidence.

### Important safety and CI boundaries

Exact agreement of TWO untrusted submitted inventories does not
authenticate a program or its compilation. It is impossible for this
library to prove the expected_events census is complete without an
independent authoritative source/type/MIR reader and reverse check of
emitted code operations. A caller could omit the same ownership effect
from both manifests. Compiler integrations MUST provide independent
provenance, authenticate source bytes, compiler identity and full effects,
and fail closed on FFI, unwind/cancellation, actor hops, pinned suspension
and unsupported operations. An unverified successful census is HOST_ONLY
and must NEVER override the existing production borrow/codegen gate.

The new regression suite tests the conditional Some-return/None-insert
borrow, mismatched/missing/injected source and lowered MIR events,
unsupported effects, duplicate event or point identities, malformed
CFG edges, edge-local SSA phi merges, negative live-loan invalidation,
budget rejection and input-order determinism. The six independently
authored adversarial tests from PR #36 were also reconciled into this
branch without importing its outdated solver changes.
