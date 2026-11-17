# SSA lifetime analysis and typed-MIR census bridge (experimental)

**Status: host-Rust diagnostics only. NOT a production AttoLang borrow checker, Polonius Alpha, a compiler/guest AOT proof, or actor authorization.** No caller may use `analyze_ssa` or `mir_loan_census_v1::project` to admit programs rejected by existing authoritative V0/cyclic, runtime, actor or backend gates.

## Why separate SSA definition and origin liveness?

`polonius_facts_v1::analyze_with_inferred_liveness` has branch-specific backward MAY liveness, but no SSA definition kill or phi-edge model. An origin value overwritten at a definition must not force the new origin to live before its own definition. This module tracks **one definition per OriginId**: overwrites receive fresh IDs. Its backwards result separates `live_before_definition` from `live_at_instruction`, and checks that every explicit use and local subset source has a dominating definition.

`PhiInput { predecessor, successor, source, destination }` requires a distinct, complete mapping for every incoming edge. Backwards liveness propagates only each edge's corresponding source; forward loan checks conservatively union the possible phi-source loans at the join. A loan live along any incoming path conflicts with an invalidating access. Ambiguous same-point definition/use, incomplete phi maps, unreachable CFG points, duplicate definitions, undeclared origins and budget exhaustion fail closed.

An SSA definition kill does **not** mean that physical memory or an object was safely overwritten: place/projection aliasing, allocation generations, relocation and pointer provenance still require proof from the actual compiler.

## Typed-MIR projection

`mir_loan_census_v1::project` first validates the `mir_v1` instruction inventory, stated producer metadata and effects, then builds each instruction point and CFG edge **from the supplied typed-MIR instructions**. Separate, one-to-one `InstructionFacts` rows identify SSA origins and explicit uses. Borrow/EndBorrow loan IDs come from the MIR op rather than these rows. Writes/Drops invalidate **all issued loans** as a conservative fallback. Unknown operations, actor effects, suspension and missing borrowed-return witnesses are rejected.

This is an **inventory consistency model**, not a complete independently derived use/alias census. `InstructionFacts` can still lie or omit a non-return origin use. The `Producer` Git hash is metadata, not cryptographic authentication. Compilers must independently attest the complete source-to-MIR-to-emitted-use/alias/cancellation inventory before this can inform any authoritative decision.

Before native integration, independently prove:
1. Every source and emitted operation's loan, alias and use effects, including terminal returned borrows and all exceptional/cancellation edges; callbacks and opaque FFI fail closed.
2. SSA and dominator/phi correctness, plus condition-specific reborrowing and region/loan activation order from typed MIR, not hand-authored facts.
3. Projection-aware place conflicts, storage invalidation and relocation, exclusive/shared loan access, lifetime across `await`, and actor/domain boundaries.
4. `take!`, `copy!`, `copy!!`, `ref!`/`deref!`/`unref!` and `block {}` conformance under full-AOT, independently checked in every target backend.
5. Differential tests against existing native ownership checks and executable positive/negative guest programs (not just Rust host unit tests), with rejection on discrepancies.

## Verification

Use an exact-head root-tree-identical private Actions mirror if source-org Actions fail before allocating jobs; never transfer private-repository credentials or turn a model-pass into production certification.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --all-targets --locked --release
```

No existing V0/cyclic acceptance rules are changed by this PR.


## Audit hardening: bounded evidence and return provenance

The diagnostic bridge rejects an evidence array whose **total nested**
`use_origins` + `define_origins` + phi-edge count exceeds 100,000,
*before* the source inventory is cloned or its nested facts are processed.
It also bounds the product of all issued loans and all Write/Drop operations,
because the conservative unknown-alias strategy expands each destructive
operation into one invalidation per loan. It rejects more than 2,048
distinct loans. These limits prevent caller-created fact amplification and
are intentional fail-closed behavior, not a performance claim.

When any MIR Borrow is issued, a terminal Return must supply an origin
witness that actually appears on a MIR Borrow. A phi destination may be used
as a borrowed-return witness only when **every distinct incoming phi source**
can be transitively traced back to a MIR Borrow. Merely supplying a
different, nominally well-formed SSA origin cannot stand in for the
returned loan. This is internal consistency, not authentication of the
origin-to-owner, type, alias or reference-lifetime relationship.

An SSA phi at the function's entry point is rejected: the ordinary CFG
tracks only explicit backedges and cannot represent the separate implicit
caller's incoming edge, so an entry phi might otherwise be accepted with an
incomplete operand census. Compilers must represent such a loop header at
a non-entry block with a complete incoming-edge inventory.

These checks do not make caller-supplied `InstructionFacts` trustworthy.
A real Atto compiler still needs an independently checked typed-MIR and
emitted-op provenance/use census, with alias, cancellation, exception, and
actor boundaries. See atto-lang/atto-source.rs#271.
