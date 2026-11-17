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
