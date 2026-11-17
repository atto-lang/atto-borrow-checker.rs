# Compiler-bound Mailman transfer bridge (V1 draft)

**Status: experimental Rust verifier and shared admission model.** Built on Mailman graph/lease PR #34 and ownership-bang PR #30; companion specification at [atto-spec #64](https://github.com/atto-lang/atto-spec/pull/64).

## Deliberately narrow supported profile

Only **TRANSFER** is admitted. Borrowed read/write delivery, frozen share, shallow copy and deep-copy/copy-elision are denied because this V1 does not have authenticated typed-MIR source operations that prove those paths. Do not automatically interpret an ownership-bang, Sendable boolean, user-constructible graph inventory or host-only oracle result as production source authority.

The gate validates a complete typed MIR function via the existing V1 reference verifier, then compares all ActorSendPrepare sites against a separately enumerated compiler-native source census: exact instruction IDs, source node IDs, owner IDs and nonzero ticket IDs. It requires explicit commit **and** abort paths in the submitted control-flow graph, rejects unsupported actor effects and compares claimed producer IDs. A request must match an admitted canonical ticket, whose source graph passes the separate whole-graph transfer verifier.

These two inventories are **claims from the native compiler**, not authenticated input. Their equality proves model consistency, not that an actual compiler parsed, type-checked or emitted those statements. Source metadata (compiler Git SHA, source SHA-256) is not a signature. A production backend must independently derive and bind this evidence to the precise checked-out source, typed AST/CFG, native allocator state, runtime actor incarnation and executable code.

## Shared Mailman broker

The SharedTransferBroker is a single, non-clonable Rust owner of a bounded DeliveryLedger for the entire memory domain and destination actor incarnation. Multiple Mailmen call through the **same broker**. Every prepare is gated by both individual Mailman quota and the global ledger's graph guards, ticket replay history, domain and allocation-generation protections. Only the reserving Mailman can commit/abort/finish its ticket; rejecting admission never burns that ticket or changes local counters.

This Rust model uses exclusive &mut self access to serialize calls. It does **not** implement a process-global singleton, cross-broker authority, an unforgeable capability or physical shared memory synchronization. Real runtime integration must ensure there is exactly one authoritative region registry across all Mailmen, and bind all tickets and allocation keys to authenticated actor IDs, incarnations, allocation generations, and lifetime-managed memory. A second independent SharedTransferBroker would be a separate unsafe authority if used on the same physical memory domain. Use native same-pass checking in each compiler; do not route production statement checking into this oracle.

## Tested negative cases

- Source census omitted, duplicated, spoofed, wrong owner, wrong source node, invalid producer or unsupported version
- Typed MIR missing instruction, wrong effect, exceptional/rollback path omitted, unmodeled actor effect
- Foreign heap transfer, mutable nested alias and nontransfer mode masquerading as move
- Two Mailmen racing for the same transitive graph; committed consumed graph cannot be reused until a genuinely new allocation generation
- Wrong Mailman settling another ticket; double commit, abort-after-commit, replayed ticket
- Local vs global mailbox exhaustion, failed admission not altering ownership or counters
- Wrong actor incarnation, wrong runtime domain, duplicate Mailman IDs, zero capacities

## Required later work before merge to production

1. Add trusted native-compiler produced typed-MIR + independent source-census attestations to Java, LLVM, .NET, WASM, Forge, and other frontends.
2. Replace claimed graph layout/escape metadata with allocator-backed region ownership and generation minting.
3. Implement one runtime-global capability authority per shared memory domain, with safe synchronization across Mailmen and supervisor STOP/cancellation.
4. Prove actual sender invalidation and fail-atomic mailbox handoff under sanitizers and actor crashes.
5. Expand typed-MIR contracts for scoped read/write loans, frozen shares, deep copy and copy!! elision without user-authored magic booleans.
6. Execute genuine AttoLang guest/AOT positive and negative tests, not merely Rust model tests.

**CI:** cargo fmt --all -- --check; cargo clippy --all-targets --locked -- -D warnings; cargo test --all-targets --locked; cargo test --all-targets --locked --release. No PASS claim without actual executed exact-head job evidence.
