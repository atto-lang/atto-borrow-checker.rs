# Mailman graph-uniqueness and lease oracle (draft V1)

**Experimental Rust model only.** Stacked on ownership-bang PR #30. Companion contract: [atto-spec #64](https://github.com/atto-lang/atto-spec/pull/64). This is NOT a compiled AttoLang guest, a runtime Mailman, a byte-copy implementation, a real cross-actor lease, or physical memory isolation.

The native compiler still performs ownership checking **in the same semantic/MIR pass**. This Rust reference module checks that a submitted whole-graph allocation inventory is closed and that an operation does not violate represented owner/loan constraints. The independently enumerated expected-reachable census must be bound to compiler AST/type/place data by a trusted producer; neither the census nor mutable/frozen/Sendable fields are cryptographically authenticated by this module.

## Source and physical semantics

- The shallow copy operator is copy!; deep graph copying is copy!!. The source copy!! requires a DeepCopyable + Sendable proof, no implicit conversion from illegal shallow aliases. This module checks eligibility only; it does **not** clone objects.
- TRANFER: require all mutable descendants exclusive to source, no escaped aliases, no outstanding loans and compatible domains. On commit, the sender must be invalidated by the real compiler/runtime transaction.
- DEEP_COPY: require transitive DeepCopyable; permits different heap domains. This model selects actual copy unless an independently proven unobservable source (including identity/hooks/destructor behavior), total graph uniqueness and same domain support an elided physical copy.
- READ_LEASE: permits multiple readers only under a proven bounded lifetime, no writer and no escaped mutable aliases.
- WRITE_LEASE: requires exclusive region-wide authority and no reader or writer.
- FROZEN_SHARE: all reachable allocations must be proven deeply frozen and Sync, with Sendable.
- Cross-domain physical zero-copy, forged actor generations, zero/replayed tickets, unknown edges and missing graph census fail closed.

## Model ledger and remaining critical runtime work

The bounded model ledger demonstrates one-slot mailbox escrow, single-use ticket settlement and lease-use quiescence. It does not maintain live operating-system or VM-level memory guards, issue unforgeable envelopes, authenticate compiler output, or implement scheduler STOP/cancellation. Production must bind every region guard and ticket to actor incarnation, memory domain, and allocation generation; escrow publication and rollback must be linearizable against concurrent Mailmen. Before claiming guest execution, implement physical/managed domains and test actual concurrent actor transfers/leases, heap isolation, STOP cancellation and resource lifetime under sanitizers.

## Test evidence

Run:
    cargo fmt --all -- --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo test --all-targets --locked
    cargo test --all-targets --locked --release

These are Rust model tests only. CI PASS requires exact source tree/blob verification and **executed steps** on a funded runner; zero-step GitHub Actions failures do not provide pass/fail evidence about code.

## Follow-up implementation gates

1. Authenticate typed-MIR/source site census, graph completeness and regional ownership in each native compiler pass.
2. Add lifetime/escape analysis across control-flow joins, unwind, defer/recover, suspended/pinned tasks and FFI.
3. Make runtime envelopes non-forgeable and generation/ABA fenced. Commit and abort grants exactly once.
4. Implement AOT deep graph cloning with cyclic/repeated alias memoization and transactional publish.
5. Run real independent actor guest tests per backend before claiming zero-copy or lease semantics.
