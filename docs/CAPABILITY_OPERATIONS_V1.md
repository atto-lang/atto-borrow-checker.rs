# freeze!, weak!, pin!: canonical restricted-V0 event model

**Status:** ownership-event verification only, **not** native runtime certification.

This model is intentionally conservative. The compiler must present a *trusted,
typed* source-to-MIR derivation of every event and must not infer the bool
witnesses from user-authored assertions. A successful verifier result does not
prove the backend emitted all required checks or that the runtime actually
provides stable addresses, generation fencing or deep immutability.

## Deep freeze

`Op::Freeze { from, into, deep_proven }` consumes an exclusive owner and
creates a **new owner identity** whose reachable graph is marked frozen.
`deep_proven` must be derived from the transitive type/alias and interior
mutability analysis. Borrowed owners, false witnesses, reused destination IDs
and pin-then-freeze (unproven in-place transformation) fail closed. Mutating the
new owner or borrowing it mutably fails; shared loans and reads remain legal.
Moving a *handle* preserves frozen status. The old owner cannot be used after
the consuming transfer.

`Op::PublishFrozen` retains its existing independent `sync_proven` and
Sendable requirements. It is the bridge to a runtime-owned frozen shared region,
not a general `Weak<T>` or cross-tenant capability. Production code must also
enforce the region's domain and actor generation.

## Weak handles

`CreateWeak { region, weak, generation_fenced }` only accepts regions already
created by successful `PublishFrozen`. A weak ID is compiler-minted, globally
single-definition, and never a raw pointer or an owning reference. The weak
handle cannot increase the region's lifetime.

`ProbeWeak { weak, generation_fenced }` is a restricted model of an optional
generation-checked observation. **It does not return a strong owner**. The real
`weak! shared`/ `upgrade(): Option<Shared<T>>` implementation needs atomic
strong-claim acquisition and a typed success/None branch in a future MIR
profile, as well as domain checks and ABA-safe generation IDs. Do not use a V0
ProbeWeak event to justify dereferencing a stale handle, and do not silently
cast it to a `Shared<T>`.

## Pinned pointee storage

`PinStorage { owner, stable_address_proven }` records that the *pointee
allocation* is stable, not that the handle or OS thread is stationary. The
backend must independently prove stable placement and correct pin cleanup.
`RelocateStorage` fails if the allocation is pinned or borrowed.
`Move` on a pinned owner represents relocating the owning **handle** only; its
pin metadata follows the handle. `Copy` allocates distinct storage and never
inherits the old address's pin.

Pinning does **not** extend a borrow across a suspension: V0 still rejects
`Suspend` with any live loan until continuation retention, cancellation and
destructor ordering are proven in a separate profile.

## Real host reference model (not guest compiler certification)

The new src/runtime_capabilities_v1.rs is a separate, concrete Rust safety model. It uses owned graph data, Arc/Weak, atomic retirement flags, scoped RwLock read leases, and Pin<Box<T>> rather than trusting a source-written boolean witness.

- Freeze validates the entire reachable graph iteratively (cycles allowed), rejects external mutable aliases, foreign/dynamic/interior mutable nodes, unknown edges, disconnected components, duplicate IDs, and bounded resource overflows. A failed validation returns its unique owner. The frozen graph exposes only immutable views.
- A frozen region owner alone issues a read permit bound to the exact domain AND monotonically allocated region ID. Weak::upgrade is atomic and revalidates this identity and logical retirement. A weak handle never keeps allocation storage alive.
- Retire publishes the retired bit before a nonblocking try_write quiescence probe. Busy means there may still be an in-flight read; after retirement no new reads/upgrades are admitted. Dropping the owner does not block on a reader that might itself drop the owner. Arc defers physical destruction until all strong references leave.
- StablePinned<T> uses Pin<Box<T>>, exposing only Pin<&T>. Moving a handle to another stack slot or OS thread cannot move the pointee. No generalized AttoLang async pin/borrow rights follow from this model.

Tests in tests/runtime_capabilities_v1.rs cover cyclic graphs, forbidden edges, budgets, stale and wrong-region weak rights, retire/upgrade races, reentrant owner Drop and pinned address stability. These tests are authored, not yet confirmed as executed; current GitHub Actions infrastructure stops before usable logs.

Important: a production backend must authenticate the object graph and domain at source-to-IR lowering, emit compatible runtime ABI operations, independently validate the guest heap and generation, and prove exception/cancellation cleanup. Do not mark cross-backend parity solely on this model.
## Test boundaries

- `tests/ownership_capabilities_v1.rs`: consuming freeze, mutable alias
  exclusion, frozen writes, moved pinned handle, relocation denial, weak
  publication/generation guards, ID uniqueness, and staged shadow events.
- `tests/ownership_capabilities_mir_v1.rs`: MIR effect categories, inventory
  completeness and witness propagation.
- Browser source compiler: recognize prefix syntax and fail closed for
  unlowered weak/pin operations. Its immutable primitive freeze lowering does
  **not** certify graph freezing of classes, enums or nested payloads.

### Remaining backend gates

A native backend must demonstrate verified object-graph traversal and alias
invalidation, stable allocation under compaction and async I/O, atomic weak
upgrade versus final release, reclaimed-generation reuse, tenant isolation,
thread sanitizer / ASan / UBSan evidence, cancellation cleanup and trace
equivalence between compiler fast-path checks and this canonical model.
Tests on the Rust **model** alone cannot establish those runtime properties.
