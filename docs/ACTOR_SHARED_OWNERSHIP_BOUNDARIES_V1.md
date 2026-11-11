# AttoLang actor-to-actor ownership boundaries — canonical V0 extension

**Implementation status:** canonical Rust verifier and model tests only. This does
not implement guest source lowering, physical actor-local allocation, runtime
shared-region locking, or independent backend parity. All new operations require
an independently validated typed-MIR instruction inventory before a backend may
use them to authorize code generation.

## Storage and ownership must remain separate

Every SHARED, PRIVATE and UNTRUSTED actor owns an independent logical
heap/arena and generation-fenced lifetime, even if trusted SHARED actors use
the same carrier pool and process address space. A per-actor logical arena
is not an OS process, Java GC isolate or physical memory-security boundary.

Only trusted SHARED actors may obtain explicit shared-region capabilities.
An actor's `self` and sealed private state cannot be promoted by virtue of
supervisor lineage or by merely possessing a pointer. ActorRef, FFI pointers,
tenant and source-level numeric region identities are **not** shared-memory
authority. Compile-time checked ownership and runtime-issued region/loan
capabilities are both mandatory.

## Closed ownership operations added to V0

| Operation | Required static proof | Sender state after success |
| --- | --- | --- |
| `ActorSendMove { owner }` | Live owner, transitive Send, no live borrows | Consumed; recipient receives one owner |
| `ActorSendCopy { owner }` | Live owner, Copy **and** Send, no exclusive loan | Retained; recipient receives an independent value |
| `PublishFrozen { owner, region, sync_proven }` | Live owner, Send, compiler-derived deep immutable Sync proof, no live borrows | Consumed into one runtime-owned frozen region |
| `PromoteGuarded { owner, region }` | Live owner, Send, no live borrows | Consumed into one runtime-owned synchronized region |

A numeric region ID here is only a globally fresh compiler IR identity; it is
never a runtime capability or proof that the memory was allocated in a
shareable domain. Zero IDs and repeated IDs, including mutually exclusive CFG
branches, are rejected. All four operations must be inventoried in MIR V1 as
`ActorBoundary` effects, not as ordinary local ownership instructions.
The existing `ActorHopBorrow` still fails closed.

`PublishFrozen` relies on the frontend to prove deep freezing and Sync.
The V0 verifier cannot authenticate that the passed `sync_proven` bit came
from real transitive type/layout evidence; a backend must not treat this
boolean as a user-assignable flag or a runtime freeze operation. Similarly,
`PromoteGuarded` is **only** a one-owner handoff preflight and grants no
read/write access or ability to cast an actor private pointer to shared
storage. Runtime admission must inspect exact source allocation-domain
provenance, trust, generation, permissions and physical loans.

## Runtime obligations not discharged by this patch

- **Transactional mailbox admission:** failed send must leave the sender
  owner usable, with no recipient owner. A successful move invalidates all
  sender aliases and permits exactly one recipient owner.
- **Immutable sharing:** freeze deeply or move into already immutable native
  storage. Publish with safe ordering, issue generation-fenced read leases,
  retain physical backing while readers/callbacks exist, deny all mutable
  aliases, and charge quotas.
- **Guarded sharing:** runtime becomes the *only* semantic owner. Give actors
  revocable non-owning typed handles. Enforce FIFO/fair N-reader/one-writer
  logical admission; never park carrier threads or allow the previous owner
  to bypass the guard. A successful lock admission is not permission to keep
  a raw pointer after the guarded scope ends.
- **STOP and hot upgrade:** generation changes revoke logical access. Retire,
  scrub and refund only after physical quiescence; a failed revocation
  quarantines instead of releasing live backing. No guard escapes across
  await, select, Task, callback, cancellation or migration.
- **No sealed-state bypass:** a child actor, parent supervisor, unrelated
  trusted actor or untrusted tenant cannot derive a shared-region capability
  from sealed actor fields, private/tenant memory or a native pointer.

## Acceptance gates for integration

1. Java `OwnershipChecker` / typed MIR builder must emit the exact closed
   operations *inside its existing ownership pass*, preserving complete
   source/instruction census and denying unknown effects.
2. Equivalent compiler-specific rules and negative diagnostics must execute
   before LLVM IR, CIL, Wasm or Forge code generation.
3. Run the same canonical `.atto` positive and negative programs across
   at least Java/GraalVM, LLVM, .NET NativeAOT, Wasm and Forge; include failed
   send rollback, no alias after promotion, mutable/immutable conflicts,
   supervisor non-ownership, cross-tenant denial, STOP and hot upgrade.
4. Require actual compiled guest runs, resource reclamation/race tests,
   exact PR head/tree and nonzero GitHub Actions job steps. A source-free
   Rust model test or zero-step workflow does not certify backend behavior.

The bounded V0 verifier still rejects cyclic CFGs, unknown effects, pinning
across suspension and incomplete cleanup. No automatic memory-domain
placement, borrow-checker integration or guest runtime shared-heap
authorization is claimed by this PR.
