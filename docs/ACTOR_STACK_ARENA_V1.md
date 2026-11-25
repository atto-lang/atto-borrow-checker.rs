# Actor-owned stack frame arena V1 (trusted Rust reference)

This module is a bounded **physical byte storage model** for actor-owned stack
frames. It is not a running AttoLang guest, a native machine stack, a compiler
source-to-MIR guarantee, a runtime scheduler, or an authorization system.
A u32 offset identifies one span **within** the owning actor's arena; it is
never widened to a host pointer.

## Safety contract

- The host creates one arena per actor incarnation. The identity and generation
  supplied to the arena **must be authenticated** by the actual supervisor.
  A process-local instance counter blocks stale handle reuse across duplicate
  constructions, but cannot prove supervisor authority or prevent persisted
  generation reuse after a process restart.
- The arena's entire byte allocation is dedicated to one instance. Offset 0 is
  reserved. Bounds arithmetic is checked, and alignment is relative to the
  arena offset, **not a guarantee of machine pointer alignment**.
- Default limits: 64 KiB storage and 64 live frames. A smaller budget may be
  configured for tests. The metadata vector is preallocated during creation,
  so a frame push does not perform a host allocator call.
- A handle contains a process-unique arena-instance ID, actor ID, generation,
  monotonically assigned frame serial, offset, and length; all fields are private.
  Every access rechecks the complete handle against an active record. A second
  arena with the *same* claimed actor and generation cannot resurrect an old
  handle, even when the offset and frame serial happen to match. Exhausting the
  process instance counter fails closed.
- Writes require an exclusive trusted Rust borrow of the arena. The closure
  interface does not return a safe Rust frame borrow. There is no unsynchronized
  guest memory sharing or cross-actor pointer export.
- Debug output redacts the backing frame contents and active handles to avoid
  exposing potentially sensitive actor-local data through routine diagnostics.
- Destruction is LIFO and clears retired frame bytes and padding on the push
  path's live arena. STOP/retirement invalidates all handles and clears the
  backing buffer, but the reference does **not** claim secure erasure from
  physical memory against compiler optimization, snapshots or DMA.
- Exceeding the capacity, depth or serial budget permanently faults this
  actor arena. It cannot be resumed or popped while faulted. Its supervisor
  must retire the incarnation, prove all physical callbacks quiescent, and
  construct a new arena. Other actors' arena instances remain independent.
- Invalid frame sizes/alignments fail without admitting a partial frame.
  Only positive power-of-two alignments through 4096 are supported.
- A stale or same-generation retirement attempt fails. A retired arena
  cannot be restarted, even with a newer generation.

## What remains unproved

1. A real compiler-generated stack layout, continuations, function calls,
   return addresses, heap/stack alias analysis, per-actor stack probes and
   signal-safe overflow handling.
2. Source-to-MIR provenance and integration with Java, LLVM or .NET native
   lowering. A native guest must not synthesize ref32 authority from arbitrary
   values merely because this Rust model accepts the handle.
3. Scheduler/carrier migration, cancellation during suspension, physical
   generation quiescence, supervisor restart fences and stack lifetime after
   an uncaught guest fault.
4. Native process/ASan/UBSan tests, nonblocking network and disk I/O, and
   broker integration. The reference does not allocate separate OS stacks.
5. Concurrent reader/writer shared-region admission. This is a *private*
   stack arena, not a shared heap. That separate feature requires an explicit
   runtime capability and a proven reader/writer loan.

## Tests and evidence

Run with the exact PR head and a Rust toolchain:

    cargo fmt --all -- --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo test --all-targets --locked
    cargo test --all-targets --locked --release

Integration tests cover actor identity collisions, stale generations,
LIFO frame retirement, offset reuse, duplicate-instance stale handles,
redacted Debug output, physically cleared slots, alignment
rejections, zero offsets, budget/depth faults and sibling survival.
These are Rust host-side tests, **not** Atto guest certification.

Follow-on gate: run the same source-pinned .atto actor test on
Java/GraalVM, LLVM O0 and O2, and .NET NativeAOT with exact compiler head/tree,
actual executed steps, negative mutation proofs, independently reviewed
runtime policies and no substituted host-only implementation.