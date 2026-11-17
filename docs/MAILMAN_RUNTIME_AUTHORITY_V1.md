# Runtime Mailman transfer capability authority — experimental V1

**PR stack:** PR #30 (ownership-bang model) → #34 (graph/lease oracle) → #35 (typed-MIR source census and shared broker) → this PR.

## Supported mode

This is a safe-Rust, process-local state machine with mutex-serialized ownership bookkeeping and non-cloneable, non-user-constructible transfer permit/envelope types. It is NOT a physical memory-moving actor runtime, production AttoLang compiler authorization, cross-process capability authentication, or an implementation of borrower read/write leases.

Only same-domain exclusive TRANSFER is supported. Deep copying, scoped borrowing, frozen sharing and AOT copy-elision remain out of scope.

### State and authority boundaries

- A bounded process-global strong domain directory keeps one authoritative Arc/Mutex state per memory domain. Multiple handles and Mailmen converge on the same registry. Strong retention intentionally preserves quarantined grants and consumed ticket history until process termination; dropping all application handles does not reset ownership. A later production implementation must define explicit global shutdown and safe reclamation.
- A **trusted host allocator adapter** must register live allocations with local allocation ID, reuse generation, actor identity, actor generation and checked owner slot. Batch registration and destruction retirement reject duplicate live slots, stale epochs and partial mutations. The compiler proof never creates a live allocation by itself.
- Prepare matches every graph allocation against the registered live owner and epoch. Then the shared Mailman broker verifies graph conflicts and both mailbox quotas, under the same domain mutex. A rejected admission retains sender ownership.
- The returned PendingTransfer cannot be cloned or publicly constructed. A successful commit moves it to a ReceivedTransfer; a pending permit that is dropped or explicitly aborted returns ownership from escrow. On a poisoned lock, escrow is retained rather than released unsafely.
- Commit consumes sender ownership in the broker and places allocations in transit, accessible to neither actor. Only a recipient's explicit accept into a nonzero owner slot binds them to the receiving actor and releases mailbox occupancy.
- **Abandoned committed envelopes remain quarantined.** Dropping a ReceivedTransfer does not restore sender ownership or assume memory destruction. Supervisor recovery must separately prove destruction/reclamation.

### Proof and security limitations

The native frontend still supplies a source-site census, typed-MIR inventory and allocation graph. All such metadata and compiler/source hashes are claimed rather than independently authenticated. The trusted host registration methods are privileged runtime adapter methods, NOT APIs permitted to untrusted AttoLang source or guest FFI. These tests do not demonstrate physical heap moves or protection from unmanaged pointers.

The Rust mutex serializes metadata decisions; it cannot enforce arbitrary foreign-language memory access. No cross-process authority, cross-domain physical zero-copy, or backend parity is implied.

## Exact-head executable Rust gates

Use the token-free private Actions carrier to run:

- cargo fmt --all -- --check
- cargo clippy --all-targets --locked -- -D warnings
- cargo test --all-targets --locked
- cargo test --all-targets --locked --release

Adversarial host-model tests exercise simultaneous Mailmen, lost pending and committed envelopes, allocation ABA, nested graph omission, wrong actor epochs, attempted owner-slot reuse, duplicate grants, independent authority handles, and failure-atomic backpressure.

## Follow-up implementation gates

1. Replace privileged registration simulation with allocator-issued handles authenticated by the native runtime.
2. Bind verified MIR and source inventory to loaded AOT guest code and actor identity.
3. Implement physical same-domain heap ownership handoff with mailbox publication, supervisor STOP, panic/unwind and cancellation safety.
4. Define verified destruction and recovery of quarantined committed envelopes before permitting memory reclamation.
5. Add compiler-proven read/write leases, pinned suspension, immutable shares, and independent deep copy with cycle/alias preservation.
6. Run executable AttoLang guests and sanitizers per backend before claiming production behavior.
