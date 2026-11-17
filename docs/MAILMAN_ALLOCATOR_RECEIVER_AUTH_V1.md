# Runtime allocator and receiver capability hardening (V1)

Stacked on PR #38 (runtime-local allocation authority), #35 (compiler/MIR census), #34 (graph proof), and #30 (typed borrow checker). This is a **Rust security boundary and host-model change**, not compiled AttoLang guest execution.

## Security changes

- DomainAuthority::open, register_allocator_owned, retire_destroyed, prepare, and receiver_session are crate-private. External Rust crates and guest adapters can no longer mint allocator ownership records, register invented epochs, retire memory or mint transfer permits through the public library surface. This is Rust visibility, not cryptographic authentication or a real trusted host ABI.
- Trusted scheduler code creates a private, non-cloneable ReceiverSession bound to the destination actor ID, incarnation and exact authority Arc. A mismatched actor is rejected at session creation.
- Committed transfer acceptance requires that session. A session from a different domain is rejected even with a matching actor ID and generation. Duplicate acceptance remains forbidden.
- Commit compares both the source actor and original owner slot against registered allocation records, not actor identity alone.
- Previous 12 external integration tests are migrated to crate-internal unit tests, with four adversarial additions. A compile-fail Rustdoc test exercises the private constructor boundary.
- Any unauthorized acceptance leaves committed ownership in quarantine until legitimate acceptance; it does not restore sender ownership.

## Trust boundaries still unresolved

The crate-internal adapter currently receives allocator generations and actor context as trusted simulation inputs. No physical allocator verifies actual heap memory or destructor completion. Native compiler and runtime integration must derive those identities from current execution context without exposing their construction to Atto guest code, FFI or callbacks.

Also pending: physical sender pointer invalidation and real mailbox publication atomicity; supervisor recovery and destructor-proof reclamation; protected cross-actor read/write leases; AOT graph deep copying; executable .atto guest/backends parity. The strong process-local directory persists until shutdown, by design.

## Exact-source validation

Run cargo fmt, clippy -D warnings, debug and release cargo tests, and Rustdoc compile-fail tests on a funded private Actions carrier. Mirror the full private Git tree and verify changed source blobs and the complete root Git tree SHA before running. No cross-organization checkout secrets. Keep this PR draft pending independent security review and real compiler/runtime execution.
