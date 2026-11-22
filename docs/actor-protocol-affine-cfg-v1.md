# Actor protocol affine CFG / stream lease oracle V1

Status: **DRAFT — host-side Rust MIR model, not compiled guest semantics**.

This module extends the canonical Rust borrow-checker crate through
`pub mod actor_protocol_v1`, next to the existing resource `typestate_v1`
checker. It does not reclassify a protocol handle as an ordinary copyable
resource, grant mailbox authority, or authenticate stream terminal events.

## Checked protocol operations

| Operation | Proof obligation |
| --- | --- |
| Init(place, protocol) | Compiler-authenticated actor-spawn source; initial state only, entry block only |
| Take(from, into) | Consume source, preserve sole owner at destination |
| Copy | Always reject (actor protocol handles are affine) |
| Borrow/EndBorrow | Reject overlapping exclusive loans, live loans across suspension, and loans on consuming operations |
| Begin(from, lease, message, payload, mode, response) | Message legal in every possible state; payload/cardinality/type match; move source authority into unique session |
| MoveLease | Transfer sole session owner; invalidate old lease |
| AwaitUnary | Four distinct exits in order: success, error, timeout, cancel |
| AwaitStream | Five distinct exits in order: item, EOF, error, timeout, cancel |
| CancelLease | Retire local lease; mint no successor authority |
| ReturnHandle | Consume the only live owner into caller return (separate return type proof required) |
| DisposeTerminal | Require definitively terminal state; release once |
| Return | No unmatched loans, leases, or possibly live handles |

**Item** retains its lease, without a successor state. **EOF** retires the
lease and can create one successor owner. A unary success behaves like EOF;
error, timeout and cancellation retire the local lease without creating any
successor authority. All five edges must come from authenticated runtime and
compiler lowering; a branch label alone is not an authenticated EOF receipt.

Branch joins must preserve the union of possible states, cannot convert
`possibly moved` to `definitely disposed`, and reject divergent live loans
or lease identities. The graph must be closed, reachable and acyclic, with
bounded nodes, edges, operations, handle places, loan IDs and lease IDs.

## Two-language equivalence target

Java: `atto-source.java#1743` —
`ActorProtocolAffineCfgV1` plus `ActorProtocolSourceCfgV1`.
Rust: `atto-borrow-checker.rs#50` — `actor_protocol_v1`.

| Scenario | Expected |
| --- | --- |
| unary success | successor handle issued once |
| unary error/cancel/timeout | no successor handle |
| stream item | lease remains live, no successor |
| stream EOF | successor issued once |
| stream failure/timeout/cancel | no successor |
| take/use old handle | E_PROTOCOL_HANDLE_NOT_LIVE |
| copy | E_PROTOCOL_AFFINE_COPY |
| await with live loan | E_PROTOCOL_LOAN_ACROSS_AWAIT |
| unbalanced stream lease across branch | E_PROTOCOL_LEASE_JOIN |
| maybe-moved handle silently escapes | E_PROTOCOL_HANDLE_ESCAPE |
| invalid unary/stream mode | E_PROTOCOL_RESPONSE_MODE |
| invalid request payload | E_PROTOCOL_MESSAGE_PAYLOAD |
| loop/unmatched exit | E_PROTOCOL_CFG_CYCLE / E_PROTOCOL_IMPLICIT_EXIT |

These are expected **model invariants**, not cross-backend executed parity
receipts. The Java adapter handles a restricted parseable .atto source subset
including take!, typed request cancellation, branch joins and returns.
The Rust compiler-side source-to-CFG extractor is **not wired** in this PR.
Source token/AST trust, aggregate ownership, exceptions, runtime stream item
and EOF authenticity, actor generation fencing and native AOT are not proven.

## CI and security

The dedicated exact-head workflow compiles, lints and tests this Rust
model in debug/release, verifying the checked-out commit and both Git blobs.
No successful test receipt exists until GitHub Actions actually executes
nonzero job steps. Do not treat a runner-admission failure as a test failure
or a pass.

The repository is private. Any cross-organization CI carrier must meet the
repo's applicable reviewed export/security policy; do not assume that
token-free copying alone authorizes an export. Source-org trusted ephemeral
runs have separate explicit independent-review and protection requirements.
