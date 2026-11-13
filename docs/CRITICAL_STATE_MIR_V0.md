# Critical actor-state lexical MIR V0 (static proof only)

**Status: DRAFT / unexecuted in CI.** This adds a conservative Rust-only
typed-MIR event model. It does not implement or authenticate an Atto compiler
frontend, runtime lock, `ref32` actor heap, actor stack, mailbox or guest code.

## Compiler-side contract

- A trusted frontend supplies nonzero actor-state IDs derived from a sealed
  state place and unique lexical critical-scope IDs derived from typed MIR.
- `CriticalReadEnter` admits only `CriticalReadAccess` for that same state/scope.
  `CriticalWriteEnter` admits reads and writes for that state/scope.
  `CriticalExit` consumes the lexical scope exactly once.
- `CriticalCopyI64 { state, scope, into }` records only a compiler-proven
  detached `i64` state value, never a pointer or borrowed view. It creates a
  fresh local SSA owner within the scope. A nonparking mailbox send of this
  independent value is permitted only **after** `CriticalExit`. A compiler
  admitting inline `self.send(s.field)` must lower that expression into copy,
  close scope, then send; it must NOT issue a mailbox call with the loan live.
  The Rust event does not itself read runtime state or authenticate source types.
- This deliberately restrictive V0 admits **one active lexical critical scope
  per path**. Nested/reentrant callbacks, including nested readers, fail closed
  until a separate proven reentrancy/ordering policy exists. This does **not**
  prevent independent actors from holding concurrent read permits at runtime.
- `Suspend`, generic `Borrow` (whose field provenance is unproved here),
  task captures, actor hops, send prepare/commit/abort, immutable publication
  and guarded promotion fail while a critical callback is active.
- Entering a critical scope also fails while **any ordinary loan** or **mailbox
  send escrow** is outstanding. V0 does not authenticate disjointness between
  an arbitrary ordinary loan and sealed actor state, nor can it establish
  completed ownership transfer before send commit/abort. Both obligations
  must settle **before** critical entry. This conservative rule can later be
  relaxed only through authenticated, compiler-owned nonalias provenance.
- A `Return` with a live scope, read-only mutation, wrong state/scope, duplicated
  scope definition, unbalanced exit, and incompatible control-flow joins reject.
- Every operation uses `Effect::CriticalRegion` in typed MIR; wrong effect
  classifications reject before canonical verification. Invalid MIR or a later
  unsafe operation produces no successful shadow event publication.

## Explicitly not proved

The model does **not** prove that input state IDs or the instruction census
are genuine; a compiler must authenticate source, type, effect and field
provenance, rejecting calls/FFI/IO that it cannot classify. It also does not
acquire an actual reader/writer permit, enforce fair scheduling, prevent
cross-tenant grants, protect native pointers, or wait for physical STOP
quiescence. The runtime must independently enforce one writer or compatible
readers, generation-fenced retirement and actor-owned heap domains.

A production claim requires the **same** `.atto` positive/negative fixtures
executing at pinned compiler/runtime heads under Java/GraalVM, LLVM O0/O2,
and .NET NativeAOT, plus independent Rust tests. Any unavailable backend
must remain **NOT_EXECUTED** and all unsupported effects fail closed.

See the [language target](https://github.com/ores-truffle-oreslang/attolang-language-spec.md/blob/main/spec/22-concurrency-and-shared-ownership.md).
The separate actor-state `GuardQueue`/physical `RwLock` proposals in PRs
#13/#14/#16 are runtime **models**, not implicit prerequisites for or
evidence of native compiled guest execution.
