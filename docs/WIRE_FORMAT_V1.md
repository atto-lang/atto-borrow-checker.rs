# `atto-borrow-wire-v1`: backend interchange format

This is the JSON that backends write and `atto-borrow-conform` reads. The
decoder (`src/wire_v1.rs`) is strict, and any of the following rejects the
whole document:

- unknown, missing or duplicate keys;
- negative or fractional numbers;
- an id that overflows `u32`;
- nesting deeper than 64, or a document over 16 MiB.

Files with many records are JSON Lines: one object per line, blank lines
ignored. Golden examples live in [`conformance/examples/`](../conformance/examples/).

## Operations

Each op is an object whose `op` field names a canonical `Op` variant. Field
names are camelCase. Ids are compiler-local `u32` values, and an id of 0
is invalid.

| `op` | fields |
|---|---|
| `Init` | `owner`, `copy`, `send` (booleans: type-checker facts, never guesses) |
| `Read`, `Write`, `Drop`, `RelocateStorage`, `TaskCaptureCopy`, `TaskCaptureMove`, `ActorHopBorrow`, `ActorSendMove`, `ActorSendCopy` | `owner` |
| `Borrow` | `owner`, `loan`, `kind` (`Shared` \| `Mutable`) |
| `WriteThrough` | `owner`, `loan` |
| `EndBorrow` | `loan` |
| `Move`, `Copy` | `from`, `into` (`into` is a fresh owner id) |
| `DeepCopy` | `from`, `into`, `graphProven` |
| `Freeze` | `from`, `into`, `deepProven` |
| `PinStorage` | `owner`, `stableAddressProven` |
| `CreateWeak` | `region`, `weak`, `generationFenced` |
| `ProbeWeak` | `weak`, `generationFenced` |
| `ActorSendPrepare` | `owner`, `ticket` |
| `ActorSendCommit`, `ActorSendAbort` | `ticket` |
| `PublishFrozen` | `owner`, `region`, `syncProven` |
| `PromoteGuarded` | `owner`, `region` |
| `Suspend`, `Return` | none |
| `UnknownEffect` | `kind` (free text). Use this for anything the backend cannot represent faithfully (FFI, unwind, conditional drop, ...). It always rejects with `E_MIR_UNSUPPORTED_EFFECT`. **Never** drop such an op or turn it into a no-op. |

Each terminal block ends with `Return`. Owners are canonical alias roots; a
field projection must resolve to its root unless disjointness is proven.

## Graph (L1 corpus and L1 results)

```json
{"entry":0,"blocks":[{"id":0,"ops":[{"op":"Init","owner":1,"copy":false,"send":false},{"op":"Return"}],"successors":[]}]}
```

Corpus file: `{"schema":"atto-borrow-graph-cases-v1","cases":[{"id","category","expected":"accept"|"reject","diagnostic":code|null,"graph"}]}`.

L1 result line (one per case):

```json
{"schema":"atto-borrow-graph-results-v1","backend":"llvm","case":"C03","verdict":"reject","code":"E_USE_AFTER_MOVE_OR_DROP"}
```

`verdict` is `accept`, `reject` (with the **exact** canonical code) or
`unsupported` (with an optional `reason`). Optional keys: `message`, `note`.

## MIR function (`atto-borrow-mir-v1`)

```json
{"version":"atto-borrow-mir-v1",
 "producer":{"compilerGitSha":"<40 hex>","sourceSha256":"<64 hex>","sourceUnitId":1,"functionId":7},
 "entry":0,
 "expectedInstructionIds":[1,2,3],
 "blocks":[{"id":0,"instructions":[
   {"instructionId":1,"sourceNodeId":41,"effect":"Ownership","op":{"op":"Init","owner":1,"copy":false,"send":false}},
   {"instructionId":2,"sourceNodeId":42,"effect":"Ownership","op":{"op":"Read","owner":1}},
   {"instructionId":3,"sourceNodeId":43,"effect":"Control","op":{"op":"Return"}}],
  "successors":[]}]}
```

- `effect` must match the op (`mir_v1::expected_effect`):
  - `Suspension` for `Suspend`;
  - `ActorBoundary` for every `Actor*` op, `PublishFrozen` and `PromoteGuarded`;
  - `Control` for `Return`;
  - `Ownership` for everything else.
  - An `UnknownEffect` op must be tagged `Unsupported`.
- `expectedInstructionIds` must come from an **independent census** of the
  backend's typed IR. It must not be copied from the instruction list, because
  set equality between the census and the instructions is the completeness
  check.
- `sourceNodeId` is the backend's AST/IR node id. It lets a disagreement be
  traced back to the source.

Check one function with `atto-borrow-conform verify-mir fn.json`.

## Backend report (L3), one line per compiled function

```json
{"schema":"atto-borrow-backend-report-v1",
 "backend":"java", "compilerGitSha":"<40 hex>",
 "sourcePath":"fixtures/borrow-checker-v1/fail/take.atto", "case":"BCV1-010",
 "function":"main",
 "local":{"verdict":"reject","code":"E_MOVED","message":"use of moved value 'first'"},
 "mir":{ ...atto-borrow-mir-v1... }}
```

- `backend` is one of `java llvm net wasm forge cranelift js rs hdl`.
- `case` is optional: a BCV1 id, or `null`.
- `local.code` is required on reject and must be a registry code (canonical
  or family); non-ownership rejects such as `E_SYNTAX` are allowed too.
- Give exactly one of `mir` and `mirUnavailable` (a reason string).
- Optional key: `note`.

Run `atto-borrow-conform cross-check report.jsonl [--allow-stricter] [--require-mir]`.
The output is JSON Lines, one classified line per record, ending with a
`summary` line. Exit status is 0 when conformant, 1 when not, and 2 on an
input error.
