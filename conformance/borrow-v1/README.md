# Atto borrow conformance protocol v1

**Status: initial source-free differential contract. Not a compiler implementation, provenance attestation, or guest certification.**

## Architecture and ownership of responsibilities

`atto-borrow-checker.rs` owns the canonical reference semantics, versioned case corpus, deterministic diagnostic taxonomy, differential comparison tooling, and eventual independent typed-MIR and emitted-code census checks. Each `atto-source.*` compiler owns its independent *in-pass* borrow checker, constructed from its type-checked CFG/MIR, and must reject unsafe source before lowering or emitting code. Normal compilation MUST NOT require spawning Rust or re-parsing Atto source in a second process.

The current `cases.tsv` pins all 22 C01–C22 fixtures in `tests/nine_toolchain_contract_v1.rs`: 21 directly represented by V0, and C20 represented by the stricter MIR envelope. The existing Rust test remains the executable semantic oracle. This file is an **index/expected-outcome catalog**, not a portable typed-MIR serializer and not `.atto` guest source. It cannot yet prove backend compatibility or compiler native verification.

The profile `mir-v0-acyclic` is intentionally conservative (e.g. loops rejected by V0); `mir-v1-envelope` covers the unknown-effect rejection. Field disjointness and point-sensitive/NLL are separate future profiles, not grounds for silently relaxing this profile. The Rust crate's field-sensitive cyclic model, MIR V1 and outstanding PRs must be reconciled before claiming a common more permissive profile.

## Report wire format and comparator

Each independently executed implementation must emit one UTF-8 JSON document with the exact structure below. `implementation_sha` is the commit SHA claimed by its producer; an external trusted CI step **must verify** it against the actual checkout, or the report is untrusted. `corpus_sha256` is SHA-256 of the **exact bytes** of `cases.tsv`, not a normalized JSON or text reserialization. A report must include every case exactly once, even on rejection, and must never mark unsupported, unrun, or skipped cases as passed.

```json
{
  "schema": "atto-borrow-differential-report/v1",
  "implementation": "atto-source.rs",
  "implementation_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "corpus_sha256": "<64 lowercase hex from sha256sum cases.tsv>",
  "results": [
    {"case_id": "C01", "profile": "mir-v0-acyclic", "decision": "allow", "diagnostic": null},
    {"case_id": "C03", "profile": "mir-v0-acyclic", "decision": "reject", "diagnostic": "E_USE_AFTER_MOVE_OR_DROP"}
  ]
}
```

The abbreviated `results` array above is for illustration and **will fail** strict validation; a real report must contain all 22 rows. `canonical` is the reserved reference implementation name; backend names are the exact `atto-source.*` repository names. Only `allow`/`reject` outcomes are legal. All expected error categories must match. The script rejects unknown/duplicate keys, duplicate case IDs, stale digests, missing reports, skipped cases, extra cases, unexpected backends, and case/profile drift.

```sh
python3 -m unittest discover -s conformance/borrow-v1 -p 'test_*.py' -v
python3 conformance/borrow-v1/compare.py \
  --require canonical --require atto-source.rs \
  --report artifacts/canonical.json --report artifacts/atto-source.rs.json
```

**Never publish a green `compare.py` result as proof that the independent compiler ran.** It only compares submitted source-free reports with the versioned fixture catalog. Even perfectly matching reports can both omit an actual source effect. CI must execute the real compiler and the canonical Rust checker, verify the exact input source/tree and toolchain SHA, and bind produced native diagnostics to actual compiler process exit status, source spans and MIR/emitted-code inventories.

## Two-tier invocation policy

The full CI/CD architecture is specified in [CI_DEEP_VERIFICATION.md](CI_DEEP_VERIFICATION.md). Normal builds run the compiler's **own** borrow checker in its ordinary type/CFG pass. Once real authenticated typed-MIR producers are integrated, CI/CD runs the Rust canonical verifier in a deeper strict mode across full exported control-flow graphs, compares both checkers, validates source/MIR/emission inventories and executes actual guest tests. CI has a larger analysis budget than an incremental developer build, but cannot claim deep feature proof before the corresponding Rust model and compiler adapter are implemented and tested. Missing/unsupported checks fail closed. Current V0 is not a whole-program or complete lifetime verifier.

## Conformance phases and release gates

| Phase | Required proof | Current state |
| --- | --- | --- |
| P0 — Reference | Golden C01–C22 cases and Rust oracle enforce the same outcome; comparator rejects forged/missing/skipped reports. | Corpus, protocol and host-only tests added; Rust synchronization assertion required. |
| P1 — Typed IR | Common versioned function, place/field path, LoanId/WriteId, Copy/Send/Share provenance, all CFG edges, NLL/last-use, cleanup, exceptional/cancellation, suspend and actor ownership effects; independently enumerated expected vs observed event inventory. | Not implemented by this PR. |
| P2 — Independent adapters | Every compiler checks in its normal pass, exports the **actual** checked typed IR and stable diagnostic code; canonical Rust independently evaluates it in strict CI. Decision and diagnostics must agree; disagreement **fails closed**. | Pending per-backend adapters and executable producer. |
| P3 — Guest | Compile identical `.atto` positive/negative programs with each backend at pinned commits; accepted programs **execute** natively/browser/AOT as applicable; rejected programs emit no executable. Verify IR-to-emission completeness, unwind/drop and actor cancellation. | No certification. |
| P4 — Production | Benchmark same-pass fast path vs strict dual check; establish sound per-feature profiles, incremental invalidation and exact-head CI receipts. | Not enabled. |

**Required backend inventory:** `atto-source.rs`, `.java`, `.llvm`, `.net`, `.wasm`, `.forge`, `.cranelift`, `.js`, `.hdl`, and other active `atto-source.*` repositories as they mature. A backend with no compiler/typed MIR cannot be silently called conformant; classify it explicitly as `NOT_IMPLEMENTED` and do not include it in a passing parity claim. `atto-source.atto` and `atto-source.realtime` are tracked as experimental/incubating where they have no suitable production frontend.

## Next work (in dependency order)

1. Reconcile existing #37 → #40 → #41 / #42 point-sensitive SSA work, #46 disjoint-field + NLL regressions, #45 task/suspension, and the new MIR profile without weakening the base V0 oracle. Coordinate with the existing P0 tracker issue #3 instead of launching duplicate semantic solvers.
2. Add a Rust binary that emits *canonical* results directly from `verify_mir` over a portable, bounded, trusted typed-MIR serialization; do not rely on user-authored `is_copy`/`is_send` flags as proofs. Independently enumerate compiler source/MIR/guest effect inventories.
3. Add compiler adapters and manifest emitters, starting with `atto-source.rs` and LLVM, then Java, .NET, Wasm, Forge, Cranelift, JS and HDL. Consume compiler-produced MIR **not hand-authored success receipts**; verify checker ran and gating happened before code generation.
4. Create runnable `.atto` fixtures for safe sibling mutable borrows, overlapping places, last-use (NLL), move/copy/take, temporary implicit receiver borrows, `try`/`catch`/`finally`, throw/raise/panic/defer, pinned `await`/`select`, actor state and message passing. Record parser and backend capability levels; no syntactically unverified fixture can gate production.
5. Pin exact commits, source tree SHAs, emitted artifact hashes and stepful CI logs; if source Actions cannot allocate a runner, an **authorized** private carrier can receive a token-free, SHA-verified Git-tree mirror. Never equate zero executed CI steps with green tests, and never export a private tree to an unapproved carrier.

This protocol intentionally refuses to conflate successful source-free model comparisons with implemented same-pass compiler checking or actual safe guest execution.
