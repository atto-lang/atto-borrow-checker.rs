# Deep Rust borrow verification in CI/CD (proposed P2–P4 contract)

Status: **design plus existing restricted V0/MIR model**, not an implemented production deep-analysis command or a nine-backend release certification. The current PR's `compare.py` is a source-free protocol comparator and cannot inspect actual compiler MIR.

## Two complementary verification layers

**Layer A — ordinary compiler invocation (required on every build).**
Every `atto-source.*` compiler owns a native-language borrow checker in its usual type resolution / typed CFG construction pass. It must reject use-after-move/drop, aliasing and loan conflicts, actor/suspend leaks, invalid capture, and unproven traits *before* emitting code. Its result is independent of the Rust reference. Normal builds must not spawn the Rust checker once per statement/function.

**Layer B — Rust deep verification (mandatory in trusted CI once adapted).**
After type checking and constructing a closed typed MIR, the compiler exports an independently-censused, versioned per-function ownership/effect CFG and a source-to-MIR mapping. Trusted CI checks the exact compiler/source commits and invokes the canonical Rust checker over this material. This pass can spend additional analysis budget on path-sensitive lifetime/loan fixed points, field projections, SSA phi, all-exit cleanup, exceptional/cancellation edges, actor isolation, pinned suspension and transitive effect/capture proofs **only for models actually implemented and validated by the reference checker**. V0 alone is deliberately acyclic and conservative; an unsupported/deep profile must fail closed, not be called conformant.

CI compares:
1. **Local compiler verdict** (accept/reject + stable error code + source node / operation ID) against **Rust verdict** on the **same typed IR**.
2. **Independent source census** against exported MIR instruction IDs, and typed MIR census against emitted IR/guest instructions; no effects omitted or synthesized.
3. **Compiler provenance**: immutable source and compiler Git trees, function/source digest, checker commit, type/layout/Copy/Send/Share proof provenance. Compiler-provided `is_copy`/`is_send` booleans are NOT independently verified proof.
4. **Runtime outcome**, including accepted real `.atto` guest runs, negative compiler rejections with no artifact, and exception/drop/cancel/actor tests. The static verifier cannot establish physical memory safety by itself.

An `allow`/PASS result is usable only when the evidence for **each applicable gate** exists and the strict checker supports that exact feature profile. A local rejection and Rust acceptance is a disagreement too; do not suppress it or silently rewrite diagnostics.

## Suggested CI cadence

| Trigger | Always run | Additional deep gates | Required result |
| --- | --- | --- | --- |
| Developer incremental compile | Native in-pass checker | No external checker required for verified simple profile | Fast safe compilation |
| Every PR | Native checker, Rust canonical unit suite and all supported typed-MIR differential fixtures | Full function CFG analysis, strict source-to-MIR census, negative guest compile tests, signed/verified artifact manifest where available | Block merge if **any** mismatch, missing evidence, unsupported effect or stale report |
| Main/integration | Above | Whole-project call/capture summaries, all-exit unwind/cancel, native/browser/AOT positive guest execution where supported; sanitizer and ABI tests | Block release on any required missing/failed check |
| Nightly / scheduled | Above | Budgeted fuzzing, mutation/differential tests, larger CFG/SSA/loop stress, model checking and cross-backend parity | File reproducible issues/counterexamples; do not silently promote unverified feature support |

In the final PR gate, Rust can be invoked once for a **batched project MIR export** (or through a persistent helper) and cache per-function decisions by a fingerprint of compiler SHA, rule-set version, typed function IR, transitive effect/type witness digest and callee summaries. This permits more expensive verification in CI without penalizing routine builds. A function cache key must invalidate on dependent type/callee/effect changes, actor-domain-generation rules or compiler version changes.

## Stable portable export requirements (not implemented here)

A safe backend producer must export:
- `source_unit_id`, `function_id`, compiler/checker/spec commits, provenance and canonical paths;
- typed roots and projected places, unique borrow/loan/write/SSA IDs, object generation/actor/tenant domains;
- explicit Copy/Send/Share/Sync trait/layout witness **and derivation**, not asserted flags;
- every CFG basic block and edge (normal, branch, loop, throw, raise, panic, defer/finally, cancel, suspend/resume);
- reads/writes, moves/takes/copies/drops, issue/use/end of loans, phi operands with per-edge origins, FFI effects and unknowns;
- effects/source-span inventory **independently enumerated** during verified compiler source/IR lowering;
- emitted instruction and cleanup/guard receipts for guest/AOT proof.

The reference checker must reject mismatched versions, missing/dangling IDs, unmodeled operations, unsupported features, absent witnesses, resource-budget exhaustion, and unverifiable provenance rather than treating them as safe no-ops. Full source completeness cannot be proven from two manifests produced by the same buggy or compromised frontend alone; require independent derivation and compiled-guest evidence.

## CI implementation sequence

1. **Current, executable:** run `cargo test --all-targets --locked` and `cargo test --all-targets --locked --release` for canonical Rust models; run `python3 -m unittest discover -s conformance/borrow-v1 -p 'test_*.py' -v`. These only test Rust model behavior and the report protocol.
2. **Next:** add a bounded portable typed-MIR reader, canonical `borrow-checker ci-check` CLI and report emitter **which calls `mir_v1::verify_mir`** (then later the reviewed cyclic/NLL/SSA models), with independently sourced inventory and parser adversarial tests. Do not allow hand-authored PASS reports as release evidence.
3. **Next:** enable true compiler-local MIR exporters and receipt generation for Rust/LLVM, then Java/.NET/Wasm/Forge/Cranelift/JS/HDL; check the exact guest behavior. Every backend remains separately accountable for native check-before-codegen.
4. **Then:** make CI strict dual-verification a **required** protected check only after it is materially runnable and correct. A missing source-org runner is `NOT_EXECUTED`, never PASS. An authorized private carrier can run an exact tree/SHA-verified token-free mirror with real steps; do not export private source to an unapproved destination.
5. **Finally:** use differential counterexamples to improve the compiler-local passes and the Rust reference, update the shared spec/corpus and rerun all backends. The Rust implementation is an independent oracle, not a substitute for language semantics or real safety testing.

## Required evidence labels

- `MODEL_ONLY`: Rust checker library/model tests were executed.
- `PROTOCOL_ONLY`: report comparator executed with fixture or synthetic receipts.
- `COMPILER_MIR_VERIFIED`: actual typed MIR from the named compiler was independently checked at exact source/compiler SHA.
- `GUEST_EXECUTED`: compiled, version-bound guest test actually ran.
- `NOT_EXECUTED`: no real test steps or runner allocation; **never green**.

A differential result only certifies the precise feature profile actually exercised and must not be promoted into a universal borrow safety claim.
