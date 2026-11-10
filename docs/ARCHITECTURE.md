# Canonical Rust checker and native compiler passes

## Scope of this first draft

This crate implements **v0 conservative** field-sensitive ownership / loan dataflow over a small, typed, backend-neutral CFG. It is **not** an AttoLang parser, production integration, complete NLL checker, full AOT verifier or proof of guest execution. Tests are source-authored until a toolchain executes them.

Native Java, .NET, LLVM, Forge, Wasm and Cranelift compiler passes stay local for speed. They should reuse the same typed MIR graph while resolving types, effects, place identities and ownership, then perform CFG checking before lowering. A compiler may safely reject more programs than the Rust oracle; it must never silently accept a program the normative rules reject.

## IR invariants

- Place identity is (root, ordered field projections); sibling fields are disjoint, ancestor / descendant places overlap.
- Compiler-minted LoanIds are globally unique per function CFG. Two shared loans can overlap; exclusive loans cannot overlap any live loan.
- MAY-moved / MAY-loan state is unioned at joins; MUST-moved / MUST-loan state is intersected. A read is denied if **any** path moved the place. Reinitialize requires an exact definite move on **every** path.
- Loan end / use requires the loan to be definitely active. Every terminal block must have released all loans. Explicit EndLoan instructions are required until a real NLL lifetime pass emits them.
- Suspension with any possibly live loan is rejected. Future pinned-frame support needs a separate proof of lifetime, frame retention and cancellation cleanup.
- Transfers are whole-root only and require authenticated Sendable-like evidence, and cannot overlap any loan.
- The frontend is trusted for type / effect facts in this preliminary API; a forged is_copy or is_transferable bit **invalidates any safety claim**. Strict mode must independently validate provenance and prove a complete mapping from real typed MIR and emitted operations.
- Unsupported operations (FFI escape, closures, reborrows, destructors with effects, partial moves with custom Drop, actor critical regions and abnormal exits) must be **rejected by adapters**, not omitted. A synthetic graph alone is not guest proof.
- Bounded graph size, projection depth, and dataflow work guard resource exhaustion. Malformed/orphan CFG nodes fail closed.

## Required follow-up contracts

1. Versioned schema with source-unit, function, type-layout, alias provenance, effect, owner-domain, actor generation, loan and instruction identity. Bind every operation to compiler-produced typed MIR.
2. Exact source->CFG inventory and CFG->emitted code forward/reverse verification, including exceptional, cancellation and drop edges.
3. Nonlexical lifetime region inference, reborrows, two-phase borrows, branch-local loans, mutable container access and pinned-frame suspension.
4. A fixed shared conformance corpus with positive/negative guest sources, diagnostic codes and provenance receipts. Compare the canonical checker against Java/C#/C++ fast paths on identical IR.
5. CI must retain exact source/head SHA, Rust version, test steps, artifacts and provenance. No parser-only, synthetic, zero-step or host-only checks may be called certified compiled AttoLang guest results.

Related work: LLVM #1556/#1557, conformance #614/#615/#522, Java #2499 and .NET #419.
