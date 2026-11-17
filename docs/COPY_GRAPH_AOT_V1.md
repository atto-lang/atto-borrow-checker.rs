# CopyGraph v1 — closed-world AOT copy-plan admission

**Status: experimental canonical Rust model, not an AttoLang guest compiler or physical copier.**

Module: src/copy_graph_v1.rs. Tests: tests/copy_graph_v1.rs.

This module admits or rejects a compiler-authenticated copy request over one
closed-world set of concrete type descriptors. copy! and copy!! have
**different witnesses and different alias guarantees**:

- **Shallow**: duplicate the concrete root and inline scalars. Owned mutable
  child fields block shallow copying. A SharedMutable child can remain aliased
  only outside the actor-send route; actual sharing still requires a trusted
  runtime authorization and correct lifetime management.
- **Deep**: compiler must generate and statically link functions that allocate
  fresh mutable children recursively, including previously shared mutable
  fields, while preserving internal repeated references and cycles using one
  memoization context **per invocation**.
- **Cross-actor**: typed sends/receives and a separately authenticated
  transitive Sendable proof are mandatory. Any retained mutable alias to a
  sender/other actor is forbidden. A deep-copy witness is not a Sendable proof.
- **Static parent / dynamic child**: the request names both types, and the
  verifier proves that the static type is a nominal ancestor of the actual
  concrete dynamic type. The returned copy plan is for the entire concrete
  type; it must not slice private child fields.
- **No runtime reflection or JIT**: each backend compiles copy functions and
  resolved layouts ahead of time. Descriptor metadata is compiler-internal and
  does not expose private fields. Unknown concrete types or imported stubs must
  fail with E_COPY_AOT_WITNESS; incomplete/ambiguous fields fail E_COPY_LAYOUT.

## Deliberate security boundaries

The admission function validates internally consistent metadata; it cannot
authenticate that the metadata represents the *entire* source program.
Compiler frontends must gather their field inventory **independently** from
typed AST/MIR, verify that no field was omitted, and produce stable
source/ABI descriptors.

The function does NOT allocate graph nodes, invoke actual user copy() hooks,
prove cyclic graph correctness, guarantee constructor-free shells, establish
rollback/destructor correctness, or authorize any cross-actor pointer. Rust
borrow checker V0 operations and this separate admission API have not yet been
composed into a sound source-to-MIR proof. A backend must refuse object
copying until that integration is finished.

Type-graph traversal has bounded size/depth, but does not bound runtime
object-graph depth, total allocation, time or hard-real-time latency. Such
budgets require additional runtime-profile proofs.

## Required backend integration

1. Parse prefix copy! and contiguous copy!!, preserving mode and
   evaluate-once semantics in typed IR. copy() / copy_deep() have zero
   user arguments.
2. Infer distinct Copyable<Self> and DeepCopyable<Self> capabilities from
   all stored fields and inherited state. Do not grant them merely because a
   method named copy_deep exists.
3. Attach authenticated concrete type, closed-world dispatch witnesses,
   field layout/version and actor destination provenance to the typed
   copy instruction. Reject unknown or noncopyable fields.
4. Generate a per-concrete-type clone plan; create an unpublished shell,
   memoize its identity before recursing, then copy all fields and invoke
   each composable superclass/subclass hook at most once.
5. Verify actor-mail admission and Sendable independently, with atomic
   release of failed message payloads. The compiler may eliminate an
   intermediate clone only if it proves destination-heap allocation preserves
   observable ownership and failure semantics.
6. Run exact-SHA parser/typecheck/Wasm/native-AOT guest fixtures and ASan/
   UBSan/drop/rollback tests across admitted backends, not just model tests.

Existing AttoLang spec PR #39 is the candidate normative contract.
Do not label this standalone Rust module a backend parity implementation.
