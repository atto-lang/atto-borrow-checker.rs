# Joint static / guarded ref32 model gate V1

**Status: draft, host-side consistency check only. No authenticated compiler-to-runtime bridge, native memory authority, or guest backend certification.**

The `actor_critical_guarded_model_v1::verify_joint_model_access` gate requires two **independent** checks:

1. Verify the **entire** typed-MIR critical-site inventory using `verify_critical_ref32_sites`: unique exact (block, operation) sites, lexical critical scopes, declared allocation/loan metadata, access bounds, alignment, and rejected suspension.
2. Select one validated read/write/snapshot operation and require trusted actor ID, generation, access size and alignment agreement with a separately minted guarded-runtime arena. Derive read/write intent from the MIR operation (never from a guest flag), require an authenticated live logical runtime permit, check the private runtime ref's extent/alignment, and compare its resulting 32-bit guest offset to the static reference offset.

A successful result is **only a checked `u32` guest offset** and records no persistent authorization. The type is an intentionally explicit logical gate, not a native pointer or transferable capability. It does not authenticate the compiler's source-to-MIR completeness, state-to-allocation mapping, actor identity, allocation ID / slot epoch, original program, runtime holder, tenant boundary, or physical RW loan; all of those remain external *trusted compiler/runtime obligations*. Static allocation IDs and runtime-private IDs have **distinct namespaces**, so matching actor IDs/generation/offsets do not establish a bijective allocation binding.

The runtime integration must maintain:

- An independently authenticated mapping between compiler MIR place IDs, arena, allocation, incarnation, and lifetime and a runtime-minted reference; reject any missing, ambiguous, replaced, or stale mapping.
- An independently authenticated holder/tenant/actor identity and non-forgeable permit, with the physical reader/writer guard held across the **entire** native load/store and not merely across this pure model call.
- Fail-closed STOP/retirement, cancellation, panic/unwind, task handoff, and pinned continuation quiescence before reclaiming native memory.
- Exact backend source/guest positive+negative fixtures, native/AOT and sanitizer verification, with no soft acceptance of an unsupported backend.

The cross-module host tests exercise valid reads, write-from-reader denial, released permits, foreign domains, offset/extent disagreement, missing MIR sites, suspended critical scope, and retired runtime. Source PR checks and independent review remain separate mandatory gates.
