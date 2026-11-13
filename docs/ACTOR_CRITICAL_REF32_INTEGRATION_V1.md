# Critical state + ref32 joint static preflight V1

**Status: DRAFT. NO EXACT-HEAD TEST EXECUTION OR GUEST CERTIFICATION.**

Integrates ref32 bounds/domain and allocation-slot epoch checking from PR #19
with lexical critical-read/write MIR checking from PR #17.

The API verify_critical_ref32_sites first checks the complete bounded CFG and
then requires one access descriptor for every critical read, critical write and
detached CriticalCopyI64 load, with no duplicates or unaccounted descriptors.
It derives read/write permission from the canonical operation, checks trusted
state-to-allocation binding and validates the full ref32/loan descriptor.

**Not an access grant.** Source-to-MIR provenance and site completeness must
be authenticated by each compiler. The runtime must independently own and
physically hold the generation-fenced reader/writer loan, keep actor-owned
heaps and logical stacks separate, and delay memory retirement until every
physical user is done. Model metadata or a successful Rust result is never a
native pointer capability.

The ref32 allocation slot generation is distinct from the actor incarnation.
Every recycled slot must burn a generation without wraparound. Cross-tenant
sharing requires separate explicit authority.

Run exact-head cargo fmt, clippy -D warnings, cargo test (debug and release),
then real same-source positive/negative .atto guest compilation and execution
using Java/Graal, LLVM O0/O2 + sanitizers and .NET NativeAOT.

Historic PR #17 and #19 CI runs refer to different source trees and cannot
certify this combined branch. No unauthorized cross-organization private source
transfer may occur.
