# Independent Atto typed-CFG SSA diagnostic consumer

This experimental adapter is the counterpart to Atto compiler issue #271,
Stage 2d. The private compiler exports `ATTO_LOAN_CFG_V1` from a real
checked typed-CFG subset; this separate Rust crate parses the complete
bounded fact census and invokes its EXISTING `polonius_ssa_v1::analyze_ssa`
solver. No dependency on private source checkout is needed by the checker.

`atto-cfg-ssa-check program.cfg` exits zero only if it received a valid
closed manifest, the independent SSA solver accepted its definition/use
dominance and loan invalidation facts, and every represented typed alias
read has a corresponding active loan at that point.

The parser rejects unknown contract versions, malformed point inventories,
duplicate IDs, missing/unknown edges, unsupported field values, wrong
owners, mismatched loan identities, unbounded input, and unproved trap or
conditional effects when an SSA-live loan is present.

**Critical nonclaims:** This is NOT authenticated proof that the compiler
emitted every source/guest instruction. The parser cannot know whether the
producer omitted a real alias use or CFG edge. The payload is not signed or
cryptographically attested. It cannot authorize production code generation,
change the Atto compiler's current ownership acceptance, or prove full
Polonius/rustc equivalence. Phi, loops, effects, cancellation, actors,
borrowed returns, heap and cross-backend conformance remain unsupported.

The strongest CI evidence is a composite private carrier branch containing
two *individually SHA-exact* Git subtrees (compiler + canonical checker),
running the actual compiler exporter and this consumer on real positive and
negative AttoLang guest fixtures. Do not use external cross-org checkout
tokens or describe partial-tree tests as complete-tree results.

Mutable stores through a loan count as SSA uses even when the RHS has no
loan loads. Issuing a loan invalidates overlapping live loans if either is
exclusive; distinct owner roots and shared/shared loans remain admissible.
Direct-read invalidation visits each known loan once per instruction. These
checks remain diagnostic-only and assume truthful canonical alias roots.
