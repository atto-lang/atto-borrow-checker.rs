# Conformance corpus

- `graph-cases-v1.json`: the canonical L1 ownership-graph corpus (59 cases).
  Backends pin it by commit plus git blob SHA; they do not vendor copies.
- `graph-cases-hybrid-v1.json`: 18 branch and loop cases for the hybrid verdict
  (`"engine": "hybrid"`): graphs V0 rejects only at its join/cycle limits.
- `examples/`: **synthetic** golden files that show the result and report
  formats. They are not results from any real backend.

See [the conformance plan](../docs/CONFORMANCE_PLAN.md) and
[the wire format](../docs/WIRE_FORMAT_V1.md).

```sh
cargo build --release --bin atto-borrow-conform
B=target/release/atto-borrow-conform
$B graph-cases   conformance/graph-cases-v1.json                    # canonical self-check
$B graph-results conformance/graph-cases-v1.json llvm-results.jsonl # L1, one backend
$B cross-check   java-report.jsonl                                  # L3
$B registry                                                         # code → class → families
```
