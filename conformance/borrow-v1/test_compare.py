"""Adversarial, source-free tests for the report comparator; NO compiler runs."""
import json
import tempfile
import unittest
from pathlib import Path

import compare

CASES = Path(__file__).with_name("cases.tsv")


class ComparatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.digest, self.cases = compare.load_corpus(CASES)
        self.assertEqual(len(self.cases), 22)

    def receipt(self, name, mutator=None):
        rows = [
            {"case_id": key, "profile": profile, "decision": decision, "diagnostic": diagnostic}
            for key, (profile, decision, diagnostic) in self.cases.items()
        ]
        obj = {
            "schema": compare.SCHEMA,
            "implementation": name,
            "implementation_sha": "a" * 40 if name == "canonical" else "b" * 40,
            "corpus_sha256": self.digest,
            "results": rows,
        }
        if mutator:
            mutator(obj)
        path = self.root / (name + ".json")
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def run_pair(self, mutator=None):
        return compare.compare(CASES, [self.receipt("canonical"), self.receipt("atto-source.rs", mutator)], {"canonical", "atto-source.rs"})

    def test_complete_model_comparison(self):
        _, count, checked = self.run_pair()
        self.assertEqual(count, 22)
        self.assertEqual(set(checked), {"canonical", "atto-source.rs"})

    def test_missing_case_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "missing/extra"):
            self.run_pair(lambda r: r["results"].pop())

    def test_duplicate_case_fails(self):
        def duplicate(r):
            r["results"][0] = r["results"][1].copy()
        with self.assertRaisesRegex(compare.ConformanceError, "duplicate"):
            self.run_pair(duplicate)

    def test_unsound_acceptance_fails(self):
        def accept(r):
            row = next(x for x in r["results"] if x["case_id"] == "C03")
            row.update(decision="allow", diagnostic=None)
        with self.assertRaisesRegex(compare.ConformanceError, "semantic disagreement"):
            self.run_pair(accept)

    def test_false_rejection_fails(self):
        def reject(r):
            row = next(x for x in r["results"] if x["case_id"] == "C01")
            row.update(decision="reject", diagnostic="E_BORROW_CONFLICT")
        with self.assertRaisesRegex(compare.ConformanceError, "semantic disagreement"):
            self.run_pair(reject)

    def test_diagnostic_drift_fails(self):
        def drift(r):
            next(x for x in r["results"] if x["case_id"] == "C03")["diagnostic"] = "E_BORROW_CONFLICT"
        with self.assertRaisesRegex(compare.ConformanceError, "semantic disagreement"):
            self.run_pair(drift)

    def test_skip_is_not_success(self):
        def skip(r):
            r["results"][0]["decision"] = "skip"
        with self.assertRaisesRegex(compare.ConformanceError, "skipped"):
            self.run_pair(skip)

    def test_corpus_digest_mismatch_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "SHA mismatch"):
            self.run_pair(lambda r: r.update(corpus_sha256="f" * 64))

    def test_claimed_shas_must_be_exact_commit_format(self):
        with self.assertRaisesRegex(compare.ConformanceError, "Git commit SHA"):
            self.run_pair(lambda r: r.update(implementation_sha="not-a-sha"))

    def test_unknown_implementation_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "unknown implementation"):
            self.run_pair(lambda r: r.update(implementation="replacement"))

    def test_unexpected_report_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "missing/unexpected"):
            compare.compare(CASES, [self.receipt("canonical"), self.receipt("atto-source.rs")], {"canonical", "atto-source.llvm"})

    def test_no_canonical_or_no_independent_backend_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "at least one"):
            compare.compare(CASES, [self.receipt("canonical")], {"canonical"})

    def test_json_duplicate_keys_fails(self):
        p = self.receipt("atto-source.rs")
        original = p.read_text()
        p.write_text(original.replace('"implementation":', '"implementation":"canonical","implementation":', 1))
        with self.assertRaisesRegex(compare.ConformanceError, "duplicate JSON member"):
            compare.compare(CASES, [self.receipt("canonical"), p], {"canonical", "atto-source.rs"})

    def test_unknown_result_field_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "expected exactly"):
            self.run_pair(lambda r: r["results"][0].update(pretend_success=True))

    def test_profile_mismatch_fails(self):
        with self.assertRaisesRegex(compare.ConformanceError, "profile mismatch"):
            self.run_pair(lambda r: r["results"][0].update(profile="mir-v1-envelope"))

    def test_c20_unsupported_effect_is_rejected_by_contract(self):
        self.assertEqual(self.cases["C20"], ("mir-v1-envelope", "reject", "E_MIR_UNSUPPORTED_EFFECT"))


if __name__ == "__main__":
    unittest.main()
