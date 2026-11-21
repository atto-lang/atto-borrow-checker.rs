#!/usr/bin/env python3
"""Strict, source-free Atto borrow differential report comparison (NOT guest certification).

The corpus binds to existing Rust ownership-model tests. This program checks
report structure and agreement; it cannot authenticate who created a report,
prove that a compiler emitted it, or establish source/MIR/code completeness.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "atto-borrow-differential-report/v1"
PROFILE = {"mir-v0-acyclic", "mir-v1-envelope"}
BACKENDS = {
    "canonical", "atto-source.rs", "atto-source.java", "atto-source.llvm",
    "atto-source.net", "atto-source.wasm", "atto-source.forge",
    "atto-source.cranelift", "atto-source.js", "atto-source.hdl",
    "atto-source.atto", "atto-source.realtime",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"C[0-9]{2,4}\Z")
DIAGNOSTIC = re.compile(r"E_[A-Z0-9_]+\Z")
MAX_REPORT_BYTES = 1024 * 1024


class ConformanceError(ValueError):
    """Invalid evidence or a real semantic disagreement."""


def _exact_keys(obj, keys, path):
    if type(obj) is not dict or set(obj) != set(keys):
        raise ConformanceError(f"{path}: expected exactly {sorted(keys)}")


def _no_duplicate_keys(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ConformanceError(f"duplicate JSON member: {key}")
        out[key] = value
    return out


def load_corpus(path):
    raw = Path(path).read_bytes()
    if not raw or len(raw) > MAX_REPORT_BYTES or b"\r" in raw:
        raise ConformanceError("invalid corpus length or line endings")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ConformanceError("corpus must be UTF-8") from exc
    expected = {}
    for lineno, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        columns = line.split("\t")
        if len(columns) != 4:
            raise ConformanceError(f"corpus line {lineno}: expected 4 columns")
        case_id, profile, decision, diagnostic = columns
        if not ID.fullmatch(case_id) or case_id in expected:
            raise ConformanceError(f"corpus line {lineno}: invalid/duplicate case id")
        if profile not in PROFILE or decision not in {"allow", "reject"}:
            raise ConformanceError(f"corpus line {lineno}: invalid profile/decision")
        if (decision == "allow" and diagnostic != "-") or (
            decision == "reject" and not DIAGNOSTIC.fullmatch(diagnostic)
        ):
            raise ConformanceError(f"corpus line {lineno}: invalid diagnostic")
        expected[case_id] = (profile, decision, None if diagnostic == "-" else diagnostic)
    if not expected:
        raise ConformanceError("empty conformance corpus")
    return hashlib.sha256(raw).hexdigest(), expected


def load_report(path, digest, expected):
    path = Path(path)
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_REPORT_BYTES:
        raise ConformanceError(f"{path}: empty/oversize report")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"{path}: malformed JSON") from exc
    _exact_keys(report, {"schema", "implementation", "implementation_sha", "corpus_sha256", "results"}, str(path))
    name = report["implementation"]
    if type(name) is not str or name not in BACKENDS:
        raise ConformanceError(f"{path}: unknown implementation {name!r}")
    if report["schema"] != SCHEMA or report["corpus_sha256"] != digest:
        raise ConformanceError(f"{path}: version or exact corpus SHA mismatch")
    if type(report["implementation_sha"]) is not str or not SHA.fullmatch(report["implementation_sha"]):
        raise ConformanceError(f"{path}: invalid implementation Git commit SHA")
    results = report["results"]
    if type(results) is not list or len(results) != len(expected):
        raise ConformanceError(f"{path}: missing/extra cases")
    seen = set()
    for record in results:
        _exact_keys(record, {"case_id", "profile", "decision", "diagnostic"}, str(path))
        case_id, profile = record["case_id"], record["profile"]
        decision, diagnostic = record["decision"], record["diagnostic"]
        if type(case_id) is not str or case_id not in expected or case_id in seen:
            raise ConformanceError(f"{path}: duplicate or unexpected case {case_id!r}")
        seen.add(case_id)
        if profile != expected[case_id][0]:
            raise ConformanceError(f"{name}/{case_id}: profile mismatch")
        if decision not in ("allow", "reject") or type(decision) is not str:
            raise ConformanceError(f"{name}/{case_id}: missing/unsupported/skipped decision")
        if decision == "allow":
            if diagnostic is not None:
                raise ConformanceError(f"{name}/{case_id}: allow must have null diagnostic")
        elif type(diagnostic) is not str or not DIAGNOSTIC.fullmatch(diagnostic):
            raise ConformanceError(f"{name}/{case_id}: reject must have a stable error code")
        if (profile, decision, diagnostic) != expected[case_id]:
            raise ConformanceError(
                f"{name}/{case_id}: semantic disagreement: got {(profile, decision, diagnostic)!r}, "
                f"expected {expected[case_id]!r}"
            )
    return name, report["implementation_sha"]


def compare(corpus, reports, required):
    if not required or "canonical" not in required or not (required - {"canonical"}):
        raise ConformanceError("must require canonical AND at least one independent compiler")
    if required - BACKENDS:
        raise ConformanceError(f"unknown required implementations: {sorted(required - BACKENDS)}")
    digest, cases = load_corpus(corpus)
    found = {}
    for report in reports:
        name, sha = load_report(report, digest, cases)
        if name in found:
            raise ConformanceError(f"duplicate report for {name}")
        found[name] = sha
    if set(found) != required:
        raise ConformanceError(f"missing/unexpected implementations: required={sorted(required)}, found={sorted(found)}")
    return digest, len(cases), found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path(__file__).with_name("cases.tsv"))
    parser.add_argument("--report", required=True, action="append", type=Path)
    parser.add_argument("--require", required=True, action="append", help="canonical and each checked atto-source.* backend")
    args = parser.parse_args(argv)
    try:
        if len(set(args.require)) != len(args.require):
            raise ConformanceError("duplicate --require implementation")
        digest, n, found = compare(args.corpus, args.report, set(args.require))
    except (ConformanceError, OSError) as exc:
        print(f"BORROW_DIFFERENTIAL_FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"BORROW_DIFFERENTIAL_PASS corpus_sha256={digest} cases={n} implementations={','.join(sorted(found))}")
    print("EVIDENCE_LEVEL=SOURCE_FREE_REPORT_COMPARISON_ONLY; GUEST_CERTIFICATION=NOT_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
