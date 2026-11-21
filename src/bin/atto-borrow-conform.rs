//! `atto-borrow-conform`: run the canonical checker as the conformance oracle
//! for the `atto-source.*` backends.
//!
//! Exit status: 0 conformant, 1 nonconformant, 2 usage or input error.
//! Output is JSON Lines on stdout; the final line is a `summary` object.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::ExitCode;

use atto_borrow_checker::conformance_v1::{
    self, compare_graph_results, cross_check, decode_backend_record, decode_graph_corpus,
    decode_graph_result, run_graph_corpus, CrossPolicy, GraphCorpus, REGISTRY,
};
use atto_borrow_checker::wire_v1::{self, parse_json, write_json, Json, MAX_DOCUMENT_BYTES};

const USAGE: &str = "usage:
  atto-borrow-conform graph-cases <graph-cases.json>
      Canonical self-conformance over the L1 corpus.
  atto-borrow-conform graph-results <graph-cases.json> <results.jsonl> [--require-full]
      L1: compare one backend engine's graph results to the corpus (exact codes).
      UNSUPPORTED cases are tolerated coverage gaps unless --require-full.
  atto-borrow-conform verify-mir <mir.json|->
      Canonically verify one atto-borrow-mir-v1 function.
  atto-borrow-conform cross-check <report.jsonl|-> [--allow-stricter] [--require-mir]
      L3: re-verify each backend-exported function and classify disagreement.
  atto-borrow-conform registry
      Print the canonical code registry as TSV (code, class, families).";

fn read_input(path: &str) -> Result<String, String> {
    let mut text = String::new();
    if path == "-" {
        std::io::stdin()
            .take(MAX_DOCUMENT_BYTES as u64 * 64 + 1)
            .read_to_string(&mut text)
            .map_err(|e| format!("stdin: {e}"))?;
    } else {
        text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    }
    return Ok(text);
}

fn parse_doc(path: &str) -> Result<Json, String> {
    let text = read_input(path)?;
    return parse_json(&text).map_err(|e| format!("{path}: {e}"));
}

/// Non-empty, non-comment lines of a JSON Lines file, each parsed.
fn parse_lines(path: &str) -> Result<Vec<(usize, Json)>, String> {
    let text = read_input(path)?;
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = parse_json(trimmed).map_err(|e| format!("{path}:{}: {e}", index + 1))?;
        out.push((index + 1, value));
    }
    return Ok(out);
}

fn obj(fields: Vec<(&str, Json)>) -> Json {
    return Json::Obj(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    );
}

fn s(v: &str) -> Json {
    return Json::Str(v.to_string());
}

fn opt_s(v: Option<&str>) -> Json {
    return v.map_or(Json::Null, s);
}

fn counts_json(counts: &BTreeMap<&'static str, u64>) -> Json {
    return Json::Obj(
        counts
            .iter()
            .map(|(k, v)| (k.to_string(), Json::Int(*v)))
            .collect(),
    );
}

fn load_corpus(path: &str) -> Result<GraphCorpus, String> {
    return decode_graph_corpus(&parse_doc(path)?).map_err(|e| format!("{path}: {e}"));
}

fn cmd_graph_cases(path: &str) -> Result<bool, String> {
    let corpus = load_corpus(path)?;
    let outcomes = run_graph_corpus(&corpus);
    let mut failures = 0u64;
    for outcome in &outcomes {
        if !outcome.conforms {
            failures += 1;
        }
        println!(
            "{}",
            write_json(&obj(vec![
                ("case", s(&outcome.id)),
                ("expected", opt_s(outcome.expected.as_deref())),
                ("canonical", outcome.actual.to_json()),
                ("conforms", Json::Bool(outcome.conforms)),
            ]))
        );
    }
    println!(
        "{}",
        write_json(&obj(vec![(
            "summary",
            obj(vec![
                ("level", s("L1-canonical")),
                ("schema", s(&corpus.schema)),
                ("cases", Json::Int(outcomes.len() as u64)),
                ("failures", Json::Int(failures)),
            ]),
        )]))
    );
    return Ok(failures == 0);
}

fn cmd_graph_results(
    corpus_path: &str,
    results_path: &str,
    require_full: bool,
) -> Result<bool, String> {
    let corpus = load_corpus(corpus_path)?;
    let mut results = Vec::new();
    let mut backend: Option<String> = None;
    for (line, value) in parse_lines(results_path)? {
        let result =
            decode_graph_result(&value).map_err(|e| format!("{results_path}:{line}: {e}"))?;
        match &backend {
            None => backend = Some(result.backend.clone()),
            Some(b) if *b != result.backend => {
                return Err(format!(
                    "{results_path}:{line}: mixed backends {b:?} and {:?}",
                    result.backend
                ))
            }
            Some(_) => {}
        }
        results.push(result);
    }
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut failures = 0u64;
    for (case, class) in compare_graph_results(&corpus, &results) {
        *counts.entry(class.name()).or_default() += 1;
        if class.fails(require_full) {
            failures += 1;
        }
        println!(
            "{}",
            write_json(&obj(vec![("case", s(&case)), ("class", s(class.name()))]))
        );
    }
    println!(
        "{}",
        write_json(&obj(vec![(
            "summary",
            obj(vec![
                ("level", s("L1-backend")),
                ("backend", opt_s(backend.as_deref())),
                ("cases", Json::Int(corpus.cases.len() as u64)),
                ("requireFull", Json::Bool(require_full)),
                ("failures", Json::Int(failures)),
                ("counts", counts_json(&counts)),
            ]),
        )]))
    );
    return Ok(failures == 0);
}

fn cmd_verify_mir(path: &str) -> Result<bool, String> {
    let doc = parse_doc(path)?;
    let mir = wire_v1::decode_mir(&doc, "").map_err(|e| format!("{path}: {e}"))?;
    let verdict = conformance_v1::verdict_for_mir(&mir);
    println!("{}", write_json(&verdict.to_json()));
    return Ok(verdict.is_accept());
}

fn cmd_cross_check(path: &str, policy: CrossPolicy) -> Result<bool, String> {
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut per_backend: BTreeMap<String, BTreeMap<&'static str, u64>> = BTreeMap::new();
    let mut failures = 0u64;
    let mut records = 0u64;
    for (line, value) in parse_lines(path)? {
        let record = decode_backend_record(&value).map_err(|e| format!("{path}:{line}: {e}"))?;
        records += 1;
        let (canonical, class) = cross_check(&record);
        let fails = class.fails(policy);
        if fails {
            failures += 1;
        }
        *counts.entry(class.name()).or_default() += 1;
        *per_backend
            .entry(record.backend.clone())
            .or_default()
            .entry(class.name())
            .or_default() += 1;
        println!(
            "{}",
            write_json(&obj(vec![
                ("line", Json::Int(line as u64)),
                ("backend", s(&record.backend)),
                ("compilerGitSha", s(&record.compiler_git_sha)),
                ("sourcePath", s(&record.source_path)),
                ("case", opt_s(record.case.as_deref())),
                ("function", s(&record.function)),
                (
                    "local",
                    obj(vec![
                        (
                            "verdict",
                            s(if record.local.accept {
                                "accept"
                            } else {
                                "reject"
                            }),
                        ),
                        ("code", opt_s(record.local.code.as_deref())),
                    ]),
                ),
                (
                    "canonical",
                    canonical.as_ref().map_or(Json::Null, |v| v.to_json()),
                ),
                (
                    "mirUnavailable",
                    opt_s(record.mir.as_ref().err().map(String::as_str)),
                ),
                ("class", s(class.name())),
                ("fails", Json::Bool(fails)),
            ]))
        );
    }
    println!(
        "{}",
        write_json(&obj(vec![(
            "summary",
            obj(vec![
                ("level", s("L3-cross-check")),
                ("records", Json::Int(records)),
                ("failures", Json::Int(failures)),
                ("allowStricter", Json::Bool(policy.allow_stricter)),
                ("requireMir", Json::Bool(policy.require_mir)),
                ("counts", counts_json(&counts)),
                (
                    "byBackend",
                    Json::Obj(
                        per_backend
                            .iter()
                            .map(|(b, c)| (b.clone(), counts_json(c)))
                            .collect(),
                    ),
                ),
            ]),
        )]))
    );
    return Ok(failures == 0);
}

fn cmd_registry() -> Result<bool, String> {
    println!("code\tclass\tfamilies");
    for info in REGISTRY {
        println!(
            "{}\t{}\t{}",
            info.code,
            info.class.name(),
            info.families.join(",")
        );
    }
    return Ok(true);
}

fn run(args: &[String]) -> Result<bool, String> {
    let rest: Vec<&str> = args.iter().map(String::as_str).collect();
    return match rest.as_slice() {
        ["graph-cases", corpus] => cmd_graph_cases(corpus),
        ["graph-results", corpus, results] => cmd_graph_results(corpus, results, false),
        ["graph-results", corpus, results, "--require-full"] => {
            cmd_graph_results(corpus, results, true)
        }
        ["verify-mir", mir] => cmd_verify_mir(mir),
        ["cross-check", report, flags @ ..] => {
            let mut policy = CrossPolicy::default();
            for flag in flags {
                match *flag {
                    "--allow-stricter" => policy.allow_stricter = true,
                    "--require-mir" => policy.require_mir = true,
                    other => return Err(format!("unknown flag {other}\n{USAGE}")),
                }
            }
            cmd_cross_check(report, policy)
        }
        ["registry"] => cmd_registry(),
        _ => Err(USAGE.to_string()),
    };
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    return match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    };
}
