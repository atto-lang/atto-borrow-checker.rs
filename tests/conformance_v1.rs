//! Conformance harness tests: corpus self-conformance (L1), the diagnostic
//! registry, strict wire decoding, and L3 cross-check classification.
//! These are host model tests; they execute no backend compiler.

use atto_borrow_checker::conformance_v1::{
    self, classify, code_conforms, code_info, compare_graph_results, cross_check,
    decode_backend_record, decode_graph_corpus, decode_graph_result, run_graph_corpus, CodeClass,
    CrossClass, CrossPolicy, GraphResultClass, LocalVerdict, Verdict, REGISTRY,
};
use atto_borrow_checker::mir_v1::Producer;
use atto_borrow_checker::wire_v1::{
    decode_mir, decode_op, encode_mir, encode_op, mir_from_program, parse_json, write_json, Json,
    WireOp,
};
use atto_borrow_checker::{Block, BorrowKind, Op, Program, Traits};

const CORPUS: &str = include_str!("../conformance/graph-cases-v1.json");
const EXAMPLE_REPORT: &str = include_str!("../conformance/examples/backend-report.example.jsonl");
const EXAMPLE_GRAPH_RESULTS: &str =
    include_str!("../conformance/examples/graph-results.example.jsonl");

fn producer() -> Producer {
    return Producer {
        compiler_git_sha: "a".repeat(40),
        source_sha256: "b".repeat(64),
        source_unit_id: 1,
        function_id: 1,
    };
}

fn straight(ops: Vec<Op>) -> Program {
    return Program {
        entry: 0,
        blocks: vec![Block {
            id: 0,
            operations: ops,
            successors: vec![],
        }],
    };
}

fn init(owner: u32) -> Op {
    return Op::Init {
        owner,
        traits: Traits {
            is_copy: false,
            is_send: false,
        },
    };
}

// ---------------------------------------------------------------------------
// L1 corpus
// ---------------------------------------------------------------------------

#[test]
fn canonical_checker_conforms_to_every_graph_case() {
    let corpus = decode_graph_corpus(&parse_json(CORPUS).unwrap()).unwrap();
    assert!(corpus.cases.len() >= 22, "corpus shrank");
    for outcome in run_graph_corpus(&corpus) {
        assert!(
            outcome.conforms,
            "{}: expected {:?}, canonical {:?}",
            outcome.id, outcome.expected, outcome.actual
        );
    }
}

#[test]
fn corpus_expected_codes_are_registered_and_cover_every_class() {
    let corpus = decode_graph_corpus(&parse_json(CORPUS).unwrap()).unwrap();
    let mut classes = Vec::new();
    for case in &corpus.cases {
        if let Some(code) = &case.diagnostic {
            let info =
                code_info(code).unwrap_or_else(|| panic!("{}: unregistered {code}", case.id));
            if !classes.contains(&info.class) {
                classes.push(info.class);
            }
        }
    }
    for class in [
        CodeClass::Semantic,
        CodeClass::ModelLimit,
        CodeClass::Adapter,
    ] {
        assert!(classes.contains(&class), "no corpus case for {class:?}");
    }
}

#[test]
fn legacy_vendored_schema_still_decodes() {
    let mut legacy = CORPUS.replacen(
        "\"atto-borrow-graph-cases-v1\"",
        "\"atto-borrow-conformance-v1\"",
        1,
    );
    legacy = legacy.replacen("\"version\"", "\"evidencePolicy\": {}, \"version\"", 1);
    let corpus = decode_graph_corpus(&parse_json(&legacy).unwrap()).unwrap();
    assert_eq!(corpus.schema, "atto-borrow-conformance-v1");
}

#[test]
fn corpus_rejects_unknown_schema_and_duplicate_ids() {
    let bad = CORPUS.replacen("atto-borrow-graph-cases-v1", "made-up", 1);
    assert!(decode_graph_corpus(&parse_json(&bad).unwrap()).is_err());
    let doc = r#"{"schema":"atto-borrow-graph-cases-v1","cases":[
        {"id":"X","category":"c","expected":"accept","diagnostic":null,
         "graph":{"entry":0,"blocks":[{"id":0,"ops":[{"op":"Return"}],"successors":[]}]}},
        {"id":"X","category":"c","expected":"accept","diagnostic":null,
         "graph":{"entry":0,"blocks":[{"id":0,"ops":[{"op":"Return"}],"successors":[]}]}}]}"#;
    assert!(decode_graph_corpus(&parse_json(doc).unwrap()).is_err());
}

#[test]
fn graph_results_compare_exact_codes_and_report_gaps() {
    let corpus = decode_graph_corpus(&parse_json(CORPUS).unwrap()).unwrap();
    let results: Vec<_> = EXAMPLE_GRAPH_RESULTS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| decode_graph_result(&parse_json(l).unwrap()).unwrap())
        .collect();
    let classes = compare_graph_results(&corpus, &results);
    let get = |id: &str| {
        classes
            .iter()
            .find(|(case, _)| case == id)
            .map(|(_, class)| class.clone())
            .unwrap()
    };
    assert_eq!(get("C01"), GraphResultClass::Conforms);
    assert_eq!(get("C03"), GraphResultClass::Conforms);
    // Family spelling is not enough at L1.
    assert_eq!(get("C06"), GraphResultClass::WrongCode);
    assert_eq!(get("C22"), GraphResultClass::WrongVerdict);
    assert_eq!(get("C99"), GraphResultClass::UnknownCase);
    assert_eq!(get("C10"), GraphResultClass::Missing);
    assert_eq!(get("C30"), GraphResultClass::Unsupported);
    assert!(!GraphResultClass::Unsupported.fails(false));
    assert!(GraphResultClass::Unsupported.fails(true));
    assert!(GraphResultClass::Missing.fails(false));
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

fn quoted_codes(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("\"E_") {
        let tail = &rest[start + 1..];
        let end = tail
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(tail.len());
        if tail[end..].starts_with('"') {
            out.push(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    out.sort();
    out.dedup();
    return out;
}

#[test]
fn registry_covers_every_code_the_canonical_checker_emits() {
    let mut codes = quoted_codes(include_str!("../src/lib.rs"));
    codes.extend(quoted_codes(include_str!("../src/mir_v1.rs")));
    codes.push("E_MIR_UNSUPPORTED_EFFECT".into());
    for code in codes {
        assert!(code_info(&code).is_some(), "registry is missing {code}");
    }
}

#[test]
fn registry_is_unique_and_semantic_codes_have_families() {
    for (i, info) in REGISTRY.iter().enumerate() {
        assert!(
            REGISTRY[i + 1..]
                .iter()
                .all(|other| other.code != info.code),
            "duplicate registry row {}",
            info.code
        );
        assert_eq!(
            info.class == CodeClass::Semantic,
            !info.families.is_empty(),
            "{}: semantic rows need families, others none",
            info.code
        );
    }
}

#[test]
fn family_spellings_conform_but_unrelated_codes_do_not() {
    assert!(code_conforms("E_MOVED", "E_USE_AFTER_MOVE_OR_DROP"));
    assert!(code_conforms("E_DROPPED", "E_USE_AFTER_MOVE_OR_DROP"));
    assert!(code_conforms(
        "E_USE_AFTER_MOVE_OR_DROP",
        "E_USE_AFTER_MOVE_OR_DROP"
    ));
    assert!(code_conforms("E_BORROW", "E_BORROW_CONFLICT"));
    assert!(!code_conforms("E_BORROW", "E_USE_AFTER_MOVE_OR_DROP"));
    assert!(!code_conforms("E_MOVED", "E_SUSPEND_WITH_LIVE_LOAN"));
}

#[test]
fn bcv1_source_oracle_families_are_all_registered() {
    // Ownership families used by atto-platform-conformance BCV1 that the
    // canonical model can express. E_BINDING, E_MUTABILITY-only, E_LIFETIME
    // binders, E_HANDLE, E_POINTER_SYNTAX and E_CRITICAL_READ_WRITE are
    // checked outside this model (types, syntax, actor-state guards).
    let families = conformance_v1::ownership_families();
    for family in [
        "E_MOVED",
        "E_DROPPED",
        "E_BORROW",
        "E_SHARED_MUTATION",
        "E_COPY_SHALLOW_ALIAS",
        "E_COPY_GRAPH_UNPROVEN",
        "E_SHARE_ALIAS",
        "E_WEAK_PROVENANCE",
        "E_PIN_BOUNDARY_TRANSFER",
        "E_ACTOR_LOAN_ESCAPE",
        "E_LOAN_SUSPEND",
    ] {
        assert!(families.contains(&family), "{family} not mapped");
    }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

fn every_op() -> Vec<Op> {
    return vec![
        init(1),
        Op::Read { owner: 1 },
        Op::Write { owner: 1 },
        Op::Borrow {
            owner: 1,
            loan: 2,
            kind: BorrowKind::Shared,
        },
        Op::Borrow {
            owner: 1,
            loan: 3,
            kind: BorrowKind::Mutable,
        },
        Op::WriteThrough { owner: 1, loan: 3 },
        Op::EndBorrow { loan: 3 },
        Op::Move { from: 1, into: 2 },
        Op::Copy { from: 1, into: 2 },
        Op::DeepCopy {
            from: 1,
            into: 2,
            graph_proven: true,
        },
        Op::Drop { owner: 1 },
        Op::Freeze {
            from: 1,
            into: 2,
            deep_proven: false,
        },
        Op::PinStorage {
            owner: 1,
            stable_address_proven: true,
        },
        Op::RelocateStorage { owner: 1 },
        Op::CreateWeak {
            region: 4,
            weak: 5,
            generation_fenced: true,
        },
        Op::ProbeWeak {
            weak: 5,
            generation_fenced: false,
        },
        Op::TaskCaptureCopy { owner: 1 },
        Op::TaskCaptureMove { owner: 1 },
        Op::Suspend,
        Op::ActorHopBorrow { owner: 1 },
        Op::ActorSendPrepare {
            owner: 1,
            ticket: 6,
        },
        Op::ActorSendCommit { ticket: 6 },
        Op::ActorSendAbort { ticket: 6 },
        Op::ActorSendMove { owner: 1 },
        Op::ActorSendCopy { owner: 1 },
        Op::PublishFrozen {
            owner: 1,
            region: 4,
            sync_proven: true,
        },
        Op::PromoteGuarded {
            owner: 1,
            region: 4,
        },
        Op::Return,
    ];
}

#[test]
fn every_op_round_trips_through_the_wire_format() {
    let ops = every_op();
    // Keep this list exhaustive: a new Op variant must be added here.
    assert_eq!(ops.len(), 28);
    for op in ops {
        let text = write_json(&encode_op(&op));
        let decoded = decode_op(&parse_json(&text).unwrap(), "op").unwrap();
        assert_eq!(decoded, WireOp::Op(op), "{text}");
    }
}

#[test]
fn mir_round_trips_and_verifies_identically() {
    let program = straight(vec![
        init(1),
        Op::Borrow {
            owner: 1,
            loan: 10,
            kind: BorrowKind::Shared,
        },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mir = mir_from_program(&program, producer());
    let text = write_json(&encode_mir(&mir));
    let decoded = decode_mir(&parse_json(&text).unwrap(), "").unwrap();
    assert!(decoded.unsupported.is_empty());
    assert_eq!(write_json(&encode_mir(&decoded.function)), text);
    assert!(conformance_v1::verdict_for_mir(&decoded).is_accept());
}

#[test]
fn decoder_fails_closed_on_malformed_input() {
    for bad in [
        r#"{"op":"Read","owner":1,"onwer":2}"#, // unknown key (typo)
        r#"{"op":"Read"}"#,                     // missing operand
        r#"{"op":"Read","owner":-1}"#,          // negative
        r#"{"op":"Read","owner":1.5}"#,         // fraction
        r#"{"op":"Read","owner":4294967296}"#,  // exceeds u32
        r#"{"op":"Read","owner":"1"}"#,         // mistyped
        r#"{"op":"Teleport","owner":1}"#,       // unknown op
        r#"{"op":"Borrow","owner":1,"loan":2,"kind":"Weak"}"#,
    ] {
        let parsed = parse_json(bad);
        let decoded = parsed.and_then(|json| decode_op(&json, "op"));
        assert!(decoded.is_err(), "accepted {bad}");
    }
    for bad in [
        r#"{"a":1,"a":2}"#,
        r#"[1,2"#,
        r#"{"a":01}"#,
        r#"{"a":1} x"#,
        "\"\\ud800\"",
    ] {
        assert!(parse_json(bad).is_err(), "parsed {bad}");
    }
    let deep = "[".repeat(100) + &"]".repeat(100);
    assert!(parse_json(&deep).is_err(), "depth budget not enforced");
}

#[test]
fn unknown_effect_requires_unsupported_tag_and_always_rejects() {
    let mir = mir_from_program(&straight(vec![init(1), Op::Return]), producer());
    let mut json = write_json(&encode_mir(&mir));
    json = json.replacen(
        r#""effect":"Control","op":{"op":"Return"}"#,
        r#""effect":"Unsupported","op":{"op":"UnknownEffect","kind":"ffi"}"#,
        1,
    );
    let decoded = decode_mir(&parse_json(&json).unwrap(), "").unwrap();
    let verdict = conformance_v1::verdict_for_mir(&decoded);
    assert_eq!(verdict.code(), Some("E_MIR_UNSUPPORTED_EFFECT"));
    let mistagged = json.replacen(r#""effect":"Unsupported""#, r#""effect":"Control""#, 1);
    assert!(decode_mir(&parse_json(&mistagged).unwrap(), "").is_err());
}

// ---------------------------------------------------------------------------
// L3 classification
// ---------------------------------------------------------------------------

fn local(accept: bool, code: Option<&str>) -> LocalVerdict {
    return LocalVerdict {
        accept,
        code: code.map(str::to_string),
    };
}

fn canonical(ops: Vec<Op>) -> Verdict {
    let mir = mir_from_program(&straight(ops), producer());
    let text = write_json(&encode_mir(&mir));
    return conformance_v1::verdict_for_mir(&decode_mir(&parse_json(&text).unwrap(), "").unwrap());
}

#[test]
fn classification_matrix() {
    let use_after_move = canonical(vec![
        init(1),
        Op::Move { from: 1, into: 2 },
        Op::Read { owner: 1 },
        Op::Return,
    ]);
    let ok = canonical(vec![init(1), Op::Read { owner: 1 }, Op::Return]);
    let owner_reuse = canonical(vec![init(1), init(1), Op::Return]);
    let leaked_loan = canonical(vec![
        init(1),
        Op::Borrow {
            owner: 1,
            loan: 9,
            kind: BorrowKind::Shared,
        },
        Op::Return,
    ]);

    let cases: Vec<(LocalVerdict, Option<&Verdict>, CrossClass)> = vec![
        (local(true, None), Some(&ok), CrossClass::Agree),
        (
            local(false, Some("E_MOVED")),
            Some(&use_after_move),
            CrossClass::Agree,
        ),
        (
            local(false, Some("E_USE_AFTER_MOVE_OR_DROP")),
            Some(&use_after_move),
            CrossClass::Agree,
        ),
        (
            local(true, None),
            Some(&use_after_move),
            CrossClass::BackendPermissive,
        ),
        (
            local(false, Some("E_BORROW")),
            Some(&ok),
            CrossClass::BackendStricter,
        ),
        (
            local(false, Some("E_BORROW")),
            Some(&use_after_move),
            CrossClass::CodeMismatch,
        ),
        (
            local(false, Some("E_BORROW")),
            Some(&leaked_loan),
            CrossClass::Agree,
        ),
        (
            local(true, None),
            Some(&owner_reuse),
            CrossClass::AdapterDefect,
        ),
        (
            local(false, Some("E_SYNTAX")),
            None,
            CrossClass::NonOwnershipReject,
        ),
        (local(true, None), None, CrossClass::NotExported),
    ];
    for (local, canonical, expected) in cases {
        assert_eq!(
            classify(&local, canonical),
            expected,
            "{local:?} vs {canonical:?}"
        );
    }
}

#[test]
fn model_limits_are_out_of_scope_not_failures() {
    let mir = mir_from_program(
        &Program {
            entry: 0,
            blocks: vec![
                Block {
                    id: 0,
                    operations: vec![init(1)],
                    successors: vec![1],
                },
                Block {
                    id: 1,
                    operations: vec![Op::Read { owner: 1 }],
                    successors: vec![1],
                },
            ],
        },
        producer(),
    );
    let text = write_json(&encode_mir(&mir));
    let verdict =
        conformance_v1::verdict_for_mir(&decode_mir(&parse_json(&text).unwrap(), "").unwrap());
    assert_eq!(verdict.code(), Some("E_CFG_CYCLE_UNPROVEN"));
    let class = classify(&local(true, None), Some(&verdict));
    assert_eq!(class, CrossClass::OutOfScope);
    assert!(!class.fails(CrossPolicy::default()));
}

#[test]
fn failure_policy() {
    let strict = CrossPolicy::default();
    let lenient = CrossPolicy {
        allow_stricter: true,
        require_mir: false,
    };
    let full_export = CrossPolicy {
        allow_stricter: false,
        require_mir: true,
    };
    assert!(CrossClass::BackendPermissive.fails(lenient));
    assert!(CrossClass::CodeMismatch.fails(lenient));
    assert!(CrossClass::AdapterDefect.fails(lenient));
    assert!(CrossClass::BackendStricter.fails(strict));
    assert!(!CrossClass::BackendStricter.fails(lenient));
    assert!(!CrossClass::NotExported.fails(strict));
    assert!(CrossClass::NotExported.fails(full_export));
    assert!(!CrossClass::Agree.fails(full_export));
}

#[test]
fn example_report_classifies_as_documented() {
    let mut classes = Vec::new();
    for line in EXAMPLE_REPORT.lines().filter(|l| !l.trim().is_empty()) {
        let json = parse_json(line).unwrap();
        let expected = match &json {
            Json::Obj(fields) => fields
                .iter()
                .find(|(k, _)| k == "note")
                .and_then(|(_, v)| match v {
                    Json::Str(s) => s.strip_prefix("expect ").map(str::to_string),
                    _ => None,
                })
                .expect("example lines document their class in note"),
            _ => unreachable!(),
        };
        let record = decode_backend_record(&json).unwrap();
        let (_, class) = cross_check(&record);
        assert_eq!(class.name(), expected, "{line}");
        classes.push(class);
    }
    for class in [
        CrossClass::Agree,
        CrossClass::BackendPermissive,
        CrossClass::NotExported,
        CrossClass::NonOwnershipReject,
    ] {
        assert!(classes.contains(&class), "example lacks {class:?}");
    }
}

#[test]
fn backend_record_requires_exactly_one_of_mir_or_reason() {
    let base = r#"{"schema":"atto-borrow-backend-report-v1","backend":"java","compilerGitSha":"x","sourcePath":"a.atto","case":null,"function":"main","local":{"verdict":"accept","code":null}"#;
    assert!(decode_backend_record(&parse_json(&format!("{base}}}")).unwrap()).is_err());
    let both = format!(r#"{base},"mir":{{}},"mirUnavailable":"r"}}"#);
    assert!(decode_backend_record(&parse_json(&both).unwrap()).is_err());
    let unknown_backend = base.replace("\"java\"", "\"cobol\"");
    let line = format!(r#"{unknown_backend},"mirUnavailable":"r"}}"#);
    assert!(decode_backend_record(&parse_json(&line).unwrap()).is_err());
}
