//! Hybrid canonical verdict (V0, then cyclic_v1 past V0 join/cycle limits).
//! Host model tests only; no backend compiler is executed.

use atto_borrow_checker::conformance_v1::{
    classify, cross_check_with, decode_backend_record, decode_graph_corpus, run_graph_corpus,
    verdict_for_graph_with, CrossClass, EngineMode, LocalVerdict, Verdict,
};
use atto_borrow_checker::hybrid_v1::{self, is_cfg_model_limit, Engine};
use atto_borrow_checker::mir_v1::Producer;
use atto_borrow_checker::wire_v1::{encode_mir, mir_from_program, parse_json, write_json};
use atto_borrow_checker::{Block, Op, Program, Traits};

const HYBRID: &str = include_str!("../conformance/graph-cases-hybrid-v1.json");
const V0_CORPUS: &str = include_str!("../conformance/graph-cases-v1.json");

fn corpus(text: &str) -> atto_borrow_checker::conformance_v1::GraphCorpus {
    return decode_graph_corpus(&parse_json(text).unwrap()).unwrap();
}

#[test]
fn hybrid_corpus_conforms() {
    let hybrid = corpus(HYBRID);
    assert_eq!(hybrid.engine, EngineMode::Hybrid);
    assert!(hybrid.cases.len() >= 18);
    for outcome in run_graph_corpus(&hybrid) {
        assert!(
            outcome.conforms,
            "{}: expected {:?}, got {:?}",
            outcome.id, outcome.expected, outcome.actual
        );
    }
}

#[test]
fn every_hybrid_case_is_one_v0_cannot_decide_or_already_agrees_on() {
    // The corpus must exercise the uplift, not restate V0 results.
    let mut limited = 0;
    for case in corpus(HYBRID).cases {
        let (v0, engine) = verdict_for_graph_with(&case.graph, EngineMode::V0);
        assert_eq!(engine, Engine::V0);
        match v0.code() {
            Some(code) if is_cfg_model_limit(code) => limited += 1,
            other => assert_eq!(
                other,
                case.diagnostic.as_deref(),
                "{}: V0 decided it, so it must agree with the hybrid expectation",
                case.id
            ),
        }
    }
    assert!(
        limited >= 15,
        "corpus no longer exercises V0 limits: {limited}"
    );
}

#[test]
fn hybrid_never_changes_a_verdict_v0_decided() {
    // Over the whole L1 corpus: identical to V0 except where V0 hit a CFG
    // model limit, and only those are attributed to cyclic_v1.
    for case in corpus(V0_CORPUS).cases {
        let (v0, _) = verdict_for_graph_with(&case.graph, EngineMode::V0);
        let (hybrid, engine) = verdict_for_graph_with(&case.graph, EngineMode::Hybrid);
        if v0.code().is_some_and(is_cfg_model_limit) {
            assert_eq!(engine, Engine::CyclicV1, "{}", case.id);
        } else {
            assert_eq!(engine, Engine::V0, "{}", case.id);
            assert_eq!(hybrid, v0, "{}", case.id);
        }
    }
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

fn block(id: u32, operations: Vec<Op>, successors: Vec<u32>) -> Block {
    return Block {
        id,
        operations,
        successors,
    };
}

#[test]
fn back_edge_to_the_entry_block_does_not_re_uninitialize_owners() {
    // The entry block is a loop header. Owners are uninitialized in a
    // separate synthetic block, so the loop keeps owner 1 initialized.
    let program = Program {
        entry: 0,
        blocks: vec![
            block(0, vec![Op::Read { owner: 1 }], vec![0, 1]),
            block(1, vec![Op::Return], vec![]),
        ],
    };
    // Owner 1 is never initialized at all: a use of a never-owned value.
    let result = hybrid_v1::check(&program).expect("lowerable");
    assert_eq!(result.unwrap_err().code, "E_USE_AFTER_MOVE_OR_DROP");

    let program = Program {
        entry: 0,
        blocks: vec![
            block(0, vec![init(1)], vec![1]),
            block(1, vec![Op::Read { owner: 1 }], vec![1, 0, 2]),
            block(2, vec![Op::Return], vec![]),
        ],
    };
    // Back-edge 1 -> 0 re-runs Init on a live owner: adapter defect.
    let result = hybrid_v1::check(&program).expect("lowerable");
    assert_eq!(result.unwrap_err().code, "E_OWNER_DEF_REUSED");
}

#[test]
fn exit_shape_is_checked_before_lowering() {
    let missing_return = Program {
        entry: 0,
        blocks: vec![
            block(0, vec![init(1)], vec![1]),
            block(1, vec![Op::Read { owner: 1 }], vec![1, 2]),
            block(2, vec![Op::Read { owner: 1 }], vec![]),
        ],
    };
    let err = hybrid_v1::check(&missing_return).unwrap().unwrap_err();
    assert_eq!(
        (err.code, err.block, err.operation),
        ("E_IMPLICIT_EXIT", 2, 1)
    );
}

#[test]
fn failures_point_at_the_original_operation() {
    // Move(1->2) lowers to two cyclic ops; the later read must still be
    // reported at its own original index in the join block.
    let program = Program {
        entry: 0,
        blocks: vec![
            block(0, vec![init(1)], vec![1, 2]),
            block(1, vec![Op::Move { from: 1, into: 2 }], vec![3]),
            block(2, vec![Op::Read { owner: 1 }], vec![3]),
            block(
                3,
                vec![Op::Read { owner: 2 }, Op::Read { owner: 1 }, Op::Return],
                vec![],
            ),
        ],
    };
    let err = hybrid_v1::check(&program).unwrap().unwrap_err();
    // Owner 2 is MAY-uninitialized at the join (only arm 1 moved into it).
    assert_eq!(
        (err.code, err.block, err.operation),
        ("E_USE_AFTER_MOVE_OR_DROP", 3, 0)
    );
}

fn producer() -> Producer {
    return Producer {
        compiler_git_sha: "a".repeat(40),
        source_sha256: "b".repeat(64),
        source_unit_id: 1,
        function_id: 1,
    };
}

#[test]
fn cross_check_uses_the_hybrid_for_backend_branches() {
    // A backend's branched graph: MAY-moved owner read after the join.
    let program = Program {
        entry: 0,
        blocks: vec![
            block(0, vec![init(1)], vec![1, 2]),
            block(
                1,
                vec![Op::Move { from: 1, into: 2 }, Op::Drop { owner: 2 }],
                vec![3],
            ),
            block(2, vec![Op::Read { owner: 1 }], vec![3]),
            block(3, vec![Op::Read { owner: 1 }, Op::Return], vec![]),
        ],
    };
    let mir = write_json(&encode_mir(&mir_from_program(&program, producer())));
    let line = |verdict: &str, code: &str| {
        format!(
            r#"{{"schema":"atto-borrow-backend-report-v1","backend":"rs","compilerGitSha":"{}","sourcePath":"x.atto","case":null,"function":"main","local":{{"verdict":"{verdict}","code":{code}}},"mir":{mir}}}"#,
            "a".repeat(40)
        )
    };
    let reject =
        decode_backend_record(&parse_json(&line("reject", r#""E_MOVED""#)).unwrap()).unwrap();
    let (canonical, class) = cross_check_with(&reject, EngineMode::Hybrid);
    let (verdict, engine) = canonical.unwrap();
    assert_eq!(engine, Engine::CyclicV1);
    assert_eq!(verdict.code(), Some("E_USE_AFTER_MOVE_OR_DROP"));
    assert_eq!(class, CrossClass::Agree);

    // Strict V0 mode keeps the old, honest OUT_OF_SCOPE.
    let (_, v0_class) = cross_check_with(&reject, EngineMode::V0);
    assert_eq!(v0_class, CrossClass::OutOfScope);

    // An unsound backend accept is now caught instead of being out of scope.
    let accept = decode_backend_record(&parse_json(&line("accept", "null")).unwrap()).unwrap();
    assert_eq!(
        cross_check_with(&accept, EngineMode::Hybrid).1,
        CrossClass::BackendPermissive
    );
}

#[test]
fn hybrid_accept_is_an_accept_without_cleanup_plan() {
    let h01 = corpus(HYBRID)
        .cases
        .into_iter()
        .find(|c| c.id == "H01")
        .unwrap();
    let (verdict, engine) = verdict_for_graph_with(&h01.graph, EngineMode::Hybrid);
    assert_eq!(engine, Engine::CyclicV1);
    match verdict {
        Verdict::Accept(proof) => assert!(proof.cleanup_by_exit.is_empty()),
        other => panic!("expected accept, got {other:?}"),
    }
    let local = LocalVerdict {
        accept: true,
        code: None,
    };
    let (verdict, _) = verdict_for_graph_with(&h01.graph, EngineMode::Hybrid);
    assert_eq!(classify(&local, Some(&verdict)), CrossClass::Agree);
}
