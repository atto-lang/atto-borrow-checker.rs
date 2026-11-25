//! Native Rust execution of the 22 logical ownership cases shared by the
//! nine-toolchain source-free conformance contract. This is intentionally a
//! direct call into the canonical verifier, not another JavaScript model.
//! These fixtures do not authenticate a compiler's source-to-MIR lowering.

use atto_borrow_checker::mir_v1::{
    verify_mir, Effect, Instruction, MirBlock, MirError, MirFunction, Producer, CONTRACT_VERSION,
};
use atto_borrow_checker::{verify, Block, BorrowKind, Op, Program, Traits};

fn init(owner: u32, copy: bool, send: bool) -> Op {
    Op::Init {
        owner,
        traits: Traits {
            is_copy: copy,
            is_send: send,
        },
    }
}

fn borrow(owner: u32, loan: u32, kind: BorrowKind) -> Op {
    Op::Borrow { owner, loan, kind }
}

fn block(id: u32, operations: Vec<Op>, successors: Vec<u32>) -> Block {
    Block {
        id,
        operations,
        successors,
    }
}

fn linear(operations: Vec<Op>) -> Program {
    Program {
        entry: 0,
        blocks: vec![block(0, operations, vec![])],
    }
}

fn branching(blocks: Vec<Block>) -> Program {
    Program { entry: 0, blocks }
}

struct Case {
    id: &'static str,
    program: Program,
    diagnostic: Option<&'static str>,
}

fn case(id: &'static str, operations: Vec<Op>, diagnostic: Option<&'static str>) -> Case {
    Case {
        id,
        program: linear(operations),
        diagnostic,
    }
}

fn all_native_cases() -> Vec<Case> {
    use BorrowKind::{Mutable, Shared};
    vec![
        case(
            "C01",
            vec![init(1, true, false), Op::Read { owner: 1 }, Op::Return],
            None,
        ),
        case(
            "C02",
            vec![
                init(1, false, false),
                Op::Move { from: 1, into: 2 },
                Op::Read { owner: 2 },
                Op::Return,
            ],
            None,
        ),
        case(
            "C03",
            vec![
                init(1, false, false),
                Op::Move { from: 1, into: 2 },
                Op::Read { owner: 1 },
                Op::Return,
            ],
            Some("E_USE_AFTER_MOVE_OR_DROP"),
        ),
        case(
            "C04",
            vec![
                init(1, false, false),
                Op::Copy { from: 1, into: 2 },
                Op::Return,
            ],
            Some("E_COPY_PROOF_REQUIRED"),
        ),
        case(
            "C05",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                borrow(1, 11, Shared),
                Op::Read { owner: 1 },
                Op::EndBorrow { loan: 11 },
                Op::EndBorrow { loan: 10 },
                Op::Return,
            ],
            None,
        ),
        case(
            "C06",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                borrow(1, 11, Mutable),
                Op::Return,
            ],
            Some("E_BORROW_CONFLICT"),
        ),
        case(
            "C07",
            vec![
                init(1, false, false),
                borrow(1, 10, Mutable),
                Op::WriteThrough { owner: 1, loan: 10 },
                Op::EndBorrow { loan: 10 },
                Op::Return,
            ],
            None,
        ),
        case(
            "C08",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                Op::Write { owner: 1 },
                Op::Return,
            ],
            Some("E_BORROW_CONFLICT"),
        ),
        case(
            "C09",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                Op::Drop { owner: 1 },
                Op::Return,
            ],
            Some("E_BORROW_CONFLICT"),
        ),
        case(
            "C10",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                Op::Suspend,
                Op::Return,
            ],
            Some("E_SUSPEND_WITH_LIVE_LOAN"),
        ),
        case(
            "C11",
            vec![
                init(1, false, false),
                borrow(1, 10, Shared),
                Op::EndBorrow { loan: 10 },
                Op::Suspend,
                Op::Return,
            ],
            None,
        ),
        case(
            "C12",
            vec![
                init(1, false, false),
                Op::ActorHopBorrow { owner: 1 },
                Op::Return,
            ],
            Some("E_ACTOR_BORROW_ESCAPE"),
        ),
        case(
            "C13",
            vec![
                init(1, true, false),
                Op::TaskCaptureCopy { owner: 1 },
                Op::Return,
            ],
            Some("E_TASK_CAPTURE_PROOF"),
        ),
        case(
            "C14",
            vec![
                init(1, false, true),
                Op::TaskCaptureMove { owner: 1 },
                Op::Return,
            ],
            None,
        ),
        case(
            "C15",
            vec![
                init(1, false, false),
                Op::EndBorrow { loan: 10 },
                Op::Return,
            ],
            Some("E_UNKNOWN_LOAN"),
        ),
        Case {
            id: "C16",
            program: branching(vec![
                block(0, vec![], vec![1, 2]),
                block(1, vec![init(1, false, false)], vec![3]),
                block(2, vec![init(1, false, false)], vec![3]),
                block(3, vec![Op::Return], vec![]),
            ]),
            diagnostic: Some("E_OWNER_DEF_REUSED"),
        },
        Case {
            id: "C17",
            program: branching(vec![
                block(0, vec![init(1, false, false)], vec![1, 2]),
                block(
                    1,
                    vec![borrow(1, 10, Shared), Op::EndBorrow { loan: 10 }],
                    vec![3],
                ),
                block(
                    2,
                    vec![borrow(1, 10, Shared), Op::EndBorrow { loan: 10 }],
                    vec![3],
                ),
                block(3, vec![Op::Return], vec![]),
            ]),
            diagnostic: Some("E_LOAN_DEF_REUSED"),
        },
        Case {
            id: "C18",
            program: branching(vec![
                block(0, vec![init(1, false, false)], vec![1, 2]),
                block(1, vec![Op::Move { from: 1, into: 2 }], vec![3]),
                block(2, vec![Op::Read { owner: 1 }], vec![3]),
                block(3, vec![Op::Return], vec![]),
            ]),
            diagnostic: Some("E_CFG_JOIN_UNPROVEN"),
        },
        Case {
            id: "C19",
            program: branching(vec![
                block(0, vec![init(1, false, false)], vec![1]),
                block(1, vec![Op::Read { owner: 1 }], vec![1]),
            ]),
            diagnostic: Some("E_CFG_CYCLE_UNPROVEN"),
        },
        case(
            "C21",
            vec![init(1, false, false), Op::Read { owner: 1 }],
            Some("E_IMPLICIT_EXIT"),
        ),
        case(
            "C22",
            vec![init(1, false, false), borrow(1, 10, Shared), Op::Return],
            Some("E_LOAN_ESCAPE"),
        ),
    ]
}

#[test]
fn canonical_rust_v0_agrees_on_all_21_representable_cases() {
    let cases = all_native_cases();
    assert_eq!(cases.len(), 21);
    let mut ids = std::collections::BTreeSet::new();
    for fixture in cases {
        assert!(ids.insert(fixture.id), "repeated case {}", fixture.id);
        match (verify(&fixture.program), fixture.diagnostic) {
            (Ok(_), None) => {}
            (Err(actual), Some(expected)) => {
                assert_eq!(actual.code, expected, "case {}", fixture.id);
            }
            (result, expected) => {
                panic!(
                    "case {} outcome {:?}, expected {:?}",
                    fixture.id, result, expected
                );
            }
        }
    }
    assert!(
        !ids.contains("C20"),
        "unknown-effect case belongs to MIR validation"
    );
}

// Test-only MIR wrapper for cross-checking the public verifier entrypoint.
// IDs are synthetic from the fixture; they DO NOT authenticate compiler
// provenance or represent independently enumerated source instructions.
fn model_envelope(program: &Program) -> MirFunction {
    let mut next = 1u64;
    let mut expected_instruction_ids = Vec::new();
    let mut blocks = Vec::new();
    for block in &program.blocks {
        let mut instructions = Vec::new();
        for operation in &block.operations {
            let id = next;
            next += 1;
            expected_instruction_ids.push(id);
            let effect = match operation {
                Op::Suspend => Effect::Suspension,
                Op::ActorHopBorrow { .. } => Effect::ActorBoundary,
                Op::Return => Effect::Control,
                _ => Effect::Ownership,
            };
            instructions.push(Instruction {
                instruction_id: id,
                source_node_id: id + 100,
                effect,
                operation: operation.clone(),
            });
        }
        blocks.push(MirBlock {
            id: block.id,
            instructions,
            successors: block.successors.clone(),
        });
    }
    MirFunction {
        version: CONTRACT_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 1,
        },
        entry: program.entry,
        expected_instruction_ids,
        blocks,
    }
}

#[test]
fn canonical_verifier_and_strict_mir_entrypoint_agree_on_representable_cases() {
    for fixture in all_native_cases() {
        let direct = verify(&fixture.program);
        let via_mir = verify_mir(&model_envelope(&fixture.program));
        match (direct, via_mir) {
            (Ok(left), Ok(right)) => {
                assert_eq!(left, right, "cleanup plan mismatch in {}", fixture.id);
            }
            (Err(left), Err(MirError::Unsafe(right))) => {
                assert_eq!(left, right, "diagnostic mismatch in {}", fixture.id);
            }
            (left, right) => {
                panic!(
                    "V0/MIR disagreed in {}: {:?} vs {:?}",
                    fixture.id, left, right
                );
            }
        }
    }
}

#[test]
fn c20_unknown_foreign_effect_is_rejected_by_real_mir_envelope() {
    let function = MirFunction {
        version: CONTRACT_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 1,
        },
        entry: 0,
        expected_instruction_ids: vec![1, 2, 3],
        blocks: vec![MirBlock {
            id: 0,
            instructions: vec![
                Instruction {
                    instruction_id: 1,
                    source_node_id: 11,
                    effect: Effect::Ownership,
                    operation: init(1, false, false),
                },
                // A frontend MUST label unmodeled FFI/unwind/cancel effects
                // Unsupported; it must never translate them into Nop.
                Instruction {
                    instruction_id: 2,
                    source_node_id: 12,
                    effect: Effect::Unsupported,
                    operation: Op::Read { owner: 1 },
                },
                Instruction {
                    instruction_id: 3,
                    source_node_id: 13,
                    effect: Effect::Control,
                    operation: Op::Return,
                },
            ],
            successors: vec![],
        }],
    };
    assert_eq!(
        verify_mir(&function),
        Err(MirError::Invalid("E_MIR_UNSUPPORTED_EFFECT"))
    );
}

#[test]
fn zero_evidence_cannot_be_called_a_compiler_emission_proof() {
    // This test asserts API scope rather than guest certification. An
    // internal model verdict is not evidence of true source/LLVM/CIL/CLIF
    // emission inventories, even when all native cases accept.
    assert_eq!(
        atto_borrow_checker::mir_v1::CONTRACT_VERSION,
        "atto-borrow-mir-v1"
    );
}

#[test]
fn cyclic_oracle_matches_llvm_fixed_point_loop_decisions() {
    use atto_borrow_checker::cyclic_v1::{
        check, Block as CyclicBlock, Code, Op as CyclicOp, Place, Program as CyclicProgram, Root,
    };

    let root = Place::root(1);
    let program = |body: CyclicOp| CyclicProgram {
        roots: vec![Root {
            id: 1,
            is_copy: false,
            is_transferable: false,
        }],
        blocks: vec![
            CyclicBlock {
                id: 0,
                ops: vec![],
                successors: vec![1],
            },
            CyclicBlock {
                id: 1,
                ops: vec![body],
                successors: vec![1, 2],
            },
            CyclicBlock {
                id: 2,
                ops: vec![CyclicOp::Read(root.clone())],
                successors: vec![],
            },
        ],
        entry: 0,
    };

    // The LLVM CFG verifier already accepts this stable read-only cycle.
    // Rust V0 rejects all cycles; cyclic_v1 is the proper future contract.
    let legal_loop = program(CyclicOp::Read(root.clone()));
    let proof = check(&legal_loop).expect("read-only cycle must reach a fixed point");
    assert_eq!(proof.reachable_blocks, 3);

    // Moving a value on the backedge makes a later read unsafe.
    let unsafe_loop = program(CyclicOp::Move(root.clone()));
    assert_eq!(check(&unsafe_loop).unwrap_err().code, Code::UseAfterMove);
}

#[test]
fn differential_v1_catalog_stays_synchronized_with_canonical_rust_cases() {
    use std::collections::BTreeMap;

    let mut rows = BTreeMap::new();
    for line in include_str!("../conformance/borrow-v1/cases.tsv").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "malformed differential catalog line");
        assert!(
            rows.insert(fields[0], (fields[1], fields[2], fields[3]))
                .is_none(),
            "duplicate differential fixture ID"
        );
    }

    let native = all_native_cases();
    assert_eq!(native.len(), 21);
    for fixture in native {
        let (profile, decision, diagnostic) = rows
            .remove(fixture.id)
            .expect("missing Rust fixture from differential catalog");
        assert_eq!(profile, "mir-v0-acyclic", "case {}", fixture.id);
        match fixture.diagnostic {
            None => {
                assert_eq!(
                    (decision, diagnostic),
                    ("allow", "-"),
                    "case {}",
                    fixture.id
                );
            }
            Some(code) => {
                assert_eq!(
                    (decision, diagnostic),
                    ("reject", code),
                    "case {}",
                    fixture.id
                );
            }
        }
    }
    let unknown_effect = ("mir-v1-envelope", "reject", "E_MIR_UNSUPPORTED_EFFECT");
    assert_eq!(
        rows.remove("C20"),
        Some(unknown_effect),
        "MIR unknown-effect failure must stay in the catalog"
    );
    assert!(rows.is_empty(), "unknown differential fixture IDs");
}
