//! Source-free static lexical critical-scope checks. Not a runtime lock or
//! proof of compiled AttoLang guest semantics.
use atto_borrow_checker::mir_v1::{
    verify_mir, Effect, Instruction, MirBlock, MirError, MirFunction, Producer, CONTRACT_VERSION,
};
use atto_borrow_checker::{verify, verify_with_shadow_v0, Block, Op, Program};

fn linear(operations: Vec<Op>) -> Program {
    Program {
        entry: 1,
        blocks: vec![Block {
            id: 1,
            operations,
            successors: vec![],
        }],
    }
}

fn denied(operations: Vec<Op>, code: &str) {
    assert_eq!(verify(&linear(operations)).unwrap_err().code, code);
}

fn enter_read(scope: u32) -> Op {
    Op::CriticalReadEnter { state: 7, scope }
}

fn enter_write(scope: u32) -> Op {
    Op::CriticalWriteEnter { state: 7, scope }
}

#[test]
fn lexical_read_and_write_callbacks_admit_checked_access_only() {
    let program = linear(vec![
        enter_read(10),
        Op::CriticalReadAccess {
            state: 7,
            scope: 10,
        },
        Op::CriticalExit { scope: 10 },
        enter_write(11),
        Op::CriticalReadAccess {
            state: 7,
            scope: 11,
        },
        Op::CriticalWriteAccess {
            state: 7,
            scope: 11,
        },
        Op::CriticalExit { scope: 11 },
        Op::Return,
    ]);
    assert!(verify(&program).is_ok());
}

#[test]
fn write_from_read_scope_is_rejected() {
    denied(
        vec![
            enter_read(10),
            Op::CriticalWriteAccess {
                state: 7,
                scope: 10,
            },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_WRITE_REQUIRED",
    );
}

#[test]
fn unguarded_wrong_state_stale_scope_and_double_exit_fail_closed() {
    for op in [
        Op::CriticalReadAccess {
            state: 7,
            scope: 10,
        },
        Op::CriticalWriteAccess {
            state: 7,
            scope: 10,
        },
        Op::CriticalExit { scope: 10 },
    ] {
        denied(vec![op, Op::Return], "E_CRITICAL_SCOPE_REQUIRED");
    }
    denied(
        vec![
            enter_read(10),
            Op::CriticalReadAccess {
                state: 8,
                scope: 10,
            },
            Op::Return,
        ],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalReadAccess {
                state: 7,
                scope: 11,
            },
            Op::Return,
        ],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalExit { scope: 10 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
}

#[test]
fn no_nested_reentrant_critical_callbacks_in_restricted_v0() {
    denied(
        vec![
            enter_read(10),
            enter_read(11),
            Op::CriticalExit { scope: 11 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_REENTRANT",
    );
    denied(
        vec![
            enter_write(10),
            Op::CriticalReadEnter {
                state: 8,
                scope: 11,
            },
            Op::Return,
        ],
        "E_CRITICAL_REENTRANT",
    );
}

#[test]
fn suspend_actor_handoff_task_capture_and_generic_borrow_are_denied() {
    use atto_borrow_checker::Traits;
    let init = Op::Init {
        owner: 42,
        traits: Traits {
            is_copy: true,
            is_send: true,
        },
    };
    for op in [
        Op::Suspend,
        Op::ActorSendCopy { owner: 42 },
        Op::TaskCaptureCopy { owner: 42 },
        Op::Borrow {
            owner: 42,
            loan: 8,
            kind: atto_borrow_checker::BorrowKind::Shared,
        },
    ] {
        denied(
            vec![
                init.clone(),
                enter_read(10),
                op,
                Op::CriticalExit { scope: 10 },
                Op::Return,
            ],
            "E_CRITICAL_EFFECT_UNPROVEN",
        );
    }
}


#[test]
fn entry_denies_live_ordinary_loans_until_released() {
    use atto_borrow_checker::{BorrowKind, Traits};
    let init = Op::Init {
        owner: 42,
        traits: Traits {
            is_copy: true,
            is_send: true,
        },
    };
    for kind in [BorrowKind::Shared, BorrowKind::Mutable] {
        for enter in [enter_read(10), enter_write(10)] {
            let loan = Op::Borrow {
                owner: 42,
                loan: 8,
                kind,
            };
            denied(
                vec![
                    init.clone(),
                    loan.clone(),
                    enter.clone(),
                    Op::CriticalExit { scope: 10 },
                    Op::EndBorrow { loan: 8 },
                    Op::Return,
                ],
                "E_CRITICAL_PREEXISTING_LOAN",
            );
            assert!(
                verify(&linear(vec![
                    init.clone(),
                    loan,
                    Op::EndBorrow { loan: 8 },
                    enter,
                    Op::CriticalExit { scope: 10 },
                    Op::Return,
                ]))
                .is_ok()
            );
        }
    }
}

#[test]
fn entry_denies_pending_mailbox_send_until_commit_or_abort() {
    use atto_borrow_checker::Traits;
    let init = Op::Init {
        owner: 42,
        traits: Traits {
            is_copy: false,
            is_send: true,
        },
    };
    let prepare = Op::ActorSendPrepare {
        owner: 42,
        ticket: 9,
    };
    for enter in [enter_read(10), enter_write(10)] {
        denied(
            vec![
                init.clone(),
                prepare.clone(),
                enter.clone(),
                Op::CriticalExit { scope: 10 },
                Op::ActorSendAbort { ticket: 9 },
                Op::Return,
            ],
            "E_CRITICAL_PENDING_SEND",
        );
        for resolved in [
            Op::ActorSendAbort { ticket: 9 },
            Op::ActorSendCommit { ticket: 9 },
        ] {
            assert!(
                verify(&linear(vec![
                    init.clone(),
                    prepare.clone(),
                    resolved,
                    enter.clone(),
                    Op::CriticalExit { scope: 10 },
                    Op::Return,
                ]))
                .is_ok()
            );
        }
    }
}

#[test]
fn early_exit_and_unclosed_scope_are_not_proofs() {
    denied(
        vec![enter_write(10), Op::Return],
        "E_CRITICAL_SCOPE_ESCAPE",
    );
    denied(
        vec![enter_write(10), Op::CriticalExit { scope: 11 }, Op::Return],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
}

#[test]
fn zero_and_duplicate_state_scope_identifiers_fail_preflight() {
    denied(
        vec![
            Op::CriticalReadEnter {
                state: 0,
                scope: 10,
            },
            Op::Return,
        ],
        "E_CRITICAL_STATE_ID_ZERO",
    );
    denied(
        vec![enter_read(0), Op::Return],
        "E_CRITICAL_SCOPE_ID_ZERO",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalExit { scope: 10 },
            enter_write(10),
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_SCOPE_DEF_REUSED",
    );
}

#[test]
fn branches_require_safe_lexical_exits_and_reject_unmatched_joins() {
    let matched = Program {
        entry: 1,
        blocks: vec![
            Block {
                id: 1,
                operations: vec![enter_read(10)],
                successors: vec![2, 3],
            },
            Block {
                id: 2,
                operations: vec![Op::CriticalReadAccess {
                    state: 7,
                    scope: 10,
                }],
                successors: vec![4],
            },
            Block {
                id: 3,
                operations: vec![],
                successors: vec![4],
            },
            Block {
                id: 4,
                operations: vec![Op::CriticalExit { scope: 10 }, Op::Return],
                successors: vec![],
            },
        ],
    };
    assert!(verify(&matched).is_ok());
    let mut invalid = matched;
    invalid.blocks[2].operations.push(Op::CriticalExit { scope: 10 });
    assert_eq!(verify(&invalid).unwrap_err().code, "E_CFG_JOIN_UNPROVEN");
}


#[test]
fn detached_i64_snapshot_can_send_only_after_critical_exit() {
    let snapshot = Op::CriticalCopyI64 {
        state: 7,
        scope: 10,
        into: 42,
    };
    assert!(verify(&linear(vec![
        enter_read(10),
        snapshot.clone(),
        Op::CriticalExit { scope: 10 },
        Op::ActorSendCopy { owner: 42 },
        Op::Return,
    ])).is_ok());
    denied(
        vec![
            enter_read(10),
            snapshot,
            Op::ActorSendCopy { owner: 42 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_EFFECT_UNPROVEN",
    );
}

#[test]
fn detached_i64_snapshot_has_checked_provenance_and_unique_id() {
    denied(
        vec![Op::CriticalCopyI64 { state: 7, scope: 10, into: 42 }, Op::Return],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalCopyI64 { state: 8, scope: 10, into: 42 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_CRITICAL_SCOPE_REQUIRED",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalCopyI64 { state: 7, scope: 10, into: 0 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_OWNER_ID_ZERO",
    );
    denied(
        vec![
            enter_read(10),
            Op::CriticalCopyI64 { state: 7, scope: 10, into: 42 },
            Op::CriticalCopyI64 { state: 7, scope: 10, into: 42 },
            Op::CriticalExit { scope: 10 },
            Op::Return,
        ],
        "E_OWNER_DEF_REUSED",
    );
}

#[test]
fn shadow_remains_empty_after_late_critical_failure() {
    let program = linear(vec![
        enter_read(10),
        Op::CriticalReadAccess { state: 7, scope: 10 },
        Op::CriticalWriteAccess { state: 7, scope: 10 },
        Op::Return,
    ]);
    let mut events = Vec::new();
    assert!(verify_with_shadow_v0(&program, &mut |event| {
        events.push(event);
        Ok(())
    })
    .is_err());
    assert!(events.is_empty());
}

#[test]
fn typed_mir_requires_critical_region_effect_and_produces_lexical_proof() {
    let mk = |effect| MirFunction {
        version: CONTRACT_VERSION.to_string(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 1,
        },
        entry: 1,
        expected_instruction_ids: vec![1, 2, 3],
        blocks: vec![MirBlock {
            id: 1,
            successors: vec![],
            instructions: vec![
                Instruction {
                    instruction_id: 1,
                    source_node_id: 101,
                    effect,
                    operation: enter_read(10),
                },
                Instruction {
                    instruction_id: 2,
                    source_node_id: 102,
                    effect: Effect::CriticalRegion,
                    operation: Op::CriticalExit { scope: 10 },
                },
                Instruction {
                    instruction_id: 3,
                    source_node_id: 103,
                    effect: Effect::Control,
                    operation: Op::Return,
                },
            ],
        }],
    };
    assert_eq!(
        verify_mir(&mk(Effect::Ownership)),
        Err(MirError::Invalid("E_MIR_EFFECT_MISMATCH"))
    );
    assert!(verify_mir(&mk(Effect::CriticalRegion)).is_ok());
}
