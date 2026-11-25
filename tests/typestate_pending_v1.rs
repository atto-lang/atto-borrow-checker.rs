//! Host-only pending-resource ownership oracle tests. These do NOT certify
//! runtime cancellation, asynchronous OS handles, or guest AOT execution.
use atto_borrow_checker::typestate_v1::*;

fn file_protocol() -> Protocol {
    Protocol {
        id: 9,
        name: "File".into(),
        states: vec![
            State {
                id: 0,
                name: "Open".into(),
                cleanup: Cleanup::VerifiedDestructor,
            },
            State {
                id: 1,
                name: "Closed".into(),
                cleanup: Cleanup::Inert,
            },
            State {
                id: 2,
                name: "Indeterminate".into(),
                cleanup: Cleanup::ExplicitTransition,
            },
        ],
        methods: vec![
            Method {
                name: "close".into(),
                from: vec![0],
                to: Some(1),
                access: Access::Exclusive,
                suspends: true,
                async_outcomes: Some(AsyncOutcomes {
                    on_error: 0,
                    on_timeout: 2,
                    on_cancel: 2,
                }),
            },
            Method {
                name: "read".into(),
                from: vec![0],
                to: None,
                access: Access::Read,
                suspends: false,
                async_outcomes: None,
            },
            Method {
                name: "is_closed".into(),
                from: vec![0, 1, 2],
                to: None,
                access: Access::Read,
                suspends: false,
                async_outcomes: None,
            },
        ],
    }
}

fn init(place: PlaceId) -> Op {
    Op::Init {
        place,
        protocol: 9,
        state: 0,
    }
}
fn begin() -> Op {
    Op::BeginAsync {
        from: 1,
        pending: 42,
        method: "close".into(),
    }
}
fn await_close() -> Op {
    Op::AwaitPending {
        pending: 42,
        into: 2,
    }
}
fn read(place: PlaceId) -> Op {
    Op::Call {
        place,
        method: "read".into(),
    }
}
fn branches() -> Program {
    Program {
        entry: 0,
        suspending: true,
        protocols: vec![file_protocol()],
        blocks: vec![
            Block {
                id: 0,
                ops: vec![init(1), begin(), await_close()],
                successors: vec![1, 2, 3, 4],
            },
            Block {
                id: 1,
                ops: vec![Op::Return],
                successors: vec![],
            },
            Block {
                id: 2,
                ops: vec![Op::Return],
                successors: vec![],
            },
            Block {
                id: 3,
                ops: vec![Op::Return],
                successors: vec![],
            },
            Block {
                id: 4,
                ops: vec![Op::Return],
                successors: vec![],
            },
        ],
    }
}
fn error(program: Program, expected: &str) {
    let err = verify(&program).expect_err("unverified transition must fail");
    assert_eq!(err.code, expected, "{err:?}");
}
fn rollback_contract(mut p: Program) -> Program {
    // This is a SYNTHETIC all-or-nothing failure contract in the host model.
    // Real I/O must independently prove it, including timeout/cancel races.
    let c = p.protocols[0].methods[0].async_outcomes.as_mut().unwrap();
    c.on_error = 0;
    c.on_timeout = 0;
    c.on_cancel = 0;
    p
}

#[test]
fn cancellation_and_timeout_cannot_discard_indeterminate_resources() {
    error(branches(), "E_TYPESTATE_INCOMPLETE");
}

#[test]
fn authenticated_atomic_rollback_is_a_host_only_four_edge_positive() {
    let p = rollback_contract(branches());
    let proof = verify(&p).expect("synthetic four-way result split should be valid");
    assert_eq!(proof.verified_blocks, 5);
    assert_eq!(proof.verified_operations, 7);
}

#[test]
fn awaiting_consumes_old_owner_even_before_result_settlement() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(2, read(1));
    error(p, "E_TYPESTATE_NOT_LIVE");
}

#[test]
fn success_is_closed_but_failed_close_can_retain_open_handle() {
    let mut p = rollback_contract(branches());
    p.blocks[1].ops.insert(0, read(2));
    error(p, "E_TYPESTATE_ILLEGAL_OPERATION");
    let mut p = rollback_contract(branches());
    p.blocks[2].ops.insert(0, read(2));
    assert!(verify(&p).is_ok());
}

#[test]
fn outcome_settlement_never_resurrects_moved_original_place() {
    let mut p = rollback_contract(branches());
    p.blocks[2].ops.insert(0, read(1));
    error(p, "E_TYPESTATE_NOT_LIVE");
}

#[test]
fn pending_operation_cannot_escape_without_any_settlement() {
    let mut p = rollback_contract(branches());
    p.blocks = vec![Block {
        id: 0,
        ops: vec![init(1), begin(), Op::Return],
        successors: vec![],
    }];
    error(p, "E_TYPESTATE_PENDING_ESCAPE");
}

#[test]
fn outcome_branching_requires_exactly_four_distinct_successors() {
    let mut p = rollback_contract(branches());
    p.blocks[0].successors.pop();
    p.blocks.pop();
    error(p, "E_TYPESTATE_ASYNC_EDGE_SHAPE");

    let mut p = rollback_contract(branches());
    p.blocks[0].successors[3] = 1;
    error(p, "E_TYPESTATE_INVALID_CFG");
}

#[test]
fn only_known_live_pending_id_can_await() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops[2] = Op::AwaitPending {
        pending: 99,
        into: 2,
    };
    error(p, "E_TYPESTATE_UNKNOWN_PENDING");
}

#[test]
fn a_pending_id_is_unique_even_when_issued_from_disjoint_blocks() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(2, begin());
    error(p, "E_TYPESTATE_PENDING_ID");
}

#[test]
fn suspension_requires_a_suspending_caller_and_method() {
    let mut p = rollback_contract(branches());
    p.suspending = false;
    error(p, "E_TYPESTATE_AWAIT_CONTEXT");
    let mut p = rollback_contract(branches());
    p.protocols[0].methods[0].suspends = false;
    // This invalid combination (async outcomes on non-susp method) fails
    // protocol validation, not a forged synchronous fallback.
    error(p, "E_TYPESTATE_INVALID_PROTOCOL");
}

#[test]
fn held_loan_cannot_enter_async_escrow() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(
        1,
        Op::Borrow {
            place: 1,
            loan: 3,
            kind: BorrowKind::Shared,
        },
    );
    error(p, "E_TYPESTATE_SUSPEND_LOAN");
}

#[test]
fn invalid_or_missing_outcome_contracts_are_rejected() {
    let mut p = rollback_contract(branches());
    p.protocols[0].methods[0].async_outcomes = None;
    error(p, "E_TYPESTATE_INVALID_PROTOCOL");
    let mut p = rollback_contract(branches());
    p.protocols[0].methods[0]
        .async_outcomes
        .as_mut()
        .unwrap()
        .on_cancel = 200;
    error(p, "E_TYPESTATE_INVALID_PROTOCOL");
}

#[test]
fn cannot_settle_into_an_existing_live_resource() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(1, init(2));
    error(p, "E_TYPESTATE_TARGET_LIVE");
}

#[test]
fn premature_drop_and_double_completion_cannot_consume_pending_escrow() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(2, Op::Drop { place: 1 });
    error(p, "E_TYPESTATE_NOT_LIVE");

    let mut p = rollback_contract(branches());
    p.blocks[1].ops = vec![Op::AwaitPending {
        pending: 42,
        into: 3,
    }];
    p.blocks[1].successors = vec![5, 6, 7, 8];
    p.blocks.extend((5..=8).map(|id| Block {
        id,
        ops: vec![Op::Return],
        successors: vec![],
    }));
    error(p, "E_TYPESTATE_UNKNOWN_PENDING");
}

#[test]
fn joined_success_error_states_allow_common_inspection_not_open_only_read() {
    let mut p = rollback_contract(branches());
    p.blocks[1].ops.clear();
    p.blocks[1].successors = vec![5];
    p.blocks[2].ops.clear();
    p.blocks[2].successors = vec![5];
    p.blocks.push(Block {
        id: 5,
        ops: vec![
            Op::Call {
                place: 2,
                method: "is_closed".into(),
            },
            Op::Return,
        ],
        successors: vec![],
    });
    assert!(verify(&p).is_ok());
    p.blocks.last_mut().unwrap().ops[0] = read(2);
    error(p, "E_TYPESTATE_ILLEGAL_OPERATION");
}

#[test]
fn unrelated_second_begin_is_denied_while_escrow_is_pending() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(
        2,
        Op::BeginAsync {
            from: 3,
            pending: 43,
            method: "close".into(),
        },
    );
    error(p, "E_TYPESTATE_PENDING_CONFLICT");
}

#[test]
fn cancellation_state_must_be_safe_independently_of_timeout_state() {
    let mut p = rollback_contract(branches());
    p.protocols[0].methods[0]
        .async_outcomes
        .as_mut()
        .unwrap()
        .on_cancel = 2;
    error(p, "E_TYPESTATE_INCOMPLETE");

    let mut p = rollback_contract(branches());
    p.protocols[0].methods[0]
        .async_outcomes
        .as_mut()
        .unwrap()
        .on_timeout = 2;
    error(p, "E_TYPESTATE_INCOMPLETE");
}

#[test]
fn async_begin_rejects_uninitialized_source_and_non_transition_method() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.remove(0);
    error(p, "E_TYPESTATE_NOT_LIVE");

    let mut p = rollback_contract(branches());
    p.blocks[0].ops[1] = Op::BeginAsync {
        from: 1,
        pending: 42,
        method: "read".into(),
    };
    error(p, "E_TYPESTATE_NOT_SUSPENDING");
}

#[test]
fn live_mutable_loan_is_not_a_cancellation_safe_async_authority() {
    let mut p = rollback_contract(branches());
    p.blocks[0].ops.insert(
        1,
        Op::Borrow {
            place: 1,
            loan: 7,
            kind: BorrowKind::Mutable,
        },
    );
    error(p, "E_TYPESTATE_SUSPEND_LOAN");
}
