use atto_borrow_checker::typestate_v1::*;

fn resource(name: &str, policy: Cleanup) -> Protocol {
    Protocol {
        id: 1,
        name: name.into(),
        states: vec![
            State { id: 0, name: "Open".into(), cleanup: policy },
            State { id: 1, name: "Closed".into(), cleanup: Cleanup::Inert },
        ],
        methods: vec![
            Method { name: "send".into(), from: vec![0], to: None, access: Access::Read, suspends: false },
            Method { name: "close".into(), from: vec![0], to: Some(1), access: Access::Exclusive, suspends: false },
            Method { name: "is_closed".into(), from: vec![0, 1], to: None, access: Access::Read, suspends: false },
        ],
    }
}

fn init() -> Op { Op::Init { place: 1, protocol: 1, state: 0 } }
fn call(place: PlaceId, method: &str) -> Op {
    match method {
        "close" => Op::CallMut { place, method: method.into() },
        _ => Op::Call { place, method: method.into() },
    }
}
fn program(ops: Vec<Op>) -> Program {
    Program { suspending: false, entry: 0, protocols: vec![resource("File", Cleanup::VerifiedDestructor)],
        blocks: vec![Block { id: 0, ops, successors: vec![] }] }
}
fn fails(p: Program, code: &str) {
    let actual = verify(&p).expect_err("unsafe resource program passed");
    assert_eq!(actual.code, code, "{actual:?}");
}

#[test]
fn open_send_close_and_return_is_valid_without_runtime_state_tests() {
    let p = program(vec![init(), call(1, "send"), call(1, "close"), Op::Return]);
    assert_eq!(verify(&p).unwrap(), Proof { verified_blocks: 1, verified_operations: 4 });
}
#[test]
fn readonly_owner_cannot_call_state_changing_method() {
    fails(program(vec![init(), Op::Call { place: 1, method: "close".into() }, Op::Return]),
        "E_TYPESTATE_MUT_BORROW_REQUIRED");
}

#[test]
fn double_close_is_rejected() {
    fails(program(vec![init(), call(1, "close"), call(1, "close"), Op::Return]), "E_TYPESTATE_ILLEGAL_OPERATION");
}
#[test]
fn send_after_close_and_use_before_init_are_rejected() {
    fails(program(vec![init(), call(1, "close"), call(1, "send"), Op::Return]), "E_TYPESTATE_ILLEGAL_OPERATION");
    fails(program(vec![call(1, "send"), Op::Return]), "E_TYPESTATE_NOT_LIVE");
}
#[test]
fn taking_handle_preserves_state_and_invalidates_sender() {
    let ops = vec![init(), Op::Take { from: 1, into: 2 }, call(2, "close"), Op::Return];
    assert!(verify(&program(ops)).is_ok());
    fails(program(vec![init(), Op::Take { from: 1, into: 2 }, call(1, "send"), Op::Return]), "E_TYPESTATE_NOT_LIVE");
    fails(program(vec![init(), Op::Take { from: 1, into: 1 }, Op::Return]), "E_TYPESTATE_ALIAS_TRANSFER");
    fails(program(vec![init(), Op::Init { place: 2, protocol: 1, state: 0 }, Op::Take { from: 1, into: 2 }, Op::Return]), "E_TYPESTATE_TARGET_LIVE");
}
#[test]
fn borrowed_resources_cannot_be_closed_dropped_or_taken() {
    let loan = Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Shared };
    fails(program(vec![init(), loan.clone(), call(1, "close"), Op::Return]), "E_TYPESTATE_LOAN_CONFLICT");
    fails(program(vec![init(), loan.clone(), Op::Drop { place: 1 }, Op::Return]), "E_TYPESTATE_LOAN_CONFLICT");
    fails(program(vec![init(), loan.clone(), Op::Take { from: 1, into: 2 }, Op::Return]), "E_TYPESTATE_LOAN_CONFLICT");
    fails(program(vec![init(), loan.clone(), Op::CallThrough { loan: 7, method: "close".into() }, Op::Return]), "E_TYPESTATE_MUT_BORROW_REQUIRED");
    assert!(verify(&program(vec![init(), loan, Op::CallThrough { loan: 7, method: "send".into() }, Op::EndBorrow { loan: 7 }, call(1, "close"), Op::Return])).is_ok());
}
#[test]
fn exclusive_mutable_loan_can_transition_and_must_end() {
    let ops = vec![init(), Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Mutable },
        Op::CallThrough { loan: 7, method: "close".into() }, Op::EndBorrow { loan: 7 }, Op::Return];
    assert!(verify(&program(ops)).is_ok());
    fails(program(vec![init(), Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Mutable },
        Op::Borrow { place: 1, loan: 8, kind: BorrowKind::Shared }, Op::Return]), "E_TYPESTATE_LOAN_CONFLICT");
    fails(program(vec![init(), Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Mutable }, Op::Return]), "E_TYPESTATE_LOAN_ESCAPE");
}
#[test]
fn transactions_and_builders_require_explicit_terminal_transition() {
    let mut p = program(vec![init(), Op::Return]);
    p.protocols[0] = resource("Transaction", Cleanup::ExplicitTransition);
    fails(p.clone(), "E_TYPESTATE_INCOMPLETE");
    p.blocks[0].ops = vec![init(), Op::Drop { place: 1 }, Op::Return];
    fails(p.clone(), "E_TYPESTATE_INCOMPLETE");
    p.blocks[0].ops = vec![init(), call(1, "close"), Op::Drop { place: 1 }, Op::Return];
    assert!(verify(&p).is_ok());
}
#[test]
fn verified_destructor_and_closed_state_allow_cleanup() {
    assert!(verify(&program(vec![init(), Op::Return])).is_ok());
    assert!(verify(&program(vec![init(), Op::Drop { place: 1 }, Op::Return])).is_ok());
    fails(program(vec![init(), Op::Drop { place: 1 }, Op::Drop { place: 1 }, Op::Return]), "E_TYPESTATE_NOT_LIVE");
    let mut p = program(vec![init(), Op::Return]);
    p.protocols[0].states[0].cleanup = Cleanup::ExplicitTransition;
    fails(p, "E_TYPESTATE_INCOMPLETE");
}
#[test]
fn join_of_open_and_closed_blocks_illegal_send_but_common_read_passes() {
    let mut p = program(vec![]);
    p.blocks = vec![
        Block { id: 0, ops: vec![init()], successors: vec![1, 2] },
        Block { id: 1, ops: vec![call(1, "close")], successors: vec![3] },
        Block { id: 2, ops: vec![], successors: vec![3] },
        Block { id: 3, ops: vec![call(1, "is_closed"), Op::Return], successors: vec![] },
    ];
    assert!(verify(&p).is_ok());
    p.blocks[3].ops[0] = call(1, "send");
    fails(p, "E_TYPESTATE_ILLEGAL_OPERATION");
}
#[test]
fn conditional_initialization_not_definite_at_join() {
    let mut p = program(vec![]);
    p.blocks = vec![
        Block { id: 0, ops: vec![], successors: vec![1, 2] },
        Block { id: 1, ops: vec![init()], successors: vec![3] },
        Block { id: 2, ops: vec![], successors: vec![3] },
        Block { id: 3, ops: vec![call(1, "send"), Op::Return], successors: vec![] },
    ];
    fails(p, "E_TYPESTATE_NOT_LIVE");
}
#[test]
fn divergent_live_loans_fail_closed() {
    let mut p = program(vec![]);
    p.blocks = vec![
        Block { id: 0, ops: vec![init()], successors: vec![1, 2] },
        Block { id: 1, ops: vec![Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Shared }], successors: vec![3] },
        Block { id: 2, ops: vec![], successors: vec![3] },
        Block { id: 3, ops: vec![Op::Return], successors: vec![] },
    ];
    fails(p, "E_TYPESTATE_LOAN_JOIN");
}
#[test]
fn cycles_and_hidden_exits_fail_closed() {
    let mut p = program(vec![init()]);
    fails(p.clone(), "E_TYPESTATE_IMPLICIT_EXIT");
    p.blocks[0].successors = vec![0];
    fails(p, "E_TYPESTATE_CFG_CYCLE");
}
#[test]
fn malformed_protocols_or_unregistered_method_fail_closed() {
    let mut p = program(vec![init(), Op::Return]);
    p.protocols[0].methods[1].access = Access::Read;
    fails(p, "E_TYPESTATE_INVALID_PROTOCOL");
    fails(program(vec![init(), call(1, "magically_reopen"), Op::Return]), "E_TYPESTATE_UNKNOWN_METHOD");
    let mut p = program(vec![init(), Op::Return]);
    p.protocols[0].states[1].id = 0;
    fails(p, "E_TYPESTATE_INVALID_PROTOCOL");
}
#[test]
fn loan_identity_and_resource_budget_are_checked() {
    let mut p = program(vec![init(), Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Shared },
        Op::EndBorrow { loan: 7 }, Op::Borrow { place: 1, loan: 7, kind: BorrowKind::Shared }, Op::Return]);
    fails(p.clone(), "E_TYPESTATE_LOAN_ID");
    p.blocks[0].ops = (1..=65).map(|place| Op::Init { place, protocol: 1, state: 0 }).chain([Op::Return]).collect();
    fails(p, "E_TYPESTATE_PLACE_BUDGET");
}

/// A source compiler must never lower a suspending I/O method as plain Call.
#[test]
fn async_io_requires_await_and_susp_callable_context() {
    let mut p = program(vec![init(), call(1, "send"), Op::Return]);
    p.protocols[0].methods[0].suspends = true;
    fails(p.clone(), "E_TYPESTATE_AWAIT_REQUIRED");

    p.blocks[0].ops[1] = Op::AwaitCall { place: 1, method: "send".into() };
    fails(p.clone(), "E_TYPESTATE_AWAIT_CONTEXT");
    p.suspending = true;
    assert!(verify(&p).is_ok(), "awaited state-preserving I/O can retain owner");

    p.protocols[0].methods[0].suspends = false;
    fails(p, "E_TYPESTATE_NOT_SUSPENDING");
}

#[test]
fn await_preserves_live_owner_but_rejects_unsafe_loan() {
    let mut p = program(vec![init(), Op::Suspend, call(1, "send"), Op::Return]);
    p.suspending = true;
    assert!(verify(&p).is_ok(), "suspension must not consume or close the owner");

    p.blocks[0].ops.insert(1, Op::Borrow { place: 1, loan: 1, kind: BorrowKind::Shared });
    fails(p.clone(), "E_TYPESTATE_SUSPEND_LOAN");
    // Only a fully ended loan can precede the independent suspension.
    p.blocks[0].ops = vec![init(),
        Op::Borrow { place: 1, loan: 1, kind: BorrowKind::Shared },
        Op::EndBorrow { loan: 1 }, Op::Suspend, call(1, "send"), Op::Return];
    assert!(verify(&p).is_ok());
}

#[test]
fn async_close_cannot_pretend_success_without_pending_ownership_model() {
    let mut p = program(vec![init(), Op::AwaitCallMut { place: 1, method: "close".into() }, Op::Return]);
    p.suspending = true;
    p.protocols[0].methods[1].suspends = true;
    fails(p.clone(), "E_TYPESTATE_ASYNC_TRANSITION_UNSUPPORTED");
    p.blocks[0].ops[1] = call(1, "close");
    fails(p, "E_TYPESTATE_AWAIT_REQUIRED");
}

#[test]
fn suspended_program_cannot_reuse_owner_after_explicit_transfer() {
    let mut p = program(vec![init(), Op::Take { from: 1, into: 2 },
        Op::Suspend, call(1, "send"), Op::Return]);
    p.suspending = true;
    fails(p, "E_TYPESTATE_NOT_LIVE");
}
