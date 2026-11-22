//! Canonical source-model cases; actual Atto guest/runtime EOF not certified.
use atto_borrow_checker::actor_protocol_v1::*;
use std::collections::BTreeSet;

fn protocol() -> Protocol {
    Protocol {
        name:"Connection".into(), initial:"Disconnected".into(),
        states:BTreeSet::from(["Disconnected".into(),"Connected".into(),"Closed".into()]),
        terminal:BTreeSet::from(["Closed".into()]),
        transitions:vec![
            Transition { from:"Disconnected".into(), message:"Connect".into(), payload:Some("Config".into()),
                to:"Connected".into(), mode:Mode::Unary, response:"Ack".into() },
            Transition { from:"Disconnected".into(), message:"Close".into(), payload:None,
                to:"Closed".into(), mode:Mode::Unary, response:"Ack".into() },
            Transition { from:"Connected".into(), message:"Close".into(), payload:None,
                to:"Closed".into(), mode:Mode::Unary, response:"Ack".into() },
            Transition { from:"Connected".into(), message:"Subscribe".into(), payload:Some("Topic".into()),
                to:"Connected".into(), mode:Mode::Stream, response:"Event".into() },
        ],
    }
}
fn init() -> Op { Op::Init { place:1, protocol:"Connection".into() } }
fn connect(place:PlaceId,lease:LeaseId)->Op { Op::Begin {
    from:place, lease, message:"Connect".into(), payload:Some("Config".into()),
    mode:Mode::Unary, response:"Ack".into()
} }
fn stream(place:PlaceId,lease:LeaseId)->Op { Op::Begin {
    from:place, lease, message:"Subscribe".into(), payload:Some("Topic".into()),
    mode:Mode::Stream, response:"Event".into()
} }
fn close(place:PlaceId,lease:LeaseId)->Op { Op::Begin {
    from:place, lease, message:"Close".into(), payload:None, mode:Mode::Unary, response:"Ack".into()
} }
fn block(id:BlockId,ops:Vec<Op>,successors:&[BlockId])->Block {
    Block { id, ops, successors:successors.to_vec() }
}
fn ret(id:BlockId)->Block { block(id,vec![Op::Return],&[]) }
fn program(suspending:bool,blocks:Vec<Block>)->Program {
    Program { entry:0,suspending,protocols:vec![protocol()],blocks }
}
fn denied(p:Program,expected:&'static str) {
    assert_eq!(verify(&p).unwrap_err().code,expected);
}
fn one_request() -> Program {
    program(true,vec![
        block(0,vec![init(),connect(1,10),Op::AwaitUnary { lease:10,into:2 }],&[1,2,3,4]),
        block(1,vec![Op::ReturnHandle { place:2 },Op::Return],&[]),
        ret(2),ret(3),ret(4),
    ])
}
#[test]
fn unary_success_only_grants_next_state() {
    assert_eq!(verify(&one_request()).unwrap(),Proof { blocks:5,operations:8 });
    let mut forged=one_request();
    forged.blocks[2].ops.insert(0,Op::ReturnHandle { place:2 });
    denied(forged,"E_PROTOCOL_HANDLE_NOT_LIVE");
}
#[test]
fn stream_item_retains_lease_and_eof_grants_successor() {
    let good=program(true,vec![
        block(0,vec![init(),connect(1,10),Op::AwaitUnary { lease:10,into:2 }],&[1,2,3,4]),
        block(1,vec![stream(2,11),Op::AwaitStream { lease:11,into:3 }],&[5,6,7,8,9]),
        ret(2),ret(3),ret(4),
        block(5,vec![Op::CancelLease { lease:11 },Op::Return],&[]),
        block(6,vec![Op::ReturnHandle { place:3 },Op::Return],&[]),
        ret(7),ret(8),ret(9),
    ]);
    assert!(verify(&good).is_ok());
    let mut early=good;
    early.blocks[5].ops.insert(0,Op::ReturnHandle { place:3 });
    denied(early,"E_PROTOCOL_HANDLE_NOT_LIVE");
}
#[test]
fn leases_are_affine_and_cancel_cannot_issue_handle() {
    assert!(verify(&program(false,vec![block(0,vec![
        init(),connect(1,10),Op::CancelLease { lease:10 },Op::Return],&[])] )).is_ok());
    denied(program(false,vec![block(0,vec![
        init(),connect(1,10),Op::CancelLease { lease:10 },
        Op::CancelLease { lease:10 },Op::Return],&[])]),"E_PROTOCOL_LEASE_NOT_LIVE");
    denied(program(false,vec![block(0,vec![
        init(),connect(1,10),Op::Return],&[])]),"E_PROTOCOL_LEASE_ESCAPE");
}
#[test]
fn take_invalidates_source_and_copy_never_authorized() {
    denied(program(false,vec![block(0,vec![
        init(),Op::Copy { from:1,into:2 },Op::Return],&[])]),"E_PROTOCOL_AFFINE_COPY");
    denied(program(false,vec![block(0,vec![
        init(),Op::Take { from:1,into:2 },Op::ReturnHandle { place:1 },Op::Return],&[])]),
        "E_PROTOCOL_HANDLE_NOT_LIVE");
    let mut good=one_request();
    good.blocks[0].ops.insert(1,Op::Take { from:1,into:3 });
    if let Op::Begin { from, .. }=&mut good.blocks[0].ops[2] { *from=3; }
    assert!(verify(&good).is_ok());
}
#[test]
fn suspended_loans_and_mutating_borrowed_owners_are_rejected() {
    denied(program(false,vec![block(0,vec![
        init(),Op::Borrow { place:1,loan:7,kind:LoanKind::Read },
        connect(1,10),Op::Return],&[])]),"E_PROTOCOL_LOAN_CONFLICT");
    denied(program(true,vec![block(0,vec![
        init(),Op::Borrow { place:1,loan:7,kind:LoanKind::Exclusive },
        Op::Suspend,Op::Return],&[])]),"E_PROTOCOL_LOAN_ACROSS_AWAIT");
    let mut good=one_request();
    good.blocks[0].ops.insert(1,Op::Borrow { place:1,loan:7,kind:LoanKind::Read });
    good.blocks[0].ops.insert(2,Op::EndBorrow { loan:7 });
    assert!(verify(&good).is_ok());
}
#[test]
fn state_union_and_optional_owner_joins_are_rejected() {
    denied(program(false,vec![
        block(0,vec![init()],&[1,2]),
        block(1,vec![Op::Take { from:1,into:2 },Op::ReturnHandle { place:2 }],&[3]),
        block(2,vec![],&[3]),
        ret(3),
    ]),"E_PROTOCOL_HANDLE_ESCAPE");
    denied(program(false,vec![
        block(0,vec![init()],&[1,2]),
        block(1,vec![Op::Take { from:1,into:2 },Op::ReturnHandle { place:2 }],&[3]),
        block(2,vec![],&[3]),
        block(3,vec![connect(1,10),Op::CancelLease { lease:10 },Op::Return],&[]),
    ]),"E_PROTOCOL_HANDLE_NOT_LIVE");
}
#[test]
fn pending_and_loan_branch_identity_must_match() {
    denied(program(false,vec![
        block(0,vec![init()],&[1,2]),block(1,vec![connect(1,10)],&[3]),
        block(2,vec![],&[3]),ret(3),
    ]),"E_PROTOCOL_LEASE_JOIN");
    denied(program(false,vec![
        block(0,vec![init()],&[1,2]),
        block(1,vec![Op::Borrow { place:1,loan:7,kind:LoanKind::Read }],&[3]),
        block(2,vec![],&[3]),ret(3),
    ]),"E_PROTOCOL_LOAN_JOIN");
}
#[test]
fn errors_in_message_type_state_and_outcome_shape_fail_closed() {
    denied(program(false,vec![block(0,vec![init(),stream(1,10),Op::Return],&[])]),
        "E_PROTOCOL_ILLEGAL_MESSAGE_STATE");
    denied(program(false,vec![block(0,vec![init(),Op::Begin {
        from:1,lease:10,message:"Connect".into(),payload:Some("Config".into()),
        mode:Mode::Stream,response:"Ack".into() },Op::Return],&[])]),
        "E_PROTOCOL_RESPONSE_MODE");
    denied(program(false,vec![block(0,vec![init(),Op::Begin {
        from:1,lease:10,message:"Connect".into(),payload:Some("WRONG".into()),
        mode:Mode::Unary,response:"Ack".into() },Op::Return],&[])]),
        "E_PROTOCOL_MESSAGE_PAYLOAD");
    let mut bad=one_request();
    bad.blocks[0].successors.pop();
    bad.blocks.pop();
    denied(bad,"E_PROTOCOL_OUTCOME_SHAPE");
}
#[test]
fn terminal_release_requires_committed_success() {
    denied(program(false,vec![block(0,vec![
        init(),Op::DisposeTerminal { place:1 },Op::Return],&[])]),
        "E_PROTOCOL_NONTERMINAL_DISPOSE");
    let p=program(true,vec![
        block(0,vec![init(),close(1,10),Op::AwaitUnary { lease:10,into:2 }],&[1,2,3,4]),
        block(1,vec![Op::DisposeTerminal { place:2 },Op::Return],&[]),
        ret(2),ret(3),ret(4),
    ]);
    assert!(verify(&p).is_ok());
}
#[test]
fn cycles_unreachable_and_implicit_exit_denied() {
    denied(program(false,vec![block(0,vec![init()],&[1]),block(1,vec![],&[0])]),
        "E_PROTOCOL_CFG_CYCLE");
    denied(program(false,vec![block(0,vec![init()],&[])]),"E_PROTOCOL_IMPLICIT_EXIT");
    denied(program(false,vec![block(0,vec![init(),Op::Return],&[]),ret(1)]),
        "E_PROTOCOL_CFG_UNREACHABLE");
}
#[test]
fn single_result_abi_denies_multiple_returned_capabilities() {
    denied(program(false,vec![block(0,vec![
        init(),Op::Init { place:2,protocol:"Connection".into() },
        Op::ReturnHandle { place:1 },Op::ReturnHandle { place:2 },Op::Return
    ],&[])]),"E_PROTOCOL_MULTIPLE_RETURN_HANDLES");
}
#[test]
fn branch_join_requires_matching_returned_handle_count() {
    denied(program(false,vec![
        block(0,vec![init()],&[1,2]),
        block(1,vec![Op::ReturnHandle { place:1 }],&[3]),
        block(2,vec![],&[3]),ret(3),
    ]),"E_PROTOCOL_RETURN_JOIN");
}
#[test]
fn old_lease_after_move_and_unreturned_owner_denied() {
    denied(program(false,vec![block(0,vec![
        init(),connect(1,10),Op::MoveLease { from:10,into:11 },
        Op::CancelLease { lease:10 },Op::Return],&[])]),
        "E_PROTOCOL_LEASE_NOT_LIVE");
    denied(program(false,vec![block(0,vec![init(),Op::Return],&[])]),
        "E_PROTOCOL_HANDLE_ESCAPE");
}
