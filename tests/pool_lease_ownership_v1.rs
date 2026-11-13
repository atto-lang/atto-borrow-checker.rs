//! PoolLease semantic regression tests over the existing ownership CFG.
//! These tests prove compiler-model transfer/release discipline only.
//! They do not certify runtime ref32 backing, native I/O pins, or guest execution.
use atto_borrow_checker::{verify, Block, BorrowKind, Op, Program, Traits};

fn run(ops: Vec<Op>) -> Result<atto_borrow_checker::Proof, atto_borrow_checker::Diagnostic> {
    verify(&Program {
        entry: 0,
        blocks: vec![Block { id: 0, operations: ops, successors: vec![] }],
    })
}
fn init() -> Op {
    Op::Init { owner: 1, traits: Traits { is_copy: false, is_send: true } }
}
fn fail(ops: Vec<Op>, expected: &str) {
    assert_eq!(run(ops).unwrap_err().code, expected);
}

#[test]
fn pool_lease_cannot_recycle_while_a_read_loan_is_active() {
    fail(vec![
        init(),
        Op::Borrow { owner: 1, loan: 7, kind: BorrowKind::Shared },
        Op::Drop { owner: 1 },
        Op::Return,
    ], "E_BORROW_CONFLICT");
}
#[test]
fn pool_lease_cannot_recycle_while_mutably_borrowed() {
    fail(vec![
        init(),
        Op::Borrow { owner: 1, loan: 7, kind: BorrowKind::Mutable },
        Op::Drop { owner: 1 },
        Op::Return,
    ], "E_BORROW_CONFLICT");
}
#[test]
fn pool_lease_escrow_blocks_access_and_recycle() {
    for blocked in [Op::Read { owner: 1 }, Op::Write { owner: 1 },
                    Op::Drop { owner: 1 }, Op::ActorSendMove { owner: 1 }] {
        fail(vec![
            init(),
            Op::ActorSendPrepare { owner: 1, ticket: 9 },
            blocked,
            Op::ActorSendAbort { ticket: 9 },
            Op::Return,
        ], "E_ACTOR_SEND_PENDING");
    }
}
#[test]
fn pool_lease_cannot_prepare_transfer_with_outstanding_loan() {
    fail(vec![
        init(),
        Op::Borrow { owner: 1, loan: 7, kind: BorrowKind::Shared },
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::Return,
    ], "E_BORROW_CONFLICT");
}
#[test]
fn pool_lease_commit_consumes_sender_ownership() {
    assert!(run(vec![
        init(),
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::ActorSendCommit { ticket: 9 },
        Op::Return,
    ]).unwrap().cleanup_by_exit[&0].is_empty());
    fail(vec![
        init(),
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::ActorSendCommit { ticket: 9 },
        Op::Drop { owner: 1 },
        Op::Return,
    ], "E_USE_AFTER_MOVE_OR_DROP");
}
#[test]
fn pool_lease_abort_restores_exact_sender_owner() {
    let proof = run(vec![
        init(),
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::ActorSendAbort { ticket: 9 },
        Op::Write { owner: 1 },
        Op::Return,
    ]).unwrap();
    assert_eq!(proof.cleanup_by_exit[&0], vec![1]);
    assert!(run(vec![
        init(),
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::ActorSendAbort { ticket: 9 },
        Op::Drop { owner: 1 },
        Op::Return,
    ]).unwrap().cleanup_by_exit[&0].is_empty());
}
#[test]
fn pool_lease_rejects_double_settlement() {
    fail(vec![
        init(),
        Op::ActorSendPrepare { owner: 1, ticket: 9 },
        Op::ActorSendAbort { ticket: 9 },
        Op::ActorSendAbort { ticket: 9 },
        Op::Return,
    ], "E_UNKNOWN_ACTOR_SEND_TICKET");
}
