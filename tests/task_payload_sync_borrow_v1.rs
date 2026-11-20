//! Source-spelling-independent reference oracle for typed task capture.
//! 'task<T>', 'await task<T>', 'sync task<T>', 'do task<T>', and
//! 'do sync task<T>' MUST share these exact MIR loan obligations.
//! This suite does not parse AttoLang or certify guest lifetime/TaskScope.
use atto_borrow_checker::{verify, Block, BorrowKind, Op, Program, Traits};

fn cfg(ops: Vec<Op>) -> Program {
    Program {
        entry: 0,
        blocks: vec![Block { id: 0, operations: ops, successors: vec![] }],
    }
}
fn owner(id: u32, copy: bool, send: bool) -> Op {
    Op::Init { owner: id, traits: Traits { is_copy: copy, is_send: send } }
}
fn error(ops: Vec<Op>) -> &'static str {
    verify(&cfg(ops)).expect_err("MIR must be rejected").code
}
#[test]
fn typed_task_payload_does_not_change_copy_send_capture_proof() {
    // For every task spelling, an independently copied Send value can be
    // read by the parent after capture. Only the payload *type* varies.
    let p = verify(&cfg(vec![
        owner(1, true, true),
        Op::TaskCaptureCopy { owner: 1 },
        Op::Read { owner: 1 },
        Op::Return,
    ]));
    assert!(p.is_ok(), "{p:?}");
}

#[test]
fn non_send_or_non_copy_task_capture_never_becomes_safe_via_sync() {
    for (copy, send) in [(false, true), (true, false), (false, false)] {
        assert_eq!(error(vec![
            owner(1, copy, send),
            Op::TaskCaptureCopy { owner: 1 },
            Op::Return,
        ]), "E_TASK_CAPTURE_PROOF");
    }
}

#[test]
fn owned_send_capture_consumes_parent_owner_for_all_task_forms() {
    assert_eq!(error(vec![
        owner(1, false, true),
        Op::TaskCaptureMove { owner: 1 },
        Op::Read { owner: 1 },
        Op::Return,
    ]), "E_USE_AFTER_MOVE_OR_DROP");
}

#[test]
fn moving_or_writing_under_live_loan_is_rejected_even_in_discarded_task() {
    assert_eq!(error(vec![
        owner(1, false, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::TaskCaptureMove { owner: 1 },
        Op::Return,
    ]), "E_BORROW_CONFLICT");
    assert_eq!(error(vec![
        owner(1, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Mutable },
        Op::TaskCaptureCopy { owner: 1 },
        Op::Return,
    ]), "E_BORROW_CONFLICT");
}

#[test]
fn sync_task_join_cannot_erase_live_borrow_at_suspension() {
    assert_eq!(error(vec![
        owner(1, false, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Suspend,
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]), "E_SUSPEND_WITH_LIVE_LOAN");
}

#[test]
fn loan_ends_before_join_then_suspend_is_accepted() {
    let p = verify(&cfg(vec![
        owner(1, false, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Read { owner: 1 },
        Op::EndBorrow { loan: 10 },
        Op::Suspend,
        Op::Return,
    ]));
    assert!(p.is_ok(), "{p:?}");
}

#[test]
fn cross_actor_borrow_never_becomes_send_from_task_sugar() {
    assert_eq!(error(vec![
        owner(1, false, true),
        Op::ActorHopBorrow { owner: 1 },
        Op::Return,
    ]), "E_ACTOR_BORROW_ESCAPE");
}
