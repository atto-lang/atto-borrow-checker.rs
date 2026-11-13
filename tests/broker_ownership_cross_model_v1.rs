//! Independent Rust tests for broker-facing ownership rules shared across
//! Redis, Kafka, AMQP/RabbitMQ and NATS. Model-only: no real guest heap,
//! compiler lowering, epoll/io_uring, or native broker benchmark is implied.
use atto_borrow_checker::{verify, Block, Op, Program, Traits, BorrowKind};
use atto_borrow_checker::actor_arena_ref32_v1::{ActorArenaRef32, Ref32Error};
use atto_borrow_checker::actor_state_guard_v1::{GuardQueue, GuardError, Mode};

fn owned() -> Op {
    Op::Init { owner: 1, traits: Traits { is_copy: false, is_send: true } }
}
fn check(operations: Vec<Op>) -> Result<atto_borrow_checker::Proof, atto_borrow_checker::Diagnostic> {
    verify(&Program { entry: 0, blocks: vec![Block {
        id: 0, operations, successors: vec![]
    }] })
}
fn denied(operations: Vec<Op>, code: &str) {
    assert_eq!(check(operations).unwrap_err().code, code);
}

#[test]
fn broker_mailbox_escrow_cannot_be_read_while_admission_is_pending() {
    denied(vec![
        owned(), Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::Read { owner: 1 }, Op::Return
    ], "E_ACTOR_SEND_PENDING");
    let proof = check(vec![
        owned(), Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendAbort { ticket: 7 }, Op::Read { owner: 1 }, Op::Return
    ]).expect("failed mailbox admission restores sender");
    assert_eq!(proof.cleanup_by_exit[&0], vec![1]);
}

#[test]
fn committed_mailbox_move_never_restores_sender_or_allows_replay() {
    let proof = check(vec![
        owned(), Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendCommit { ticket: 7 }, Op::Return
    ]).expect("one admitted owner transfers once");
    assert!(proof.cleanup_by_exit[&0].is_empty());
    denied(vec![
        owned(), Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendCommit { ticket: 7 },
        Op::Read { owner: 1 }, Op::Return
    ], "E_USE_AFTER_MOVE_OR_DROP");
    assert!(check(vec![
        owned(), Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendCommit { ticket: 7 },
        Op::ActorSendCommit { ticket: 7 }, Op::Return
    ]).is_err(), "duplicate commit must fail closed");
}

#[test]
fn actor_owned_ref32_never_authorizes_cross_actor_memory() {
    let mut a = ActorArenaRef32::new(1, 100, 1024).unwrap();
    let mut b = ActorArenaRef32::new(2, 100, 1024).unwrap();
    let ar = a.allocate(16, 8).unwrap();
    let br = b.allocate(16, 8).unwrap();
    assert_ne!(ar.offset(), 0);
    assert_eq!(a.checked_offset(ar, 1, 100, 0, 8, 8), Ok(ar.offset()));
    assert_eq!(a.checked_offset(ar, 2, 100, 0, 8, 8), Err(Ref32Error::WrongActor));
    assert_eq!(b.checked_offset(ar, 2, 100, 0, 8, 8), Err(Ref32Error::WrongActor));
    assert_eq!(a.checked_offset(br, 1, 100, 0, 8, 8), Err(Ref32Error::WrongActor));
    assert_eq!(a.checked_offset(ar, 1, 100, 12, 8, 1), Err(Ref32Error::OutOfBounds));
    a.retire(101).unwrap();
    assert_eq!(a.checked_offset(ar, 1, 101, 0, 8, 8), Err(Ref32Error::Retired));
    // The other actor has its own valid arena even after this STOP generation.
    assert_eq!(b.checked_offset(br, 2, 100, 0, 8, 8), Ok(br.offset()));
}

#[test]
fn shared_actor_region_requires_fifo_reader_writer_admission_and_stop_quiescence() {
    let mut region = GuardQueue::new(7).unwrap();
    region.request(1, 7, Mode::Read).unwrap();
    region.request(2, 7, Mode::Read).unwrap();
    let read_guards = region.admit_ready();
    assert_eq!(read_guards.len(), 2);
    region.request(3, 7, Mode::Write).unwrap();
    region.request(4, 7, Mode::Read).unwrap();
    assert!(region.admit_ready().is_empty(), "queued writer may not be bypassed");
    for (actor, permit) in [(1, &read_guards[0]), (2, &read_guards[1])] {
        assert_eq!(region.access(permit, actor, false), Ok(()));
        assert_eq!(region.access(permit, actor, true), Err(GuardError::WriteRequiresExclusive));
        region.release(permit, actor).unwrap();
    }
    let writer = region.admit_ready();
    assert_eq!(writer.len(), 1);
    assert_eq!(writer[0].actor(), 3);
    assert_eq!(region.access(&writer[0], 3, true), Ok(()));
    assert!(region.admit_ready().is_empty());
    region.retire(8).unwrap();
    assert_eq!(region.access(&writer[0], 3, true), Err(GuardError::StaleGeneration));
    assert!(!region.may_reclaim());
    assert_eq!(region.release(&writer[0], 3), Err(GuardError::PhysicalQuiescenceRequired));
    region.complete_physical_quiescence(&writer[0], 3).unwrap();
    assert!(region.may_reclaim());
    assert!(region.admit_ready().is_empty(), "STOP must cancel queued reader");
}

#[test]
fn raw_borrow_cannot_cross_actor_or_suspension_boundary() {
    denied(vec![
        owned(), Op::Borrow { owner: 1, loan: 9, kind: BorrowKind::Shared },
        Op::Suspend, Op::Return
    ], "E_SUSPEND_WITH_LIVE_LOAN");
    denied(vec![owned(), Op::ActorHopBorrow { owner: 1 }, Op::Return],
        "E_ACTOR_BORROW_ESCAPE");
}
