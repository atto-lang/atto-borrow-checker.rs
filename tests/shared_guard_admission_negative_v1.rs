//! Fail-closed logical shared-region admission regressions.
//!
//! These are host-only Rust tests. They never establish AttoLang guest actor
//! isolation, symbol interning, protected ref32 or backend native parity.

use atto_borrow_checker::actor_state_guard_v1::{GuardError, GuardQueue, Mode};

#[test]
fn cancellation_rejects_wrong_holder_and_keeps_fifo_writer_barrier() {
    let mut queue = GuardQueue::new(7).unwrap();
    queue.request(11, 7, Mode::Read).unwrap();
    let first = queue.admit_ready().pop().unwrap();
    let writer_ticket = queue.request(12, 7, Mode::Write).unwrap();
    let later_reader = queue.request(13, 7, Mode::Read).unwrap();

    assert_eq!(
        queue.cancel_pending(writer_ticket, 13, 7),
        Err(GuardError::WrongHolder)
    );
    assert!(queue.admit_ready().is_empty(), "queued writer fences later reads");
    assert_eq!(queue.waiting_count(), 2);

    queue.cancel_pending(writer_ticket, 12, 7).unwrap();
    assert_eq!(
        queue.cancel_pending(writer_ticket, 12, 7),
        Err(GuardError::UnknownTicket),
        "a cancelled ticket is one-use and cannot be replayed"
    );
    let readers = queue.admit_ready();
    assert_eq!(readers.len(), 1);
    assert_eq!(readers[0].ticket(), later_reader);
    assert_eq!(queue.access(&readers[0], 13, true), Err(GuardError::WriteRequiresExclusive));
    queue.release(&first, 11).unwrap();
    queue.release(&readers[0], 13).unwrap();
    assert_eq!(queue.waiting_count(), 0);
    assert_eq!(queue.active_count(), 0);
}

#[test]
fn a_single_holder_cannot_acquire_a_second_scope_before_release() {
    let mut queue = GuardQueue::new(8).unwrap();
    queue.request(21, 8, Mode::Read).unwrap();
    assert_eq!(queue.request(21, 8, Mode::Write), Err(GuardError::Reentrant));
    let scope = queue.admit_ready().pop().unwrap();
    assert_eq!(queue.request(21, 8, Mode::Read), Err(GuardError::Reentrant));
    queue.release(&scope, 21).unwrap();

    let write_ticket = queue.request(21, 8, Mode::Write).unwrap();
    let writer = queue.admit_ready().pop().unwrap();
    assert_eq!(writer.ticket(), write_ticket);
    assert_eq!(queue.access(&writer, 21, true), Ok(()));
    queue.release(&writer, 21).unwrap();
}

#[test]
fn trusted_quiescence_rejects_foreign_permit_even_when_ids_match() {
    let mut first = GuardQueue::new(5).unwrap();
    let mut second = GuardQueue::new(5).unwrap();
    first.request(31, 5, Mode::Read).unwrap();
    second.request(31, 5, Mode::Read).unwrap();
    let first_permit = first.admit_ready().pop().unwrap();
    let second_permit = second.admit_ready().pop().unwrap();

    first.retire(6).unwrap();
    assert_eq!(
        first.complete_physical_quiescence(&second_permit, 31),
        Err(GuardError::WrongRegion)
    );
    assert_eq!(
        first.complete_physical_quiescence(&first_permit, 32),
        Err(GuardError::WrongHolder)
    );
    assert!(!first.may_reclaim());
    second.release(&second_permit, 31).unwrap();
    first.complete_physical_quiescence(&first_permit, 31).unwrap();
    assert!(first.may_reclaim());
}

#[test]
fn stop_drops_queued_requests_without_releasing_live_physical_scope() {
    let mut queue = GuardQueue::new(15).unwrap();
    queue.request(41, 15, Mode::Read).unwrap();
    let scope = queue.admit_ready().pop().unwrap();
    let queued = queue.request(42, 15, Mode::Write).unwrap();
    queue.retire(16).unwrap();

    assert_eq!(queue.waiting_count(), 0);
    assert!(queue.admit_ready().is_empty());
    assert_eq!(
        queue.cancel_pending(queued, 42, 16),
        Err(GuardError::Retired)
    );
    assert_eq!(
        queue.access(&scope, 41, false),
        Err(GuardError::StaleGeneration)
    );
    assert!(!queue.may_reclaim());
    queue.complete_physical_quiescence(&scope, 41).unwrap();
    assert!(queue.may_reclaim());
    assert_eq!(
        queue.request(43, 16, Mode::Read),
        Err(GuardError::Retired)
    );
}
