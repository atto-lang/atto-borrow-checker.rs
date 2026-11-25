//! Source-free shared-domain cases for the singleton/symbol ownership target.
//! These test the existing Rust guard model, NOT compiler lowering, the
//! singleton grammar, symbol interning, or a native 32-bit actor heap.

use atto_borrow_checker::actor_state_guard_v1::{GuardError, GuardQueue, Mode};
use atto_borrow_checker::actor_state_runtime_v1::{GuardedActorRegion, RuntimeError};

#[test]
fn concurrent_readers_are_admitted_before_a_queued_writer() {
    let mut queue = GuardQueue::new(7).unwrap();
    let first = queue.request(11, 7, Mode::Read).unwrap();
    let second = queue.request(12, 7, Mode::Read).unwrap();
    let readers = queue.admit_ready();
    assert_eq!(readers.len(), 2);
    assert_eq!(readers[0].ticket(), first);
    assert_eq!(readers[1].ticket(), second);

    let writer_ticket = queue.request(13, 7, Mode::Write).unwrap();
    let later_reader_ticket = queue.request(14, 7, Mode::Read).unwrap();
    assert!(queue.admit_ready().is_empty(), "writer must not overtake live readers");
    assert_eq!(
        queue.access(&readers[0], 11, true),
        Err(GuardError::WriteRequiresExclusive)
    );
    assert_eq!(queue.access(&readers[1], 12, false), Ok(()));

    queue.release(&readers[0], 11).unwrap();
    assert!(queue.admit_ready().is_empty());
    queue.release(&readers[1], 12).unwrap();
    let writers = queue.admit_ready();
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].ticket(), writer_ticket);
    assert_eq!(queue.access(&writers[0], 13, true), Ok(()));
    assert!(queue.admit_ready().is_empty(), "reader may not overtake writer");

    queue.release(&writers[0], 13).unwrap();
    let late_readers = queue.admit_ready();
    assert_eq!(late_readers.len(), 1);
    assert_eq!(late_readers[0].ticket(), later_reader_ticket);
    queue.release(&late_readers[0], 14).unwrap();
    assert_eq!(queue.active_count(), 0);
}

#[test]
fn same_numeric_actor_and_ticket_do_not_authorize_foreign_region() {
    let mut first = GuardQueue::new(9).unwrap();
    let mut second = GuardQueue::new(9).unwrap();
    first.request(31, 9, Mode::Read).unwrap();
    second.request(31, 9, Mode::Read).unwrap();
    let first_scope = first.admit_ready().pop().unwrap();
    let second_scope = second.admit_ready().pop().unwrap();

    assert_eq!(
        second.access(&first_scope, 31, false),
        Err(GuardError::WrongRegion)
    );
    assert_eq!(
        first.access(&second_scope, 31, false),
        Err(GuardError::WrongRegion)
    );
    assert_eq!(
        first.access(&first_scope, 32, false),
        Err(GuardError::WrongHolder)
    );
    assert_eq!(first.access(&first_scope, 31, false), Ok(()));
    first.release(&first_scope, 31).unwrap();
    second.release(&second_scope, 31).unwrap();
    assert_eq!(
        first.access(&first_scope, 31, false),
        Err(GuardError::UnknownTicket)
    );
}

#[test]
fn retired_region_fences_stale_tokens_until_physical_release() {
    let mut queue = GuardQueue::new(21).unwrap();
    queue.request(41, 21, Mode::Read).unwrap();
    let scope = queue.admit_ready().pop().unwrap();
    queue.retire(22).unwrap();

    assert_eq!(
        queue.access(&scope, 41, false),
        Err(GuardError::StaleGeneration)
    );
    assert_eq!(
        queue.release(&scope, 41),
        Err(GuardError::PhysicalQuiescenceRequired)
    );
    assert!(!queue.may_reclaim(), "logical STOP is not physical quiescence");
    queue.complete_physical_quiescence(&scope, 41).unwrap();
    assert!(queue.may_reclaim());
    assert_eq!(queue.request(41, 22, Mode::Read), Err(GuardError::Retired));
}

#[test]
fn physical_shared_region_serializes_writer_after_reader_completions() {
    let region = GuardedActorRegion::new(3, 10_i64).unwrap();
    region.request(61, 3, Mode::Read).unwrap();
    region.request(62, 3, Mode::Read).unwrap();
    let mut readers = region.admit_ready().unwrap();
    assert_eq!(readers.len(), 2);
    region.request(63, 3, Mode::Write).unwrap();
    assert!(region.admit_ready().unwrap().is_empty());

    for scope in readers.drain(..) {
        let observed = region.execute_read(scope, |state| *state).unwrap();
        assert_eq!(observed, 10);
    }
    let mut writer = region.admit_ready().unwrap();
    assert_eq!(writer.len(), 1);
    region
        .execute_write(writer.pop().unwrap(), |state| *state += 1)
        .unwrap();
    region.request(64, 3, Mode::Read).unwrap();
    let reader = region.admit_ready().unwrap().pop().unwrap();
    assert_eq!(region.execute_read(reader, |state| *state).unwrap(), 11);
    assert_eq!(region.active_count().unwrap(), 0);
}

#[test]
fn physical_region_stop_never_exposes_a_stale_read_callback() {
    let region = GuardedActorRegion::new(5, vec![35_u8, 114, 101, 97, 100, 121]).unwrap();
    region.request(71, 5, Mode::Read).unwrap();
    let scope = region.admit_ready().unwrap().pop().unwrap();
    region.retire(6).unwrap();
    assert!(!region.may_reclaim().unwrap());

    let result: Result<(), RuntimeError> =
        region.execute_read(scope, |_| panic!("stale read callback executed"));
    assert_eq!(result, Err(RuntimeError::Guard(GuardError::StaleGeneration)));
    assert!(region.may_reclaim().unwrap(), "scope drop must retire physical loan");
}
