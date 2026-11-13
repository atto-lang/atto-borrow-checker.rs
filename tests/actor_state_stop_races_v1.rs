use atto_borrow_checker::actor_state_guard_v1::{GuardError, Mode};
use atto_borrow_checker::actor_state_runtime_v1::{GuardedActorRegion, RuntimeError};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

/// STOP is a logical fence, not permission to reclaim actor-owned memory
/// while a writer is still physically executing its critical callback.
#[test]
fn stop_waits_for_physical_writer_exit_and_discards_queued_readers() {
    let region = GuardedActorRegion::new(10, 0_i64).unwrap();
    region.request(101, 10, Mode::Write).unwrap();
    let writer = region.admit_ready().unwrap().pop().unwrap();
    region.request(202, 10, Mode::Read).unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_region = region.clone();
    let worker = thread::spawn(move || {
        worker_region.execute_write(writer, |state| {
            *state = 41;
            entered_tx.send(()).unwrap();
            // The test never assumes a sleep proves that a callback entered.
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            *state += 1;
            *state
        })
    });

    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(
        region.request(101, 10, Mode::Read),
        Err(RuntimeError::Guard(GuardError::Reentrant)),
        "the same actor must not acquire another state loan during its turn"
    );
    assert!(region.admit_ready().unwrap().is_empty());
    assert_eq!(region.active_count(), Ok(1));
    assert_eq!(region.waiting_count(), Ok(1));

    // STOP must complete without waiting on the physical write lock.
    region.retire(11).unwrap();
    assert_eq!(region.active_count(), Ok(1));
    assert_eq!(region.waiting_count(), Ok(0));
    assert_eq!(region.may_reclaim(), Ok(false));
    assert_eq!(
        region.request(303, 10, Mode::Read),
        Err(RuntimeError::Guard(GuardError::StaleGeneration))
    );
    assert_eq!(
        region.request(303, 11, Mode::Read),
        Err(RuntimeError::Guard(GuardError::Retired))
    );

    release_tx.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), Ok(42));
    assert_eq!(region.active_count(), Ok(0));
    assert_eq!(region.may_reclaim(), Ok(true));
    assert!(region.admit_ready().unwrap().is_empty());
}

/// A reader callback can unwind without poisoning an immutable RwLock loan.
/// Its deferred completion must be drained before a following writer enters.
#[test]
fn panicking_reader_releases_only_its_scope_and_allows_following_writer() {
    let region = GuardedActorRegion::new(20, 7_i64).unwrap();
    region.request(1, 20, Mode::Read).unwrap();
    let reader = region.admit_ready().unwrap().pop().unwrap();
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), RuntimeError> = region.execute_read(reader, |_| {
            panic!("reader callback failure");
        });
    }));
    assert!(panicked.is_err());
    assert_eq!(region.active_count(), Ok(0));

    region.request(2, 20, Mode::Write).unwrap();
    let writer = region.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        region.execute_write(writer, |state| {
            *state += 35;
            *state
        }),
        Ok(42)
    );
    assert_eq!(region.active_count(), Ok(0));
    assert_eq!(region.waiting_count(), Ok(0));
}

/// Cancelling a granted-but-not-entered scope must not let a later writer
/// overtake an earlier queued writer, and actor IDs become reusable on exit.
#[test]
fn unused_granted_scope_releases_before_next_fifo_writer() {
    let region = GuardedActorRegion::new(30, 0_i64).unwrap();
    region.request(11, 30, Mode::Read).unwrap();
    let reader = region.admit_ready().unwrap().pop().unwrap();
    region.request(22, 30, Mode::Write).unwrap();
    region.request(33, 30, Mode::Read).unwrap();
    assert!(region.admit_ready().unwrap().is_empty());

    // The trusted host can cancel a scope that has never executed a callback.
    drop(reader);
    assert_eq!(region.active_count(), Ok(0));
    let writer = region.admit_ready().unwrap().pop().unwrap();
    assert!(region.admit_ready().unwrap().is_empty());
    assert_eq!(
        region.execute_write(writer, |value| {
            *value += 42;
            *value
        }),
        Ok(42)
    );

    let last_reader = region.admit_ready().unwrap().pop().unwrap();
    assert_eq!(region.execute_read(last_reader, |value| *value), Ok(42));
    // No old read permit survives to block a new incarnation of the actor.
    region.request(11, 30, Mode::Read).unwrap();
    let reused = region.admit_ready().unwrap().pop().unwrap();
    assert_eq!(region.execute_read(reused, |value| *value), Ok(42));
    assert_eq!(region.active_count(), Ok(0));
}

/// A burst of later readers must never starve an earlier queued writer.
/// Prove the initial reader actually holds the physical RwLock, rather than
/// relying on sleeps or just observing logical ticket counts.
#[test]
fn queued_writer_survives_a_burst_of_one_hundred_twenty_eight_later_readers() {
    let region = GuardedActorRegion::new(61, 0_i64).unwrap();
    region.request(1, 61, Mode::Read).unwrap();
    let first_reader = region.admit_ready().unwrap().pop().unwrap();

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_region = Arc::clone(&region);
    let first = thread::spawn(move || {
        worker_region.execute_read(first_reader, |value| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            *value
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    region.request(2, 61, Mode::Write).unwrap();
    for actor in 100_u64..228 {
        region.request(actor, 61, Mode::Read).unwrap();
    }
    assert_eq!(region.waiting_count(), Ok(129));
    assert_eq!(region.active_count(), Ok(1));
    assert!(region.admit_ready().unwrap().is_empty());

    release_tx.send(()).unwrap();
    assert_eq!(first.join().unwrap(), Ok(0));
    let writers = region.admit_ready().unwrap();
    assert_eq!(writers.len(), 1, "queued writer must be admitted first");
    assert_eq!(region.active_count(), Ok(1));
    assert!(region.admit_ready().unwrap().is_empty());
    assert_eq!(
        region.execute_write(writers.into_iter().next().unwrap(), |value| {
            *value = 42;
            *value
        }),
        Ok(42)
    );

    let readers = region.admit_ready().unwrap();
    assert_eq!(readers.len(), 128, "all later readers must follow writer");
    for reader in readers {
        assert_eq!(region.execute_read(reader, |value| *value), Ok(42));
    }
    assert_eq!(region.active_count(), Ok(0));
    assert_eq!(region.waiting_count(), Ok(0));
}
