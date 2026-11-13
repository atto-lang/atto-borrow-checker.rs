//! Source-free logical integration tests, not compiler guest/native heap proof.
use atto_borrow_checker::actor_arena_ref32_v1::Ref32Error;
use atto_borrow_checker::actor_ref32_guarded_v1::{
    GuardedRef32Arena, GuardedRef32Error, Ref32Access,
};
use atto_borrow_checker::actor_state_guard_v1::{GuardError, Mode};

fn seeded(owner: u64, generation: u64) -> GuardedRef32Arena {
    GuardedRef32Arena::new(owner, generation, 256).unwrap()
}

#[test]
fn seal_gate_rejects_early_admission_and_late_mutation() {
    let mut arena = seeded(11, 7);
    assert_eq!(
        arena.request(11, 7, Mode::Read),
        Err(GuardedRef32Error::Unsealed)
    );
    assert_eq!(
        arena.admit_ready().unwrap_err(),
        GuardedRef32Error::Unsealed
    );
    let first = arena.allocate_before_seal(16, 8).unwrap();
    assert_eq!(first.offset(), 8);
    arena.seal();
    assert_eq!(
        arena.allocate_before_seal(1, 1),
        Err(GuardedRef32Error::Sealed)
    );
    arena.request(11, 7, Mode::Read).unwrap();
    let permit = arena.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        arena.checked_offset(first, &permit, 11, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    arena.release(&permit, 11).unwrap();
}

#[test]
fn shared_readers_then_one_writer_then_late_reader_without_overtaking() {
    let mut arena = seeded(81, 3);
    let reference = arena.allocate_before_seal(32, 8).unwrap();
    arena.seal();

    let a = arena.request(10, 3, Mode::Read).unwrap();
    let b = arena.request(20, 3, Mode::Read).unwrap();
    let readers = arena.admit_ready().unwrap();
    assert_eq!(readers.len(), 2);
    assert_eq!(readers[0].ticket(), a);
    assert_eq!(readers[1].ticket(), b);

    let writer = arena.request(30, 3, Mode::Write).unwrap();
    let later_reader = arena.request(40, 3, Mode::Read).unwrap();
    assert!(arena.admit_ready().unwrap().is_empty());
    for (holder, permit) in [(10, &readers[0]), (20, &readers[1])] {
        assert_eq!(
            arena.checked_offset(reference, permit, holder, Ref32Access::read(4, 4, 4)),
            Ok(12)
        );
        assert_eq!(
            arena.checked_offset(reference, permit, holder, Ref32Access::write(4, 4, 4)),
            Err(GuardedRef32Error::Guard(GuardError::WriteRequiresExclusive))
        );
    }

    arena.release(&readers[0], 10).unwrap();
    assert!(arena.admit_ready().unwrap().is_empty());
    arena.release(&readers[1], 20).unwrap();
    let writers = arena.admit_ready().unwrap();
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].ticket(), writer);
    assert_eq!(
        arena.checked_offset(reference, &writers[0], 30, Ref32Access::write(4, 4, 4)),
        Ok(12)
    );
    assert!(arena.admit_ready().unwrap().is_empty());
    arena.release(&writers[0], 30).unwrap();

    let late_readers = arena.admit_ready().unwrap();
    assert_eq!(late_readers.len(), 1);
    assert_eq!(late_readers[0].ticket(), later_reader);
    arena.release(&late_readers[0], 40).unwrap();
}

#[test]
fn matching_actor_ticket_does_not_allow_foreign_region_or_allocation() {
    let mut a = seeded(6, 9);
    let mut b = seeded(6, 9);
    let a_ref = a.allocate_before_seal(16, 8).unwrap();
    let b_ref = b.allocate_before_seal(16, 8).unwrap();
    assert_eq!(a_ref.offset(), b_ref.offset());
    a.seal();
    b.seal();

    let ta = a.request(77, 9, Mode::Read).unwrap();
    let tb = b.request(77, 9, Mode::Read).unwrap();
    assert_eq!(ta, tb);
    let pa = a.admit_ready().unwrap().pop().unwrap();
    let pb = b.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        b.checked_offset(b_ref, &pa, 77, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::WrongRegion))
    );
    assert_eq!(
        a.checked_offset(b_ref, &pa, 77, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Arena(Ref32Error::WrongArena))
    );
    assert_eq!(
        a.checked_offset(a_ref, &pa, 88, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::WrongHolder))
    );
    assert_eq!(
        a.checked_offset(a_ref, &pa, 77, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    a.release(&pa, 77).unwrap();
    b.release(&pb, 77).unwrap();
}

#[test]
fn checked_extent_rejects_cross_allocation_and_unaligned_access() {
    let mut arena = seeded(5, 2);
    let first = arena.allocate_before_seal(8, 8).unwrap();
    let _second = arena.allocate_before_seal(16, 8).unwrap();
    arena.seal();
    arena.request(5, 2, Mode::Write).unwrap();
    let permit = arena.admit_ready().unwrap().pop().unwrap();

    assert_eq!(
        arena.checked_offset(first, &permit, 5, Ref32Access::write(7, 2, 1)),
        Err(GuardedRef32Error::Arena(Ref32Error::OutOfBounds))
    );
    assert_eq!(
        arena.checked_offset(first, &permit, 5, Ref32Access::read(1, 1, 4)),
        Err(GuardedRef32Error::Arena(Ref32Error::Unaligned))
    );
    assert_eq!(
        arena.checked_offset(first, &permit, 5, Ref32Access::read(0, 0, 1)),
        Err(GuardedRef32Error::Arena(Ref32Error::InvalidSize))
    );
    arena.release(&permit, 5).unwrap();
    assert_eq!(
        arena.checked_offset(first, &permit, 5, Ref32Access::read(0, 1, 1)),
        Err(GuardedRef32Error::Guard(GuardError::UnknownTicket))
    );
}

#[test]
fn stop_fences_both_permits_and_refs_until_trusted_quiescence() {
    let mut arena = seeded(17, 6);
    let reference = arena.allocate_before_seal(16, 8).unwrap();
    arena.seal();
    arena.request(17, 6, Mode::Read).unwrap();
    let permit = arena.admit_ready().unwrap().pop().unwrap();

    assert_eq!(
        arena.retire(6),
        Err(GuardedRef32Error::Guard(GuardError::StaleGeneration))
    );
    assert_eq!(
        arena.checked_offset(reference, &permit, 17, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    arena.retire(7).unwrap();
    assert_eq!(arena.generation(), 7);
    assert_eq!(
        arena.checked_offset(reference, &permit, 17, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::StaleGeneration))
    );
    assert_eq!(
        arena.release(&permit, 17),
        Err(GuardedRef32Error::Guard(
            GuardError::PhysicalQuiescenceRequired
        ))
    );
    assert!(!arena.may_reclaim());
    assert_eq!(
        arena.request(17, 7, Mode::Read),
        Err(GuardedRef32Error::Guard(GuardError::Retired))
    );
    arena.complete_physical_quiescence(&permit, 17).unwrap();
    assert!(arena.may_reclaim());
    let mut replacement = seeded(17, 7);
    let fresh = replacement.allocate_before_seal(16, 8).unwrap();
    replacement.seal();
    replacement.request(17, 7, Mode::Read).unwrap();
    let fresh_permit = replacement.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        replacement.checked_offset(reference, &fresh_permit, 17, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Arena(Ref32Error::StaleGeneration))
    );
    assert_eq!(
        replacement.checked_offset(fresh, &fresh_permit, 17, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    replacement.release(&fresh_permit, 17).unwrap();
}

#[test]
fn cancelled_writer_does_not_starve_later_readers_or_bypass_holder_checks() {
    let mut arena = seeded(101, 8);
    let reference = arena.allocate_before_seal(8, 8).unwrap();
    arena.seal();

    let first = arena.request(1, 8, Mode::Read).unwrap();
    let active_readers = arena.admit_ready().unwrap();
    assert_eq!(active_readers.len(), 1);
    assert_eq!(active_readers[0].ticket(), first);

    let queued_writer = arena.request(2, 8, Mode::Write).unwrap();
    let later = arena.request(3, 8, Mode::Read).unwrap();
    assert!(arena.admit_ready().unwrap().is_empty());

    assert_eq!(
        arena.cancel_pending(queued_writer, 3, 8),
        Err(GuardedRef32Error::Guard(GuardError::WrongHolder))
    );
    assert!(arena.admit_ready().unwrap().is_empty());

    assert_eq!(arena.cancel_pending(queued_writer, 2, 8), Ok(()));
    assert_eq!(
        arena.cancel_pending(queued_writer, 2, 8),
        Err(GuardedRef32Error::Guard(GuardError::UnknownTicket))
    );
    let admitted = arena.admit_ready().unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].ticket(), later);
    assert_eq!(
        arena.checked_offset(reference, &admitted[0], 3, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    assert_eq!(
        arena.cancel_pending(first, 1, 8),
        Err(GuardedRef32Error::Guard(GuardError::UnknownTicket))
    );
    arena.release(&admitted[0], 3).unwrap();
    arena.release(&active_readers[0], 1).unwrap();
}

#[test]
fn pending_cancellation_is_fenced_by_stop_and_generation() {
    let mut arena = seeded(17, 5);
    let reference = arena.allocate_before_seal(8, 8).unwrap();
    arena.seal();
    let waiting = arena.request(9, 5, Mode::Read).unwrap();
    assert_eq!(
        arena.cancel_pending(waiting, 9, 6),
        Err(GuardedRef32Error::Guard(GuardError::StaleGeneration))
    );
    arena.retire(6).unwrap();
    assert_eq!(
        arena.cancel_pending(waiting, 9, 5),
        Err(GuardedRef32Error::Guard(GuardError::StaleGeneration))
    );
    assert!(arena.may_reclaim());
    assert_eq!(
        arena.request(9, 6, Mode::Read),
        Err(GuardedRef32Error::Guard(GuardError::Retired))
    );
    assert_eq!(
        arena.allocate_before_seal(1, 1),
        Err(GuardedRef32Error::Sealed)
    );
    // No scope can be acquired after STOP, even with a previously valid
    // reference and a ticket that was waiting when retirement began.
    assert!(arena.admit_ready().unwrap().is_empty());
    let mut fresh = seeded(17, 6);
    let _current = fresh.allocate_before_seal(8, 8).unwrap();
    fresh.seal();
    fresh.request(9, 6, Mode::Read).unwrap();
    let permit = fresh.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        fresh.checked_offset(reference, &permit, 9, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Arena(Ref32Error::StaleGeneration))
    );
    fresh.release(&permit, 9).unwrap();
}
