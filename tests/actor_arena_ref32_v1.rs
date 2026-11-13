//! Independent ref32 metadata regressions; not native compiler/guest proof.
use atto_borrow_checker::actor_arena_ref32_v1::{
    ActorArenaRef32, Ref32Error, MAX_REF32_CAPACITY,
};

#[test]
fn actor_private_allocations_resolve_only_within_their_extent() {
    let mut arena = ActorArenaRef32::new(7, 10, 128).unwrap();
    let first = arena.allocate(8, 8).unwrap();
    let second = arena.allocate(4, 4).unwrap();
    assert_eq!(first.offset(), 8);
    assert_eq!(second.offset(), 16);
    assert_eq!(arena.checked_offset(first, 7, 10, 4, 4, 4), Ok(12));
    assert_eq!(
        arena.checked_offset(first, 7, 10, 7, 2, 1),
        Err(Ref32Error::OutOfBounds)
    );
    assert_eq!(
        arena.checked_offset(first, 7, 10, 1, 1, 4),
        Err(Ref32Error::Unaligned)
    );
}

#[test]
fn arbitrary_actor_cannot_read_or_write_another_actors_arena() {
    let mut arena = ActorArenaRef32::new(41, 2, 256).unwrap();
    let reference = arena.allocate(16, 8).unwrap();
    assert_eq!(
        arena.checked_offset(reference, 42, 2, 0, 4, 4),
        Err(Ref32Error::WrongActor)
    );
    assert_eq!(arena.checked_offset(reference, 41, 2, 0, 4, 4), Ok(8));
}

#[test]
fn cross_arena_refs_fail_even_with_same_actor_generation_and_offset() {
    let mut a = ActorArenaRef32::new(7, 4, 256).unwrap();
    let mut b = ActorArenaRef32::new(7, 4, 256).unwrap();
    let x = a.allocate(16, 8).unwrap();
    let y = b.allocate(16, 8).unwrap();
    assert_eq!(x.offset(), y.offset());
    assert_eq!(
        b.checked_offset(x, 7, 4, 0, 8, 8),
        Err(Ref32Error::WrongArena)
    );
    assert_eq!(b.checked_offset(y, 7, 4, 0, 8, 8), Ok(8));
}

#[test]
fn stop_and_restart_cannot_reanimate_stale_ref32() {
    let mut old = ActorArenaRef32::new(18, 3, 256).unwrap();
    let stale = old.allocate(16, 8).unwrap();
    assert_eq!(old.retire(4), Ok(()));
    assert_eq!(
        old.checked_offset(stale, 18, 3, 0, 8, 8),
        Err(Ref32Error::Retired)
    );
    assert_eq!(old.allocate(1, 1), Err(Ref32Error::Retired));
    let mut fresh = ActorArenaRef32::new(18, 4, 256).unwrap();
    let current = fresh.allocate(16, 8).unwrap();
    assert_eq!(
        fresh.checked_offset(stale, 18, 4, 0, 8, 8),
        Err(Ref32Error::StaleGeneration)
    );
    assert_eq!(fresh.checked_offset(current, 18, 4, 0, 8, 8), Ok(8));
}

#[test]
fn failed_allocation_is_atomic_and_does_not_consume_space() {
    let mut arena = ActorArenaRef32::new(9, 1, 12).unwrap();
    assert_eq!(arena.allocate(13, 1), Err(Ref32Error::Exhausted));
    assert_eq!(arena.allocate(4, 3), Err(Ref32Error::InvalidAlignment));
    assert_eq!(arena.allocate(0, 1), Err(Ref32Error::InvalidSize));
    let first = arena.allocate(4, 4).unwrap();
    assert_eq!(first.offset(), 4);
    let second = arena.allocate(5, 1).unwrap();
    assert_eq!(second.offset(), 8);
    assert_eq!(arena.allocate(1, 1), Err(Ref32Error::Exhausted));
}

#[test]
fn u32_boundary_never_widens_or_wraps_guest_offset() {
    assert_eq!(
        ActorArenaRef32::new(1, 1, MAX_REF32_CAPACITY + 1)
            .unwrap_err(),
        Ref32Error::InvalidCapacity
    );
    let mut arena = ActorArenaRef32::new(1, 1, MAX_REF32_CAPACITY).unwrap();
    let max = arena.allocate(u32::MAX - 1, 1).unwrap();
    assert_eq!(max.offset(), 1);
    assert_eq!(
        arena.checked_offset(max, 1, 1, u32::MAX - 2, 1, 1),
        Ok(u32::MAX - 1)
    );
    let final_byte = arena.allocate(1, 1).unwrap();
    assert_eq!(final_byte.offset(), u32::MAX);
    assert_eq!(arena.checked_offset(final_byte, 1, 1, 0, 1, 1), Ok(u32::MAX));
    assert_eq!(arena.allocate(1, 1), Err(Ref32Error::Exhausted));
    assert_eq!(
        arena.checked_offset(max, 1, 1, u32::MAX - 1, 1, 1),
        Err(Ref32Error::OutOfBounds)
    );
}

#[test]
fn invalid_initial_state_and_stale_retirement_fail_closed() {
    assert_eq!(
        ActorArenaRef32::new(0, 1, 32).unwrap_err(),
        Ref32Error::InvalidIdentity
    );
    assert_eq!(
        ActorArenaRef32::new(1, 0, 32).unwrap_err(),
        Ref32Error::InvalidIdentity
    );
    assert_eq!(
        ActorArenaRef32::new(1, 1, 0).unwrap_err(),
        Ref32Error::InvalidCapacity
    );
    let mut arena = ActorArenaRef32::new(1, 1, 32).unwrap();
    assert_eq!(arena.retire(1), Err(Ref32Error::StaleGeneration));
    assert_eq!(arena.retire(0), Err(Ref32Error::StaleGeneration));
    assert_eq!(arena.retire(2), Ok(()));
    assert_eq!(arena.retire(3), Err(Ref32Error::Retired));
}
