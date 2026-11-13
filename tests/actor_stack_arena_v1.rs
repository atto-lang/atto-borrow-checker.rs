use atto_borrow_checker::actor_stack_arena_v1::{
    ActorStackArena, StackError, MAX_STACK_BYTES, MAX_STACK_FRAMES,
};

#[test]
fn offsets_are_u32_actor_local_and_zero_reserved() {
    let mut actor = ActorStackArena::new(11, 3).unwrap();
    assert_eq!(actor.capacity_bytes(), MAX_STACK_BYTES);
    let frame = actor.push(32, 16).unwrap();
    assert_ne!(frame.offset(), 0);
    assert_eq!(frame.offset() % 16, 0);
    assert_eq!(frame.len(), 32);
    assert!(!frame.is_empty());
    actor.with_write(frame, |b| b.fill(0xA5)).unwrap();
    assert_eq!(
        actor.with_read(frame, |b| b.iter().all(|&v| v == 0xA5)),
        Ok(true)
    );
    assert_eq!(actor.active_frames(), 1);
    actor.pop(frame).unwrap();
    assert_eq!(actor.active_frames(), 0);
}

#[test]
fn cross_actor_and_stale_generation_handles_are_denied() {
    let mut first = ActorStackArena::with_limits(100, 9, 128, 4).unwrap();
    let mut second = ActorStackArena::with_limits(200, 9, 128, 4).unwrap();
    let mut restarted = ActorStackArena::with_limits(100, 10, 128, 4).unwrap();

    let first_frame = first.push(8, 8).unwrap();
    let second_frame = second.push(8, 8).unwrap();
    let restart_frame = restarted.push(8, 8).unwrap();
    // Same offset/sequence is never sufficient authority.
    assert_eq!(first_frame.offset(), second_frame.offset());
    assert_eq!(
        second.with_read(first_frame, |b| b.len()),
        Err(StackError::ForeignActor)
    );
    assert_eq!(
        restarted.with_write(first_frame, |b| b.fill(0)),
        Err(StackError::StaleGeneration)
    );
    assert_eq!(
        first.with_read(restart_frame, |b| b.len()),
        Err(StackError::StaleGeneration)
    );
    assert_eq!(first.with_read(first_frame, |b| b.len()), Ok(8));
    assert_eq!(second.with_read(second_frame, |b| b.len()), Ok(8));
}

#[test]
fn non_lifo_destruction_is_denied_without_changing_live_frames() {
    let mut arena = ActorStackArena::with_limits(1, 1, 64, 4).unwrap();
    let base = arena.push(6, 2).unwrap();
    let nested = arena.push(9, 4).unwrap();
    assert_eq!(arena.pop(base), Err(StackError::NotTopFrame));
    assert_eq!(arena.active_frames(), 2);
    arena.with_write(base, |b| b[0] = 17).unwrap();
    arena.pop(nested).unwrap();
    assert_eq!(arena.with_read(base, |b| b[0]), Ok(17));
    arena.pop(base).unwrap();
    assert_eq!(arena.pop(base), Err(StackError::UnknownFrame));
}

#[test]
fn popped_frame_is_zeroed_and_same_offset_has_new_identity() {
    let mut arena = ActorStackArena::with_limits(1, 1, 64, 4).unwrap();
    let old = arena.push(12, 8).unwrap();
    arena.with_write(old, |b| b.fill(0xFE)).unwrap();
    arena.pop(old).unwrap();
    let new = arena.push(12, 8).unwrap();
    assert_eq!(old.offset(), new.offset());
    assert_ne!(old, new);
    assert_eq!(
        arena.with_read(old, |b| b.len()),
        Err(StackError::UnknownFrame)
    );
    assert_eq!(
        arena.with_read(new, |b| b.iter().all(|&v| v == 0)),
        Ok(true)
    );
}

#[test]
fn frame_budget_overflow_faults_only_the_owning_actor() {
    let mut faulty = ActorStackArena::with_limits(7, 4, 32, 2).unwrap();
    let mut sibling = ActorStackArena::with_limits(8, 4, 32, 2).unwrap();
    let old = faulty.push(10, 1).unwrap();
    let valid = sibling.push(10, 1).unwrap();

    assert_eq!(faulty.push(24, 8), Err(StackError::Exhausted));
    assert!(faulty.is_faulted());
    assert_eq!(faulty.with_read(old, |b| b.len()), Err(StackError::Faulted));
    assert_eq!(faulty.push(1, 1), Err(StackError::Faulted));
    sibling.with_write(valid, |b| b[0] = 42).unwrap();
    assert_eq!(sibling.with_read(valid, |b| b[0]), Ok(42));
    sibling.pop(valid).unwrap();

    assert_eq!(faulty.retire(5), Ok(()));
    assert!(faulty.is_retired());
    assert_eq!(faulty.push(1, 1), Err(StackError::Retired));
}

#[test]
fn depth_exhaustion_never_wraps_or_pops_an_active_frame() {
    let mut arena = ActorStackArena::with_limits(17, 3, 64, 1).unwrap();
    let _active = arena.push(4, 1).unwrap();
    assert_eq!(arena.push(4, 1), Err(StackError::Exhausted));
    assert_eq!(arena.active_frames(), 1);
    assert_eq!(arena.pop(_active), Err(StackError::Faulted));
    arena.retire(4).unwrap();
    assert_eq!(arena.active_frames(), 0);
    assert_eq!(arena.retire(5), Err(StackError::Retired));
}

#[test]
fn invalid_allocations_do_not_mutate_the_stack() {
    let mut arena = ActorStackArena::with_limits(1, 1, 64, 4).unwrap();
    for (len, alignment) in [(0, 1), (1, 0), (1, 3), (1, 8192)] {
        assert_eq!(arena.push(len, alignment), Err(StackError::InvalidFrame));
    }
    assert!(!arena.is_faulted());
    assert_eq!(arena.active_frames(), 0);
    let frame = arena.push(1, 1).unwrap();
    assert_eq!(frame.offset(), 1);
    arena.pop(frame).unwrap();
    assert_eq!(arena.retire(1), Err(StackError::StaleGeneration));
    assert_eq!(arena.retire(0), Err(StackError::StaleGeneration));
    assert_eq!(arena.retire(2), Ok(()));
}

#[test]
fn reject_invalid_actor_generation_and_budgets() {
    for (actor, generation, bytes, frames) in [
        (0, 1, 64, 2),
        (1, 0, 64, 2),
        (1, 1, 0, 2),
        (1, 1, 1, 2),
        (1, 1, 64, 0),
        (1, 1, MAX_STACK_BYTES + 1, 2),
        (1, 1, 64, MAX_STACK_FRAMES + 1),
    ] {
        assert!(matches!(
            ActorStackArena::with_limits(actor, generation, bytes, frames),
            Err(StackError::InvalidConfiguration)
        ));
    }
}

#[test]
fn alignment_over_budget_poisoning_is_atomic_and_actor_local() {
    let mut actor = ActorStackArena::with_limits(9, 2, 16, 4).unwrap();
    let live = actor.push(7, 1).unwrap();
    assert_eq!(actor.push(8, 8), Err(StackError::Exhausted));
    assert_eq!(actor.active_frames(), 1);
    assert!(actor.is_faulted());
    // No partial frame has been admitted, and stale work must be retired.
    assert_eq!(actor.pop(live), Err(StackError::Faulted));
    actor.retire(3).unwrap();
    assert_eq!(actor.active_frames(), 0);
}

#[test]
fn same_actor_and_generation_cannot_reuse_stale_handle_from_old_instance() {
    // A supervisor must still authenticate the durable actor generation, but
    // duplicate local arena construction cannot revive an old frame handle.
    let mut old = ActorStackArena::with_limits(51, 7, 64, 4).unwrap();
    let mut duplicate = ActorStackArena::with_limits(51, 7, 64, 4).unwrap();
    let old_frame = old.push(12, 4).unwrap();
    let new_frame = duplicate.push(12, 4).unwrap();
    assert_eq!(old_frame.offset(), new_frame.offset());
    assert_ne!(old_frame, new_frame);
    assert_eq!(
        duplicate.with_read(old_frame, |bytes| bytes.len()),
        Err(StackError::UnknownFrame)
    );
    assert_eq!(
        old.with_write(new_frame, |bytes| bytes.fill(0)),
        Err(StackError::UnknownFrame)
    );
    assert_eq!(duplicate.with_read(new_frame, |bytes| bytes.len()), Ok(12));
}

#[test]
fn debug_output_never_exposes_actor_stack_contents() {
    let mut arena = ActorStackArena::with_limits(8, 3, 96, 4).unwrap();
    let frame = arena.push(16, 1).unwrap();
    arena
        .with_write(frame, |bytes| bytes.copy_from_slice(b"SECRET_FRAME_123"))
        .unwrap();
    let printed = format!("{arena:?}");
    assert!(printed.contains("ActorStackArena"));
    assert!(!printed.contains("SECRET_FRAME_123"));
    // No backing storage vector, byte array or internal handles are emitted.
    assert!(!printed.contains("bytes:"));
    assert!(!printed.contains("frames: ["));
}
