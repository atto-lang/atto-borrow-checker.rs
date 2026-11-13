//! Ref32 static negative/positive inventory, not live compiler or heap proof.
use atto_borrow_checker::actor_ref32_v1::{
    check_access, AccessMode, ActorArena, Allocation, Loan, LoanMode, Ref32, Ref32Error,
    MAX_ARENA_BYTES,
};

fn case() -> (ActorArena, Allocation, Ref32, Loan) {
    let arena = ActorArena {
        actor_id: 11,
        arena_id: 3,
        incarnation: 2,
        generation: 7,
        capacity_bytes: 1024,
        retired: false,
    };
    let allocation = Allocation {
        actor_id: 11,
        arena_id: 3,
        incarnation: 2,
        generation: 7,
        allocation_id: 99,
        base: 64,
        bytes: 32,
        retired: false,
    };
    let reference = Ref32 {
        actor_id: 11,
        arena_id: 3,
        incarnation: 2,
        generation: 7,
        allocation_id: 99,
        offset: 72,
    };
    let loan = Loan {
        actor_id: 11,
        arena_id: 3,
        incarnation: 2,
        generation: 7,
        mode: LoanMode::ExclusiveWrite,
        live: true,
    };
    (arena, allocation, reference, loan)
}

#[test]
fn valid_actor_local_access_and_exclusive_writer() {
    let (arena, allocation, reference, loan) = case();
    let extent = check_access(
        &arena,
        &allocation,
        &reference,
        &loan,
        16,
        8,
        AccessMode::Write,
    )
    .unwrap();
    assert_eq!(extent.start, 72);
    assert_eq!(extent.end_exclusive, 88);
}

#[test]
fn readers_are_allowed_but_cannot_write() {
    let (arena, allocation, reference, mut loan) = case();
    loan.mode = LoanMode::SharedRead;
    assert!(check_access(
        &arena,
        &allocation,
        &reference,
        &loan,
        16,
        8,
        AccessMode::Read
    )
    .is_ok());
    assert_eq!(
        check_access(
            &arena,
            &allocation,
            &reference,
            &loan,
            16,
            8,
            AccessMode::Write
        ),
        Err(Ref32Error::WriteRequiresExclusive)
    );
    loan.live = false;
    assert_eq!(
        check_access(
            &arena,
            &allocation,
            &reference,
            &loan,
            16,
            8,
            AccessMode::Read
        ),
        Err(Ref32Error::MissingLoan)
    );
}

#[test]
fn actor_and_arena_domain_forgery_is_rejected() {
    let (arena, allocation, mut reference, loan) = case();
    reference.actor_id = 12;
    assert_eq!(
        check_access(
            &arena,
            &allocation,
            &reference,
            &loan,
            8,
            8,
            AccessMode::Read
        ),
        Err(Ref32Error::WrongDomain)
    );
    reference.actor_id = 11;
    reference.arena_id = 4;
    assert_eq!(
        check_access(
            &arena,
            &allocation,
            &reference,
            &loan,
            8,
            8,
            AccessMode::Read
        ),
        Err(Ref32Error::WrongDomain)
    );
}

#[test]
fn restart_generation_allocation_and_retirement_are_fenced() {
    let (mut arena, mut allocation, mut reference, mut loan) = case();
    reference.generation = 6;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::StaleGeneration)
    );
    reference.generation = 7;
    reference.allocation_id = 100;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::WrongAllocation)
    );
    reference.allocation_id = 99;
    allocation.retired = true;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::Retired)
    );
    allocation.retired = false;
    arena.incarnation += 1;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::StaleGeneration)
    );
    arena.incarnation -= 1;
    loan.generation += 1;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::StaleGeneration)
    );
}

#[test]
fn allocation_extent_not_just_arena_size_is_enforced() {
    let (arena, allocation, mut reference, loan) = case();
    reference.offset = 96; // valid in arena but just beyond this allocation
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::OutsideAllocation)
    );
    reference.offset = 72;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 32, 8, AccessMode::Read),
        Err(Ref32Error::OutsideAllocation)
    );
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 0, 8, AccessMode::Read),
        Err(Ref32Error::InvalidExtent)
    );
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 16, AccessMode::Read),
        Err(Ref32Error::InvalidAlignment)
    );
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 0, AccessMode::Read),
        Err(Ref32Error::InvalidAlignment)
    );
}

#[test]
fn reject_4gib_plus_one_and_32_bit_wraparound() {
    let (mut arena, mut allocation, mut reference, loan) = case();
    arena.capacity_bytes = MAX_ARENA_BYTES + 1;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::InvalidArena)
    );

    arena.capacity_bytes = MAX_ARENA_BYTES;
    allocation.base = u32::MAX - 7;
    allocation.bytes = 8;
    reference.offset = u32::MAX - 7;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 8, 8, AccessMode::Read),
        Err(Ref32Error::InvalidAlignment)
    );
    // Aligned start, but an attempted access would exceed the ref32 arena.
    allocation.base = u32::MAX - 15;
    allocation.bytes = 32;
    reference.offset = u32::MAX - 15;
    assert_eq!(
        check_access(&arena, &allocation, &reference, &loan, 32, 8, AccessMode::Read),
        Err(Ref32Error::InvalidExtent)
    );
    allocation.bytes = 16;
    assert!(check_access(
        &arena,
        &allocation,
        &reference,
        &loan,
        16,
        8,
        AccessMode::Read
    )
    .is_ok());
}
