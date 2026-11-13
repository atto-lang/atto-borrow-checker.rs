//! Independent Rust static model tests; not compiled Atto guest evidence.
use atto_borrow_checker::actor_critical_ref32_v1::{
    verify_critical_ref32_sites, CriticalRef32Error, CriticalRef32Site,
};
use atto_borrow_checker::actor_ref32_v1::{
    ActorArena, Allocation, Loan, LoanMode, Ref32, Ref32Error,
};
use atto_borrow_checker::{Block, Op, Program};

fn program() -> Program {
    Program {
        entry: 1,
        blocks: vec![Block {
            id: 1,
            successors: vec![],
            operations: vec![
                Op::CriticalReadEnter { state: 7, scope: 10 },
                Op::CriticalReadAccess { state: 7, scope: 10 },
                Op::CriticalCopyI64 { state: 7, scope: 10, into: 42 },
                Op::CriticalExit { scope: 10 },
                Op::CriticalWriteEnter { state: 7, scope: 11 },
                Op::CriticalWriteAccess { state: 7, scope: 11 },
                Op::CriticalExit { scope: 11 },
                Op::ActorSendCopy { owner: 42 },
                Op::Return,
            ],
        }],
    }
}
fn fixture() -> (ActorArena, Allocation, Ref32, Loan, Loan) {
    let arena = ActorArena {
        actor_id: 5, arena_id: 3, incarnation: 2, generation: 8,
        capacity_bytes: 4096, retired: false,
    };
    let allocation = Allocation {
        actor_id: 5, arena_id: 3, incarnation: 2, generation: 8,
        allocation_id: 99, allocation_generation: 12,
        base: 64, bytes: 128, retired: false,
    };
    let reference = Ref32 {
        actor_id: 5, arena_id: 3, incarnation: 2, generation: 8,
        allocation_id: 99, allocation_generation: 12, offset: 72,
    };
    let read = Loan {
        actor_id: 5, arena_id: 3, incarnation: 2, generation: 8,
        allocation_id: 99, allocation_generation: 12,
        mode: LoanMode::SharedRead, live: true,
    };
    let write = Loan {
        actor_id: 5, arena_id: 3, incarnation: 2, generation: 8,
        allocation_id: 99, allocation_generation: 12,
        mode: LoanMode::ExclusiveWrite, live: true,
    };
    (arena, allocation, reference, read, write)
}
fn site<'a>(
    operation: usize, scope: u32, arena: &'a ActorArena, allocation: &'a Allocation,
    reference: &'a Ref32, loan: &'a Loan,
) -> CriticalRef32Site<'a> {
    CriticalRef32Site {
        block: 1, operation, state: 7, scope, state_allocation_id: 99,
        arena, allocation, reference, loan, access_bytes: 8, alignment: 8,
    }
}

#[test]
fn complete_read_write_and_detached_copy_inventory_is_admitted() {
    let (arena, allocation, reference, reader, writer) = fixture();
    let sites = [
        site(1, 10, &arena, &allocation, &reference, &reader),
        site(2, 10, &arena, &allocation, &reference, &reader),
        site(5, 11, &arena, &allocation, &reference, &writer),
    ];
    assert!(verify_critical_ref32_sites(&program(), &sites).is_ok());
}

#[test]
fn detached_copy_requires_explicit_load_site() {
    let (arena, allocation, reference, reader, writer) = fixture();
    let sites = [
        site(1, 10, &arena, &allocation, &reference, &reader),
        site(5, 11, &arena, &allocation, &reference, &writer),
    ];
    assert_eq!(
        verify_critical_ref32_sites(&program(), &sites),
        Err(CriticalRef32Error::MissingSite { block: 1, operation: 2 })
    );
}

#[test]
fn write_requires_physical_exclusive_loan_metadata() {
    let (arena, allocation, reference, reader, _) = fixture();
    let sites = [
        site(1, 10, &arena, &allocation, &reference, &reader),
        site(2, 10, &arena, &allocation, &reference, &reader),
        site(5, 11, &arena, &allocation, &reference, &reader),
    ];
    assert_eq!(
        verify_critical_ref32_sites(&program(), &sites),
        Err(CriticalRef32Error::Ref32 {
            block: 1, operation: 5, reason: Ref32Error::WriteRequiresExclusive
        })
    );
}

#[test]
fn recycled_slot_cannot_use_stale_read_or_write_loans() {
    let (arena, mut allocation, mut reference, reader, writer) = fixture();
    allocation.allocation_generation += 1;
    reference.allocation_generation += 1;
    let sites = [
        site(1, 10, &arena, &allocation, &reference, &reader),
        site(2, 10, &arena, &allocation, &reference, &reader),
        site(5, 11, &arena, &allocation, &reference, &writer),
    ];
    assert_eq!(
        verify_critical_ref32_sites(&program(), &sites),
        Err(CriticalRef32Error::Ref32 {
            block: 1, operation: 1, reason: Ref32Error::StaleAllocation
        })
    );
}

#[test]
fn duplicate_unexpected_and_wrong_state_sites_fail_closed() {
    let (arena, allocation, reference, reader, writer) = fixture();
    assert_eq!(
        verify_critical_ref32_sites(&program(), &[
            site(1, 10, &arena, &allocation, &reference, &reader),
            site(1, 10, &arena, &allocation, &reference, &reader),
        ]),
        Err(CriticalRef32Error::DuplicateSite { block: 1, operation: 1 })
    );
    let mut wrong = site(1, 10, &arena, &allocation, &reference, &reader);
    wrong.scope = 11;
    assert_eq!(
        verify_critical_ref32_sites(&program(), &[
            wrong,
            site(2, 10, &arena, &allocation, &reference, &reader),
            site(5, 11, &arena, &allocation, &reference, &writer),
        ]),
        Err(CriticalRef32Error::StateMismatch { block: 1, operation: 1 })
    );
    assert_eq!(
        verify_critical_ref32_sites(&program(), &[
            site(1, 10, &arena, &allocation, &reference, &reader),
            site(2, 10, &arena, &allocation, &reference, &reader),
            site(5, 11, &arena, &allocation, &reference, &writer),
            site(7, 11, &arena, &allocation, &reference, &writer),
        ]),
        Err(CriticalRef32Error::UnexpectedSite { block: 1, operation: 7 })
    );
}

#[test]
fn wrong_allocation_binding_and_unproved_suspend_are_denied() {
    let (arena, allocation, reference, reader, writer) = fixture();
    let mut wrong = site(1, 10, &arena, &allocation, &reference, &reader);
    wrong.state_allocation_id = 100;
    assert_eq!(
        verify_critical_ref32_sites(&program(), &[
            wrong,
            site(2, 10, &arena, &allocation, &reference, &reader),
            site(5, 11, &arena, &allocation, &reference, &writer),
        ]),
        Err(CriticalRef32Error::AllocationBindingMismatch { block: 1, operation: 1 })
    );
    let mut unsafe_program = program();
    unsafe_program.blocks[0].operations.insert(1, Op::Suspend);
    assert!(matches!(
        verify_critical_ref32_sites(&unsafe_program, &[]),
        Err(CriticalRef32Error::Lexical(d)) if d.code == "E_CRITICAL_EFFECT_UNPROVEN"
    ));
}
