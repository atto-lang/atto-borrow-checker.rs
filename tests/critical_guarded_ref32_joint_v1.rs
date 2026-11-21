//! Cross-module fail-closed conformance of the *models*, not native memory authority.
//!
//! The static MIR records below are independently seeded test fixtures.
//! They are NOT derived from the runtime's private minted Ref32, and this
//! test does not claim a compiler-to-runtime authentication bridge exists.
//! Both the compiler's static proof and the trusted runtime's independently
//! authenticated live permit must succeed before a real backend may access memory.
use atto_borrow_checker::actor_arena_ref32_v1::Ref32Error as RuntimeRefError;
use atto_borrow_checker::actor_critical_ref32_v1::{
    verify_critical_ref32_sites, CriticalRef32Error, CriticalRef32Site,
};
use atto_borrow_checker::actor_ref32_guarded_v1::{
    GuardedRef32Arena, GuardedRef32Error, Ref32Access,
};
use atto_borrow_checker::actor_ref32_v1::{
    ActorArena, Allocation, Loan, LoanMode, Ref32 as StaticRef32, Ref32Error as StaticRefError,
};
use atto_borrow_checker::actor_state_guard_v1::{GuardError, Mode};
use atto_borrow_checker::{Block, Op, Program};

struct StaticFixture {
    arena: ActorArena,
    allocation: Allocation,
    reference: StaticRef32,
    reader: Loan,
    writer: Loan,
}

fn static_fixture() -> StaticFixture {
    let arena = ActorArena {
        actor_id: 5,
        arena_id: 3,
        incarnation: 2,
        generation: 8,
        capacity_bytes: 256,
        retired: false,
    };
    let allocation = Allocation {
        actor_id: 5,
        arena_id: 3,
        incarnation: 2,
        generation: 8,
        allocation_id: 99,
        allocation_generation: 12,
        base: 8,
        bytes: 32,
        retired: false,
    };
    let reference = StaticRef32 {
        actor_id: 5,
        arena_id: 3,
        incarnation: 2,
        generation: 8,
        allocation_id: 99,
        allocation_generation: 12,
        offset: 8,
    };
    let reader = Loan {
        actor_id: 5,
        arena_id: 3,
        incarnation: 2,
        generation: 8,
        allocation_id: 99,
        allocation_generation: 12,
        mode: LoanMode::SharedRead,
        live: true,
    };
    let writer = Loan {
        actor_id: 5,
        arena_id: 3,
        incarnation: 2,
        generation: 8,
        allocation_id: 99,
        allocation_generation: 12,
        mode: LoanMode::ExclusiveWrite,
        live: true,
    };
    StaticFixture {
        arena,
        allocation,
        reference,
        reader,
        writer,
    }
}

fn critical_program() -> Program {
    Program {
        entry: 1,
        blocks: vec![Block {
            id: 1,
            successors: vec![],
            operations: vec![
                Op::CriticalReadEnter {
                    state: 7,
                    scope: 10,
                },
                Op::CriticalReadAccess {
                    state: 7,
                    scope: 10,
                },
                Op::CriticalCopyI64 {
                    state: 7,
                    scope: 10,
                    into: 42,
                },
                Op::CriticalExit { scope: 10 },
                Op::CriticalWriteEnter {
                    state: 7,
                    scope: 11,
                },
                Op::CriticalWriteAccess {
                    state: 7,
                    scope: 11,
                },
                Op::CriticalExit { scope: 11 },
                Op::ActorSendCopy { owner: 42 },
                Op::Return,
            ],
        }],
    }
}

fn site<'a>(
    f: &'a StaticFixture,
    operation: usize,
    scope: u32,
    loan: &'a Loan,
) -> CriticalRef32Site<'a> {
    CriticalRef32Site {
        block: 1,
        operation,
        state: 7,
        scope,
        state_allocation_id: 99,
        arena: &f.arena,
        allocation: &f.allocation,
        reference: &f.reference,
        loan,
        access_bytes: 8,
        alignment: 8,
    }
}

fn sites(f: &StaticFixture) -> [CriticalRef32Site<'_>; 3] {
    [
        site(f, 1, 10, &f.reader),
        site(f, 2, 10, &f.reader),
        site(f, 5, 11, &f.writer),
    ]
}

fn runtime_fixture() -> (
    GuardedRef32Arena,
    atto_borrow_checker::actor_arena_ref32_v1::Ref32,
) {
    let mut runtime = GuardedRef32Arena::new(5, 8, 256).unwrap();
    let reference = runtime.allocate_before_seal(32, 8).unwrap();
    assert_eq!(reference.offset(), 8);
    (runtime, reference)
}

#[test]
fn static_success_never_replaces_a_live_runtime_permit() {
    let f = static_fixture();
    assert!(verify_critical_ref32_sites(&critical_program(), &sites(&f)).is_ok());

    let (mut runtime, reference) = runtime_fixture();
    assert_eq!(
        runtime.request(5, 8, Mode::Read),
        Err(GuardedRef32Error::Unsealed)
    );
    runtime.seal();
    let read_ticket = runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(read.ticket(), read_ticket);
    assert_eq!(
        runtime.checked_offset(reference, &read, 5, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    assert_eq!(
        runtime.checked_offset(reference, &read, 5, Ref32Access::write(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::WriteRequiresExclusive))
    );
    runtime.release(&read, 5).unwrap();
    assert_eq!(
        runtime.checked_offset(reference, &read, 5, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::UnknownTicket))
    );
    runtime.request(5, 8, Mode::Write).unwrap();
    let write = runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        runtime.checked_offset(reference, &write, 5, Ref32Access::write(0, 8, 8)),
        Ok(8)
    );
    runtime.release(&write, 5).unwrap();
}

#[test]
fn independently_valid_static_metadata_cannot_cross_runtime_arenas_or_holders() {
    let f = static_fixture();
    assert!(verify_critical_ref32_sites(&critical_program(), &sites(&f)).is_ok());

    let (mut a, a_ref) = runtime_fixture();
    let (mut b, b_ref) = runtime_fixture();
    assert_eq!(a_ref.offset(), b_ref.offset());
    a.seal();
    b.seal();
    a.request(5, 8, Mode::Read).unwrap();
    b.request(5, 8, Mode::Read).unwrap();
    let a_permit = a.admit_ready().unwrap().pop().unwrap();
    let b_permit = b.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        b.checked_offset(b_ref, &a_permit, 5, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::WrongRegion))
    );
    assert_eq!(
        a.checked_offset(b_ref, &a_permit, 5, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Arena(RuntimeRefError::WrongArena))
    );
    assert_eq!(
        a.checked_offset(a_ref, &a_permit, 6, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::WrongHolder))
    );
    a.release(&a_permit, 5).unwrap();
    b.release(&b_permit, 5).unwrap();
}

#[test]
fn runtime_permission_cannot_rescue_a_forged_static_domain_or_recycled_slot() {
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let permit = runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );

    let mut wrong_actor = static_fixture();
    wrong_actor.reference.actor_id = 999;
    assert!(matches!(
        verify_critical_ref32_sites(&critical_program(), &sites(&wrong_actor)),
        Err(CriticalRef32Error::Ref32 {
            reason: StaticRefError::WrongDomain,
            ..
        })
    ));

    let mut recycled = static_fixture();
    recycled.allocation.allocation_generation += 1;
    recycled.reference.allocation_generation += 1;
    assert!(matches!(
        verify_critical_ref32_sites(&critical_program(), &sites(&recycled)),
        Err(CriticalRef32Error::Ref32 {
            reason: StaticRefError::StaleAllocation,
            ..
        })
    ));
    runtime.release(&permit, 5).unwrap();
}

#[test]
fn runtime_access_does_not_excuse_missing_static_sites_or_unsafe_suspend() {
    let f = static_fixture();
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let permit = runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );

    let all_sites = sites(&f);
    assert_eq!(
        verify_critical_ref32_sites(&critical_program(), &all_sites[..2]),
        Err(CriticalRef32Error::MissingSite {
            block: 1,
            operation: 5
        })
    );
    let mut suspended = critical_program();
    suspended.blocks[0].operations.insert(1, Op::Suspend);
    assert!(matches!(
        verify_critical_ref32_sites(&suspended, &[]),
        Err(CriticalRef32Error::Lexical(d)) if d.code == "E_CRITICAL_EFFECT_UNPROVEN"
    ));
    runtime.release(&permit, 5).unwrap();
}

#[test]
fn retired_runtime_denies_old_ref_even_if_static_metadata_has_not_changed() {
    let f = static_fixture();
    assert!(verify_critical_ref32_sites(&critical_program(), &sites(&f)).is_ok());
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let permit = runtime.admit_ready().unwrap().pop().unwrap();
    runtime.retire(9).unwrap();

    assert!(!runtime.may_reclaim());
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Guard(GuardError::StaleGeneration))
    );
    assert_eq!(
        runtime.release(&permit, 5),
        Err(GuardedRef32Error::Guard(
            GuardError::PhysicalQuiescenceRequired
        ))
    );
    assert_eq!(
        runtime.complete_physical_quiescence(&permit, 6),
        Err(GuardedRef32Error::Guard(GuardError::WrongHolder))
    );
    assert!(!runtime.may_reclaim());
    // Trusted physical quiescence is a PRECONDITION supplied by the runtime,
    // not proven by this source-free model or by a guest acknowledgement.
    runtime.complete_physical_quiescence(&permit, 5).unwrap();
    assert!(runtime.may_reclaim());

    let (mut new_runtime, fresh_ref) = {
        let mut replacement = GuardedRef32Arena::new(5, 9, 256).unwrap();
        let new_ref = replacement.allocate_before_seal(32, 8).unwrap();
        replacement.seal();
        (replacement, new_ref)
    };
    new_runtime.request(5, 9, Mode::Read).unwrap();
    let new_permit = new_runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        new_runtime.checked_offset(reference, &new_permit, 5, Ref32Access::read(0, 8, 8)),
        Err(GuardedRef32Error::Arena(RuntimeRefError::StaleGeneration))
    );
    assert_eq!(
        new_runtime.checked_offset(fresh_ref, &new_permit, 5, Ref32Access::read(0, 8, 8)),
        Ok(8)
    );
    new_runtime.release(&new_permit, 5).unwrap();
}

#[test]
fn static_snapshot_width_and_runtime_allocation_extent_are_separate_checks() {
    let f = static_fixture();
    let mut all_sites = sites(&f);
    all_sites[1].access_bytes = 4;
    assert_eq!(
        verify_critical_ref32_sites(&critical_program(), &all_sites),
        Err(CriticalRef32Error::InvalidScalarWidth {
            block: 1,
            operation: 2,
            bytes: 4,
        })
    );

    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Write).unwrap();
    let permit = runtime.admit_ready().unwrap().pop().unwrap();
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::read(0, 4, 4)),
        Ok(8)
    );
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::write(28, 8, 4)),
        Err(GuardedRef32Error::Arena(RuntimeRefError::OutOfBounds))
    );
    assert_eq!(
        runtime.checked_offset(reference, &permit, 5, Ref32Access::write(1, 1, 8)),
        Err(GuardedRef32Error::Arena(RuntimeRefError::Unaligned))
    );
    runtime.release(&permit, 5).unwrap();
}

#[test]
fn guarded_fifo_blocks_writer_until_readers_exit_despite_static_write_proof() {
    let f = static_fixture();
    assert!(verify_critical_ref32_sites(&critical_program(), &sites(&f)).is_ok());

    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(10, 8, Mode::Read).unwrap();
    runtime.request(20, 8, Mode::Read).unwrap();
    let readers = runtime.admit_ready().unwrap();
    assert_eq!(readers.len(), 2);
    runtime.request(30, 8, Mode::Write).unwrap();
    runtime.request(40, 8, Mode::Read).unwrap();
    assert!(runtime.admit_ready().unwrap().is_empty());

    for (holder, permit) in [(10, &readers[0]), (20, &readers[1])] {
        assert_eq!(
            runtime.checked_offset(reference, permit, holder, Ref32Access::read(0, 8, 8)),
            Ok(8)
        );
    }
    runtime.release(&readers[0], 10).unwrap();
    assert!(runtime.admit_ready().unwrap().is_empty());
    runtime.release(&readers[1], 20).unwrap();

    let writers = runtime.admit_ready().unwrap();
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].actor(), 30);
    assert_eq!(
        runtime.checked_offset(reference, &writers[0], 30, Ref32Access::write(0, 8, 8)),
        Ok(8)
    );
    assert!(runtime.admit_ready().unwrap().is_empty());
    runtime.release(&writers[0], 30).unwrap();

    let late_readers = runtime.admit_ready().unwrap();
    assert_eq!(late_readers.len(), 1);
    assert_eq!(late_readers[0].actor(), 40);
    runtime.release(&late_readers[0], 40).unwrap();
}

#[test]
fn joint_model_gate_requires_static_proof_and_live_minted_permit() {
    use atto_borrow_checker::actor_critical_guarded_model_v1::{
        verify_joint_model_access, JointModelError, JointModelRequest,
    };

    let f = static_fixture();
    let all_sites = sites(&f);
    let program = critical_program();
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();

    let mut request = JointModelRequest {
        program: &program,
        sites: &all_sites,
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    assert_eq!(verify_joint_model_access(&request), Ok(8));
    request.operation = 5; // Write MUST be derived from typed MIR, not caller intent.
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::Runtime(GuardedRef32Error::Guard(
            GuardError::WriteRequiresExclusive
        )))
    );
    // Non-lexical borrows end after the final request use above.
    runtime.release(&read, 5).unwrap();
    let after_release = JointModelRequest {
        program: &program,
        sites: &all_sites,
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    assert_eq!(
        verify_joint_model_access(&after_release),
        Err(JointModelError::Runtime(GuardedRef32Error::Guard(
            GuardError::UnknownTicket
        )))
    );
}

#[test]
fn joint_model_gate_rejects_wrong_extent_offset_and_operation() {
    use atto_borrow_checker::actor_critical_guarded_model_v1::{
        verify_joint_model_access, JointModelError, JointModelRequest,
    };
    let f = static_fixture();
    let all_sites = sites(&f);
    let program = critical_program();
    let (mut runtime, reference) = runtime_fixture();
    let second = runtime.allocate_before_seal(16, 8).unwrap();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();
    let mut request = JointModelRequest {
        program: &program,
        sites: &all_sites,
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    request.access_bytes = 4;
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::ExtentMismatch)
    );
    request.access_bytes = 8;
    request.runtime_ref = second; // Same actor/permit, but different allocation.
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::OffsetMismatch)
    );
    request.runtime_ref = reference;
    request.operation = 7; // Actor send, not an actual critical read/write.
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::UnknownAccessOperation)
    );
    request.block = 999;
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::UnknownAccessOperation)
    );
    runtime.release(&read, 5).unwrap();
}

#[test]
fn joint_model_gate_rejects_static_actor_or_generation_mismatch() {
    use atto_borrow_checker::actor_critical_guarded_model_v1::{
        verify_joint_model_access, JointModelError, JointModelRequest,
    };
    let program = critical_program();
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();

    let mut f = static_fixture();
    f.arena.actor_id = 6;
    f.allocation.actor_id = 6;
    f.reference.actor_id = 6;
    f.reader.actor_id = 6;
    f.writer.actor_id = 6;
    let all_sites = sites(&f);
    let mut request = JointModelRequest {
        program: &program,
        sites: &all_sites,
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    assert!(verify_critical_ref32_sites(&program, &all_sites).is_ok());
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::DomainMismatch)
    );

    let mut f2 = static_fixture();
    f2.arena.generation = 9;
    f2.allocation.generation = 9;
    f2.reference.generation = 9;
    f2.reader.generation = 9;
    f2.writer.generation = 9;
    let sites2 = sites(&f2);
    request.sites = &sites2;
    assert!(verify_critical_ref32_sites(&program, &sites2).is_ok());
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::DomainMismatch)
    );
    runtime.release(&read, 5).unwrap();
}

#[test]
fn joint_model_gate_denies_missing_static_sites_even_with_live_runtime_permit() {
    use atto_borrow_checker::actor_critical_guarded_model_v1::{
        verify_joint_model_access, JointModelError, JointModelRequest,
    };
    let f = static_fixture();
    let all_sites = sites(&f);
    let program = critical_program();
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();
    let request = JointModelRequest {
        program: &program,
        sites: &all_sites[..2],
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::Static(CriticalRef32Error::MissingSite {
            block: 1,
            operation: 5
        }))
    );
    runtime.release(&read, 5).unwrap();
}

#[test]
fn joint_model_gate_denies_retired_permit_and_cannot_prove_physical_quiescence() {
    use atto_borrow_checker::actor_critical_guarded_model_v1::{
        verify_joint_model_access, JointModelError, JointModelRequest,
    };
    let f = static_fixture();
    let all_sites = sites(&f);
    let program = critical_program();
    let (mut runtime, reference) = runtime_fixture();
    runtime.seal();
    runtime.request(5, 8, Mode::Read).unwrap();
    let read = runtime.admit_ready().unwrap().pop().unwrap();
    runtime.retire(9).unwrap();
    let request = JointModelRequest {
        program: &program,
        sites: &all_sites,
        block: 1,
        operation: 1,
        runtime: &runtime,
        runtime_ref: reference,
        permit: &read,
        trusted_holder: 5,
        displacement: 0,
        access_bytes: 8,
        alignment: 8,
    };
    assert_eq!(
        verify_joint_model_access(&request),
        Err(JointModelError::DomainMismatch)
    );
    assert!(!runtime.may_reclaim());
    runtime.complete_physical_quiescence(&read, 5).unwrap();
    assert!(runtime.may_reclaim());
}
