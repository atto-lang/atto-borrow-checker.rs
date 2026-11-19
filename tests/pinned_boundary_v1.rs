//! Pinning must preserve the pointee address, never silently waive actor,
//! task, scheduler or region admission rules. Native storage handoff is not
//! yet authenticated by this V0 ownership-event profile.
use atto_borrow_checker::{verify, Block, Op, Program, Traits};

fn init(owner: u32) -> Op {
    Op::Init {
        owner,
        traits: Traits {
            is_copy: false,
            is_send: true,
        },
    }
}
fn pin(owner: u32) -> Op {
    Op::PinStorage {
        owner,
        stable_address_proven: true,
    }
}
fn check(
    mut events: Vec<Op>,
) -> Result<atto_borrow_checker::Proof, atto_borrow_checker::Diagnostic> {
    events.push(Op::Return);
    verify(&Program {
        entry: 0,
        blocks: vec![Block {
            id: 0,
            operations: events,
            successors: vec![],
        }],
    })
}
fn must_reject(events: Vec<Op>, expected: &str) {
    assert_eq!(check(events).unwrap_err().code, expected);
}

#[test]
fn moving_only_an_owner_handle_preserves_pin_and_forbids_pointee_relocation() {
    assert!(check(vec![
        init(1),
        pin(1),
        Op::Move { from: 1, into: 2 },
        Op::Read { owner: 2 }
    ])
    .is_ok());
    must_reject(
        vec![
            init(1),
            pin(1),
            Op::Move { from: 1, into: 2 },
            Op::RelocateStorage { owner: 2 },
        ],
        "E_PIN_RELOCATION",
    );
}

#[test]
fn direct_actor_move_of_pinned_storage_is_not_a_verified_address_handoff() {
    must_reject(
        vec![init(1), pin(1), Op::ActorSendMove { owner: 1 }],
        "E_PIN_BOUNDARY_TRANSFER",
    );
}

#[test]
fn mailbox_prepare_must_reject_a_pinned_owner_before_admission() {
    must_reject(
        vec![
            init(1),
            pin(1),
            Op::ActorSendPrepare {
                owner: 1,
                ticket: 7,
            },
        ],
        "E_PIN_BOUNDARY_TRANSFER",
    );
}

#[test]
fn task_capture_move_requires_a_separate_continuation_storage_proof() {
    must_reject(
        vec![init(1), pin(1), Op::TaskCaptureMove { owner: 1 }],
        "E_PIN_BOUNDARY_TRANSFER",
    );
}

#[test]
fn guarded_promotion_must_not_relocate_a_pinned_allocation() {
    must_reject(
        vec![
            init(1),
            pin(1),
            Op::PromoteGuarded {
                owner: 1,
                region: 7,
            },
        ],
        "E_PIN_BOUNDARY_TRANSFER",
    );
}

#[test]
fn frozen_shared_region_publication_also_checks_pinning() {
    must_reject(
        vec![
            init(1),
            pin(1),
            Op::PublishFrozen {
                owner: 1,
                region: 8,
                sync_proven: true,
            },
        ],
        "E_PIN_BOUNDARY_TRANSFER",
    );
}

#[test]
fn copying_to_fresh_storage_does_not_inherit_a_source_pointee_pin() {
    let proof = check(vec![
        init(1),
        pin(1),
        Op::DeepCopy {
            from: 1,
            into: 2,
            graph_proven: true,
        },
        Op::RelocateStorage { owner: 2 },
    ])
    .expect("distinct cloned storage is not pinned");
    assert_eq!(proof.cleanup_by_exit[&0], vec![2, 1]);
}

#[test]
fn dropping_the_pinned_owner_itself_is_safe_after_borrow_release() {
    // drop! ends the pinned allocation lifetime. It does not transfer it to
    // an unknown allocator, and no surviving loan can observe its address.
    assert!(check(vec![init(1), pin(1), Op::Drop { owner: 1 }]).is_ok());
}
