//! Structural safety checks for freeze!, weak!, and pin! lowering.
//!
//! These tests prove event-graph invariants only. They do not allow a compiler
//! to invent a deep-freeze or stable-address witness, and they do not turn
//! ProbeWeak into a usable strong reference without generation-checked runtime
//! upgrade and an independently verified typed result.
use atto_borrow_checker::{
    verify, verify_with_shadow_v0, Block, BorrowKind, Diagnostic, Op, Program, Traits,
};

fn init(owner: u32) -> Op {
    Op::Init {
        owner,
        traits: Traits {
            is_copy: false,
            is_send: true,
        },
    }
}
fn freeze(from: u32, into: u32) -> Op {
    Op::Freeze {
        from,
        into,
        deep_proven: true,
    }
}
fn pin(owner: u32) -> Op {
    Op::PinStorage {
        owner,
        stable_address_proven: true,
    }
}
fn weak(region: u32, id: u32) -> Op {
    Op::CreateWeak {
        region,
        weak: id,
        generation_fenced: true,
    }
}
fn program(mut ops: Vec<Op>) -> Program {
    ops.push(Op::Return);
    Program {
        entry: 0,
        blocks: vec![Block {
            id: 0,
            operations: ops,
            successors: vec![],
        }],
    }
}
fn run(ops: Vec<Op>) -> Result<atto_borrow_checker::Proof, Diagnostic> {
    verify(&program(ops))
}
fn code(ops: Vec<Op>) -> &'static str {
    run(ops).unwrap_err().code
}

#[test]
fn freezing_transfers_owner_and_retains_deterministic_cleanup_order() {
    let proof = run(vec![init(1), freeze(1, 2), Op::Read { owner: 2 }]).unwrap();
    assert_eq!(proof.cleanup_by_exit[&0], vec![2]);
    assert_eq!(
        code(vec![init(1), freeze(1, 2), Op::Read { owner: 1 }]),
        "E_USE_AFTER_MOVE_OR_DROP"
    );
}

#[test]
fn freeze_requires_an_independent_deep_graph_witness() {
    assert_eq!(
        code(vec![
            init(1),
            Op::Freeze {
                from: 1,
                into: 2,
                deep_proven: false
            }
        ]),
        "E_DEEP_FREEZE_PROOF_REQUIRED"
    );
}

#[test]
fn freeze_cannot_invalidate_live_shared_or_mutable_aliases() {
    for kind in [BorrowKind::Shared, BorrowKind::Mutable] {
        assert_eq!(
            code(vec![
                init(1),
                Op::Borrow {
                    owner: 1,
                    loan: 10,
                    kind
                },
                freeze(1, 2)
            ]),
            "E_BORROW_CONFLICT"
        );
    }
}

#[test]
fn frozen_owner_supports_reads_but_never_mutable_access() {
    assert!(run(vec![
        init(1),
        freeze(1, 2),
        Op::Read { owner: 2 },
        Op::Borrow {
            owner: 2,
            loan: 3,
            kind: BorrowKind::Shared
        },
        Op::EndBorrow { loan: 3 }
    ])
    .is_ok());
    assert_eq!(
        code(vec![init(1), freeze(1, 2), Op::Write { owner: 2 }]),
        "E_FROZEN_WRITE"
    );
    assert_eq!(
        code(vec![
            init(1),
            freeze(1, 2),
            Op::Borrow {
                owner: 2,
                loan: 3,
                kind: BorrowKind::Mutable
            }
        ]),
        "E_FROZEN_BORROW_MUT"
    );
}

#[test]
fn moved_frozen_handles_remain_frozen() {
    assert_eq!(
        code(vec![
            init(1),
            freeze(1, 2),
            Op::Move { from: 2, into: 3 },
            Op::Write { owner: 3 }
        ]),
        "E_FROZEN_WRITE"
    );
}

#[test]
fn a_frozen_owner_can_be_published_only_with_an_independent_sync_witness() {
    assert_eq!(
        code(vec![
            init(1),
            freeze(1, 2),
            Op::PublishFrozen {
                owner: 2,
                region: 5,
                sync_proven: false
            }
        ]),
        "E_SHARED_FROZEN_PROOF_REQUIRED"
    );
    assert!(run(vec![
        init(1),
        freeze(1, 2),
        Op::PublishFrozen {
            owner: 2,
            region: 5,
            sync_proven: true
        }
    ])
    .is_ok());
}

#[test]
fn pinning_requires_an_address_stability_witness() {
    assert_eq!(
        code(vec![
            init(1),
            Op::PinStorage {
                owner: 1,
                stable_address_proven: false
            }
        ]),
        "E_PIN_ADDRESS_PROOF_REQUIRED"
    );
    assert!(run(vec![init(1), pin(1), Op::Read { owner: 1 }]).is_ok());
    assert_eq!(code(vec![init(1), pin(1), pin(1)]), "E_ALREADY_PINNED");
}

#[test]
fn moving_a_pinned_handle_does_not_unpin_pointee_storage() {
    assert!(run(vec![
        init(1),
        pin(1),
        Op::Move { from: 1, into: 2 },
        Op::Read { owner: 2 }
    ])
    .is_ok());
    assert_eq!(
        code(vec![
            init(1),
            pin(1),
            Op::Move { from: 1, into: 2 },
            Op::RelocateStorage { owner: 2 }
        ]),
        "E_PIN_RELOCATION"
    );
    assert!(run(vec![init(1), Op::RelocateStorage { owner: 1 }]).is_ok());
}

#[test]
fn pinned_storage_cannot_be_reinterpreted_through_freeze_or_relocated_while_loaned() {
    assert_eq!(
        code(vec![init(1), pin(1), freeze(1, 2)]),
        "E_PIN_STORAGE_TRANSFER"
    );
    assert_eq!(
        code(vec![
            init(1),
            Op::Borrow {
                owner: 1,
                loan: 3,
                kind: BorrowKind::Shared
            },
            pin(1)
        ]),
        "E_BORROW_CONFLICT"
    );
    assert_eq!(
        code(vec![
            init(1),
            Op::Borrow {
                owner: 1,
                loan: 3,
                kind: BorrowKind::Shared
            },
            Op::RelocateStorage { owner: 1 }
        ]),
        "E_BORROW_CONFLICT"
    );
}

#[test]
fn pin_does_not_waive_suspension_lifetime_rules() {
    assert_eq!(
        code(vec![
            init(1),
            pin(1),
            Op::Borrow {
                owner: 1,
                loan: 3,
                kind: BorrowKind::Shared
            },
            Op::Suspend
        ]),
        "E_SUSPEND_WITH_LIVE_LOAN"
    );
}

#[test]
fn weak_handles_require_published_frozen_storage_not_arbitrary_mutable_owners() {
    assert_eq!(
        code(vec![init(1), weak(5, 7)]),
        "E_WEAK_SHARED_REGION_REQUIRED"
    );
    assert!(run(vec![
        init(1),
        Op::PublishFrozen {
            owner: 1,
            region: 5,
            sync_proven: true
        },
        weak(5, 7),
        Op::ProbeWeak {
            weak: 7,
            generation_fenced: true
        }
    ])
    .is_ok());
}

#[test]
fn weak_handles_cannot_fake_generation_checks() {
    assert_eq!(
        code(vec![
            init(1),
            Op::PublishFrozen {
                owner: 1,
                region: 5,
                sync_proven: true
            },
            Op::CreateWeak {
                region: 5,
                weak: 7,
                generation_fenced: false
            }
        ]),
        "E_WEAK_GENERATION_PROOF_REQUIRED"
    );
    assert_eq!(
        code(vec![
            init(1),
            Op::PublishFrozen {
                owner: 1,
                region: 5,
                sync_proven: true
            },
            weak(5, 7),
            Op::ProbeWeak {
                weak: 7,
                generation_fenced: false
            }
        ]),
        "E_WEAK_GENERATION_PROOF_REQUIRED"
    );
}

#[test]
fn unknown_duplicate_or_zero_weak_handle_ids_fail_closed() {
    assert_eq!(
        code(vec![Op::ProbeWeak {
            weak: 17,
            generation_fenced: true
        }]),
        "E_UNKNOWN_WEAK"
    );
    assert_eq!(
        code(vec![
            init(1),
            Op::PublishFrozen {
                owner: 1,
                region: 5,
                sync_proven: true
            },
            weak(5, 0)
        ]),
        "E_WEAK_ID_ZERO"
    );
    assert_eq!(
        code(vec![
            init(1),
            Op::PublishFrozen {
                owner: 1,
                region: 5,
                sync_proven: true
            },
            weak(5, 7),
            weak(5, 7)
        ]),
        "E_WEAK_DEF_REUSED"
    );
}

#[test]
fn shadow_does_not_publish_tentative_capability_success() {
    let mut observed = Vec::new();
    let result = verify_with_shadow_v0(
        &program(vec![init(1), pin(1), Op::RelocateStorage { owner: 1 }]),
        &mut |event| {
            observed.push(event);
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().code, "E_PIN_RELOCATION");
    assert!(observed.is_empty());
}

#[test]
fn shadow_records_successful_freeze_and_weak_provenance_in_order() {
    let mut observed = Vec::new();
    verify_with_shadow_v0(
        &program(vec![
            init(1),
            freeze(1, 2),
            Op::PublishFrozen {
                owner: 2,
                region: 5,
                sync_proven: true,
            },
            weak(5, 7),
            Op::ProbeWeak {
                weak: 7,
                generation_fenced: true,
            },
        ]),
        &mut |event| {
            observed.push(event.kind);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        observed,
        [
            "INIT",
            "FREEZE",
            "PUBLISH_FROZEN",
            "CREATE_WEAK",
            "PROBE_WEAK",
            "RETURN"
        ]
    );
}
