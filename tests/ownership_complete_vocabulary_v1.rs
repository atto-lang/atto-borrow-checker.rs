//! Canonical ownership-event verification for the complete AttoLang vocabulary.
//! These are source-independent typed-MIR invariants, not emitted guest binaries.
use atto_borrow_checker::{verify, Block, BorrowKind, Op, Program, Traits};

fn own(id: u32, is_copy: bool) -> Op {
    Op::Init {
        owner: id,
        traits: Traits {
            is_copy,
            is_send: true,
        },
    }
}
fn program(mut events: Vec<Op>) -> Program {
    events.push(Op::Return);
    Program {
        entry: 0,
        blocks: vec![Block {
            id: 0,
            operations: events,
            successors: vec![],
        }],
    }
}
fn fails(events: Vec<Op>, expected: &str) {
    assert_eq!(verify(&program(events)).unwrap_err().code, expected);
}
fn deep(from: u32, into: u32, proof: bool) -> Op {
    Op::DeepCopy {
        from,
        into,
        graph_proven: proof,
    }
}

#[test]
fn copy_bang_requires_copy_trait_but_copy_double_bang_accepts_owned_noncopy_graphs() {
    fails(
        vec![own(1, false), Op::Copy { from: 1, into: 2 }],
        "E_COPY_PROOF_REQUIRED",
    );
    let result = verify(&program(vec![
        own(1, false),
        deep(1, 2, true),
        Op::Read { owner: 1 },
        Op::Read { owner: 2 },
    ]))
    .unwrap();
    assert_eq!(result.cleanup_by_exit[&0], vec![2, 1]);
}

#[test]
fn clone_proof_must_cover_entire_graph_and_be_independently_derived() {
    fails(
        vec![own(1, false), deep(1, 2, false)],
        "E_DEEP_COPY_PROOF_REQUIRED",
    );
    fails(vec![own(1, false), deep(1, 1, true)], "E_OWNER_DEF_REUSED");
    fails(vec![own(1, false), deep(1, 0, true)], "E_OWNER_ID_ZERO");
}

#[test]
fn copy_double_bang_rejects_read_of_moved_source_or_unfinished_exclusive_loan() {
    fails(
        vec![
            own(1, false),
            Op::Move { from: 1, into: 3 },
            deep(1, 2, true),
        ],
        "E_USE_AFTER_MOVE_OR_DROP",
    );
    fails(
        vec![
            own(1, false),
            Op::Borrow {
                owner: 1,
                loan: 7,
                kind: BorrowKind::Mutable,
            },
            deep(1, 2, true),
        ],
        "E_BORROW_CONFLICT",
    );
}

#[test]
fn deep_copy_may_observe_shared_loan_but_must_not_inherit_source_pin() {
    let out = verify(&program(vec![
        own(1, false),
        Op::PinStorage {
            owner: 1,
            stable_address_proven: true,
        },
        Op::Borrow {
            owner: 1,
            loan: 7,
            kind: BorrowKind::Shared,
        },
        deep(1, 2, true),
        Op::EndBorrow { loan: 7 },
        Op::RelocateStorage { owner: 2 },
    ]))
    .unwrap();
    assert_eq!(out.cleanup_by_exit[&0], vec![2, 1]);
    fails(
        vec![
            own(1, false),
            Op::PinStorage {
                owner: 1,
                stable_address_proven: true,
            },
            deep(1, 2, true),
            Op::RelocateStorage { owner: 1 },
        ],
        "E_PIN_RELOCATION",
    );
}

#[test]
fn copied_frozen_graph_remains_immutable_without_aliasing_back_to_source() {
    fails(
        vec![
            own(1, false),
            Op::Freeze {
                from: 1,
                into: 2,
                deep_proven: true,
            },
            deep(2, 3, true),
            Op::Write { owner: 3 },
        ],
        "E_FROZEN_WRITE",
    );
}

#[test]
fn explicit_drop_consumes_owner_and_never_double_releases() {
    let out = verify(&program(vec![
        own(1, false),
        own(2, false),
        Op::Drop { owner: 2 },
    ]))
    .unwrap();
    assert_eq!(out.cleanup_by_exit[&0], vec![1]);
    fails(
        vec![own(1, false), Op::Drop { owner: 1 }, Op::Drop { owner: 1 }],
        "E_USE_AFTER_MOVE_OR_DROP",
    );
    fails(
        vec![own(1, false), Op::Drop { owner: 1 }, Op::Read { owner: 1 }],
        "E_USE_AFTER_MOVE_OR_DROP",
    );
    fails(
        vec![
            own(1, false),
            Op::Move { from: 1, into: 2 },
            Op::Drop { owner: 1 },
        ],
        "E_USE_AFTER_MOVE_OR_DROP",
    );
}

#[test]
fn dropping_a_borrowed_owner_is_rejected_until_the_loan_releases() {
    fails(
        vec![
            own(1, false),
            Op::Borrow {
                owner: 1,
                loan: 4,
                kind: BorrowKind::Shared,
            },
            Op::Drop { owner: 1 },
        ],
        "E_BORROW_CONFLICT",
    );
    assert!(verify(&program(vec![
        own(1, false),
        Op::Borrow {
            owner: 1,
            loan: 4,
            kind: BorrowKind::Shared
        },
        Op::EndBorrow { loan: 4 },
        Op::Drop { owner: 1 }
    ]))
    .is_ok());
}

#[test]
fn sharing_and_freezing_remain_different_rights() {
    // PublishFrozen does NOT synthesize a frozen value from a temporary
    // read-only borrow. It consumes the unique source owner and demands an
    // independent Sync/Send witness verified by the compiler.
    fails(
        vec![
            own(1, false),
            Op::Borrow {
                owner: 1,
                loan: 2,
                kind: BorrowKind::Shared,
            },
            Op::PublishFrozen {
                owner: 1,
                region: 3,
                sync_proven: true,
            },
        ],
        "E_BORROW_CONFLICT",
    );
    fails(
        vec![
            own(1, false),
            Op::PublishFrozen {
                owner: 1,
                region: 3,
                sync_proven: false,
            },
        ],
        "E_SHARED_FROZEN_PROOF_REQUIRED",
    );
}
