use atto_borrow_checker::master_dual_v1::{verify_dual_profile, DualError};
use atto_borrow_checker::master_evidence_v1::{
    verify_strict, EvidenceRequest, EvidenceResolver, ProofKind, StrictError,
};
use atto_borrow_checker::mir_v1::{
    Effect, Instruction, MirBlock, MirError, MirFunction, Producer, CONTRACT_VERSION,
};
use atto_borrow_checker::ownership_bang_v1::{
    BangError, BangManifest, BangSite, SourceAuthority, Spelling, Verb,
    CONTRACT_VERSION as BANG_VERSION,
};
use atto_borrow_checker::{Block, BorrowKind, Op, Program, Traits};
use std::collections::BTreeSet;

fn op(id: u64, operation: Op) -> Instruction {
    let effect = match &operation {
        Op::Return => Effect::Control,
        Op::Suspend => Effect::Suspension,
        Op::PublishFrozen { .. }
        | Op::PromoteGuarded { .. }
        | Op::ActorSendMove { .. }
        | Op::ActorSendCopy { .. }
        | Op::ActorSendPrepare { .. }
        | Op::ActorSendCommit { .. }
        | Op::ActorSendAbort { .. }
        | Op::ActorHopBorrow { .. } => Effect::ActorBoundary,
        _ => Effect::Ownership,
    };
    Instruction {
        instruction_id: id,
        source_node_id: id + 100,
        operation,
        effect,
    }
}
fn typed(ops: Vec<Op>) -> MirFunction {
    let instructions: Vec<_> = ops
        .into_iter()
        .enumerate()
        .map(|(i, o)| op(i as u64 + 1, o))
        .collect();
    MirFunction {
        version: CONTRACT_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 17,
            function_id: 29,
        },
        entry: 0,
        expected_instruction_ids: instructions.iter().map(|i| i.instruction_id).collect(),
        blocks: vec![MirBlock {
            id: 0,
            instructions,
            successors: vec![],
        }],
    }
}
fn init(copy: bool, send: bool) -> Op {
    Op::Init {
        owner: 1,
        traits: Traits {
            is_copy: copy,
            is_send: send,
        },
    }
}
fn empty() -> BangManifest {
    BangManifest {
        version: BANG_VERSION.into(),
        sites: vec![],
        source_bang_instruction_ids: vec![],
    }
}
fn site(id: u64, verb: Verb) -> BangSite {
    BangSite {
        instruction_id: id,
        source_node_id: id + 100,
        verb,
        spelling: Spelling::Preferred,
        source_authority: SourceAuthority::Owned,
        from: 1,
        into: None,
        loan: None,
        region: None,
        place_is_writable: false,
        detached_copy_proven: false,
        frozen_sync_proven: false,
    }
}
fn manifest(sites: Vec<BangSite>) -> BangManifest {
    BangManifest {
        version: BANG_VERSION.into(),
        source_bang_instruction_ids: sites.iter().map(|s| s.instruction_id).collect(),
        sites,
    }
}
#[derive(Default)]
struct StubResolver {
    deny: BTreeSet<ProofKind>,
    observed: Vec<EvidenceRequest>,
    producer_seen: bool,
}
impl EvidenceResolver for StubResolver {
    fn prove(&mut self, producer: &Producer, request: &EvidenceRequest) -> bool {
        self.producer_seen = producer.function_id == 29
            && producer.source_unit_id == 17
            && producer.compiler_git_sha == "a".repeat(40)
            && producer.source_sha256 == "b".repeat(64);
        self.observed.push(request.clone());
        !self.deny.contains(&request.kind)
    }
}
fn deny(kind: ProofKind) -> StubResolver {
    StubResolver {
        deny: BTreeSet::from([kind]),
        ..StubResolver::default()
    }
}
fn borrow_op(loan: u32, kind: BorrowKind) -> Op {
    Op::Borrow {
        owner: 1,
        loan,
        kind,
    }
}
fn borrow_site(id: u64, loan: u32, mutable: bool) -> BangSite {
    let mut s = site(
        id,
        if mutable {
            Verb::BorrowMut
        } else {
            Verb::Borrow
        },
    );
    s.loan = Some(loan);
    s.place_is_writable = mutable;
    s
}

#[test]
fn independent_copy_witness_required_even_if_mir_claims_copy() {
    let f = typed(vec![
        init(true, false),
        Op::Copy { from: 1, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    let mut r = deny(ProofKind::CopyTrait);
    let err = verify_strict(&f, &manifest(vec![s.clone()]), &mut r).unwrap_err();
    assert!(matches!(err, StrictError::EvidenceDenied(req) if req.kind == ProofKind::CopyTrait));
    let mut ok = StubResolver::default();
    assert_eq!(
        verify_strict(&f, &manifest(vec![s]), &mut ok)
            .unwrap()
            .cleanup_by_exit[&0],
        vec![2, 1]
    );
    assert!(ok.producer_seen);
}

#[test]
fn independent_send_witness_required_even_when_type_bit_is_true() {
    let f = typed(vec![
        init(false, true),
        Op::ActorSendMove { owner: 1 },
        Op::Return,
    ]);
    let mut r = deny(ProofKind::SendTrait);
    assert!(matches!(
        verify_strict(&f, &empty(), &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::SendTrait
    ));
}

#[test]
fn source_owner_authority_cannot_be_derived_from_mir_claims() {
    let f = typed(vec![
        init(true, false),
        Op::Copy { from: 1, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    let mut r = deny(ProofKind::OwnedAuthority);
    assert!(matches!(
        verify_strict(&f, &manifest(vec![s]), &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::OwnedAuthority
    ));
}

#[test]
fn frozen_publication_requires_independent_sync_proof() {
    let f = typed(vec![
        init(false, true),
        Op::PublishFrozen {
            owner: 1,
            region: 7,
            sync_proven: true,
        },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Share);
    s.region = Some(7);
    s.frozen_sync_proven = true;
    let mut r = deny(ProofKind::FrozenSync);
    assert!(matches!(
        verify_strict(&f, &manifest(vec![s]), &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::FrozenSync
    ));
}

#[test]
fn detached_copy_through_loan_requires_independent_escape_proof() {
    let f = typed(vec![
        init(true, false),
        borrow_op(10, BorrowKind::Shared),
        Op::CopyThrough {
            owner: 1,
            loan: 10,
            into: 2,
            detached_proven: true,
        },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mut s = site(3, Verb::Copy);
    s.into = Some(2);
    s.loan = Some(10);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.detached_copy_proven = true;
    let m = manifest(vec![borrow_site(2, 10, false), s]);
    let mut r = deny(ProofKind::DetachedOwnedCopy);
    assert!(matches!(
        verify_strict(&f, &m, &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::DetachedOwnedCopy
    ));
    let mut r = deny(ProofKind::BorrowedLoanRoot);
    assert!(matches!(
        verify_strict(&f, &m, &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::BorrowedLoanRoot
    ));
}

#[test]
fn mutable_borrow_witness_required_from_independent_resolver() {
    let f = typed(vec![
        init(false, false),
        borrow_op(10, BorrowKind::Mutable),
        Op::WriteThrough { owner: 1, loan: 10 },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mut r = deny(ProofKind::MutablePlace);
    assert!(matches!(
        verify_strict(&f, &manifest(vec![borrow_site(2, 10, true)]), &mut r),
        Err(StrictError::EvidenceDenied(req)) if req.kind == ProofKind::MutablePlace
    ));
}

#[test]
fn rejected_mir_publishes_no_evidence_callbacks() {
    let f = typed(vec![init(false, false), Op::Read { owner: 99 }, Op::Return]);
    let mut r = StubResolver::default();
    assert!(matches!(
        verify_strict(&f, &empty(), &mut r),
        Err(StrictError::Canonical(BangError::Mir(MirError::Unsafe(_))))
    ));
    assert!(r.observed.is_empty());
}

#[test]
fn malformed_source_manifest_publishes_no_evidence_callbacks() {
    let f = typed(vec![
        init(true, false),
        Op::Copy { from: 1, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    let mut r = StubResolver::default();
    assert_eq!(
        verify_strict(&f, &manifest(vec![s]), &mut r),
        Err(StrictError::Canonical(BangError::Invalid(
            "E_BANG_MIR_MISMATCH"
        )))
    );
    assert!(r.observed.is_empty());
}

#[test]
fn witness_requests_are_deterministic_and_producer_bound() {
    let f = typed(vec![
        init(true, true),
        borrow_op(10, BorrowKind::Mutable),
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mut a = StubResolver::default();
    let mut b = StubResolver::default();
    let m = manifest(vec![borrow_site(2, 10, true)]);
    verify_strict(&f, &m, &mut a).unwrap();
    verify_strict(&f, &m, &mut b).unwrap();
    assert_eq!(a.observed, b.observed);
    assert_eq!(a.observed.len(), 4);
    assert!(a.producer_seen);
    let kinds: BTreeSet<_> = a.observed.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            ProofKind::CopyTrait,
            ProofKind::SendTrait,
            ProofKind::MutablePlace,
            ProofKind::OwnedAuthority,
        ])
    );
}

#[test]
fn dual_checker_accepts_shared_loan_and_preserves_v0_cleanup() {
    let f = typed(vec![
        init(false, false),
        borrow_op(10, BorrowKind::Shared),
        Op::ReadThrough { owner: 1, loan: 10 },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let p = verify_dual_profile(
        &f,
        &manifest(vec![borrow_site(2, 10, false)]),
        &mut StubResolver::default(),
    )
    .unwrap();
    assert_eq!(p.v0.cleanup_by_exit[&0], vec![1]);
    assert_eq!(p.cyclic.validated_operations, 4);
}

#[test]
fn dual_checker_accepts_exclusive_write_only_via_loan() {
    let f = typed(vec![
        init(false, false),
        borrow_op(10, BorrowKind::Mutable),
        Op::WriteThrough { owner: 1, loan: 10 },
        Op::EndBorrow { loan: 10 },
        Op::Write { owner: 1 },
        Op::Return,
    ]);
    assert!(verify_dual_profile(
        &f,
        &manifest(vec![borrow_site(2, 10, true)]),
        &mut StubResolver::default()
    )
    .is_ok());
}

#[test]
fn dual_checker_does_not_override_canonical_loan_conflict() {
    let f = typed(vec![
        init(false, false),
        borrow_op(10, BorrowKind::Shared),
        Op::Write { owner: 1 },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    assert!(matches!(
        verify_dual_profile(
            &f,
            &manifest(vec![borrow_site(2, 10, false)]),
            &mut StubResolver::default()
        ),
        Err(DualError::Strict(StrictError::Canonical(BangError::Mir(
            MirError::Unsafe(_)
        ))))
    ));
}

#[test]
fn dual_checker_rejects_copies_without_full_minting_semantics() {
    let f = typed(vec![
        init(true, false),
        Op::Copy { from: 1, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    assert!(matches!(
        verify_dual_profile(&f, &manifest(vec![s]), &mut StubResolver::default()),
        Err(DualError::Unsupported {
            code: "E_DUAL_UNMODELED_OPERATION",
            ..
        })
    ));
}

#[test]
fn dual_checker_rejects_moves_without_full_minting_semantics() {
    let f = typed(vec![
        init(false, false),
        Op::Move { from: 1, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    assert!(matches!(
        verify_dual_profile(&f, &manifest(vec![s]), &mut StubResolver::default()),
        Err(DualError::Unsupported {
            code: "E_DUAL_UNMODELED_OPERATION",
            ..
        })
    ));
}

#[test]
fn dual_checker_rejects_actor_send_and_shared_regions() {
    for op in [
        Op::ActorSendMove { owner: 1 },
        Op::PromoteGuarded {
            owner: 1,
            region: 7,
        },
    ] {
        let f = typed(vec![init(false, true), op, Op::Return]);
        assert!(matches!(
            verify_dual_profile(&f, &empty(), &mut StubResolver::default()),
            Err(DualError::Unsupported {
                code: "E_DUAL_UNMODELED_OPERATION",
                ..
            })
        ));
    }
}

#[test]
fn dual_checker_rejects_late_root_initialization() {
    let f = typed(vec![
        init(false, false),
        Op::Read { owner: 1 },
        Op::Init {
            owner: 2,
            traits: Traits {
                is_copy: false,
                is_send: false,
            },
        },
        Op::Return,
    ]);
    assert!(matches!(
        verify_dual_profile(&f, &empty(), &mut StubResolver::default()),
        Err(DualError::Unsupported {
            code: "E_DUAL_LATE_INIT",
            ..
        })
    ));
}

#[test]
fn dual_checker_preserves_terminal_drop_and_empty_cleanup() {
    let f = typed(vec![init(false, false), Op::Drop { owner: 1 }, Op::Return]);
    assert_eq!(
        verify_dual_profile(&f, &empty(), &mut StubResolver::default())
            .unwrap()
            .v0
            .cleanup_by_exit[&0],
        Vec::<u32>::new()
    );
}

#[test]
fn dual_checker_must_reject_cyclic_cfg_until_cleanup_is_proved() {
    let mut f = typed(vec![init(false, false)]);
    f.blocks[0].successors = vec![1];
    f.blocks.push(MirBlock {
        id: 1,
        instructions: vec![op(2, Op::Read { owner: 1 })],
        successors: vec![1, 2],
    });
    f.blocks.push(MirBlock {
        id: 2,
        instructions: vec![op(3, Op::Return)],
        successors: vec![],
    });
    f.expected_instruction_ids = vec![1, 2, 3];
    assert!(matches!(
        verify_dual_profile(&f, &empty(), &mut StubResolver::default()),
        Err(DualError::Strict(StrictError::Canonical(BangError::Mir(
            MirError::Unsafe(_)
        ))))
    ));
}

#[test]
fn dual_checker_does_not_erase_v0_unmodeled_loan_escape() {
    let f = typed(vec![
        init(false, false),
        borrow_op(10, BorrowKind::Shared),
        Op::Return,
    ]);
    assert!(matches!(
        verify_dual_profile(
            &f,
            &manifest(vec![borrow_site(2, 10, false)]),
            &mut StubResolver::default()
        ),
        Err(DualError::Strict(StrictError::Canonical(BangError::Mir(
            MirError::Unsafe(_)
        ))))
    ));
}

#[test]
fn source_only_v0_graph_is_not_a_substitute_for_attested_inventory() {
    let p = Program {
        entry: 0,
        blocks: vec![Block {
            id: 0,
            operations: vec![init(true, true), Op::Copy { from: 1, into: 2 }, Op::Return],
            successors: vec![],
        }],
    };
    assert!(atto_borrow_checker::verify(&p).is_ok());
    let f = typed(p.blocks[0].operations.clone());
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    let mut denied = deny(ProofKind::CopyTrait);
    assert!(verify_strict(&f, &manifest(vec![s]), &mut denied).is_err());
}
