//! Adversarial and metamorphic tests of the model-only bang-to-MIR contract.
//! These intentionally do not claim that a frontend parsed or executed .atto.
use atto_borrow_checker::mir_v1::{
    Effect, Instruction, MirBlock, MirError, MirFunction, Producer, CONTRACT_VERSION as MIR_VERSION,
};
use atto_borrow_checker::ownership_bang_v1::{
    verify_bang_mir, BangError, BangManifest, BangSite, SourceAuthority, Spelling, Verb,
    CONTRACT_VERSION as BANG_VERSION,
};
use atto_borrow_checker::{BorrowKind, Op, Proof, Traits};

fn init(owner: u32, copy: bool, send: bool) -> Op {
    Op::Init { owner, traits: Traits { is_copy: copy, is_send: send } }
}
fn instruction(id: u64, op: Op) -> Instruction {
    let effect = match &op {
        Op::Return => Effect::Control,
        Op::Suspend => Effect::Suspension,
        Op::ActorSendPrepare { .. }
        | Op::ActorSendCommit { .. }
        | Op::ActorSendAbort { .. }
        | Op::ActorSendMove { .. }
        | Op::ActorSendCopy { .. }
        | Op::ActorHopBorrow { .. }
        | Op::PublishFrozen { .. }
        | Op::PromoteGuarded { .. } => Effect::ActorBoundary,
        _ => Effect::Ownership,
    };
    Instruction { instruction_id: id, source_node_id: id + 100, effect, operation: op }
}
fn function(ops: Vec<Op>) -> MirFunction {
    let instructions: Vec<_> = ops.into_iter().enumerate().map(|(i, op)| instruction(i as u64 + 1, op)).collect();
    MirFunction {
        version: MIR_VERSION.to_owned(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 19,
            function_id: 20,
        },
        entry: 0,
        expected_instruction_ids: instructions.iter().map(|i| i.instruction_id).collect(),
        blocks: vec![MirBlock { id: 0, instructions, successors: vec![] }],
    }
}
fn site(id: u64, verb: Verb, from: u32) -> BangSite {
    BangSite {
        instruction_id: id,
        source_node_id: id + 100,
        verb,
        spelling: Spelling::Preferred,
        source_authority: SourceAuthority::Owned,
        from,
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
        version: BANG_VERSION.to_owned(),
        source_bang_instruction_ids: sites.iter().map(|s| s.instruction_id).collect(),
        sites,
    }
}
fn run(ops: Vec<Op>, sites: Vec<BangSite>) -> Result<Proof, BangError> {
    verify_bang_mir(&function(ops), &manifest(sites))
}
fn semantic_code(ops: Vec<Op>, sites: Vec<BangSite>) -> &'static str {
    match run(ops, sites).unwrap_err() {
        BangError::Mir(MirError::Unsafe(diagnostic)) => diagnostic.code,
        error => panic!("expected a semantic error, got {error:?}"),
    }
}
fn copy_site(id: u64, from: u32, into: u32) -> BangSite {
    let mut s = site(id, Verb::Copy, from);
    s.into = Some(into);
    s
}
fn take_site(id: u64, from: u32, into: u32) -> BangSite {
    let mut s = site(id, Verb::Take, from);
    s.into = Some(into);
    s
}
fn borrow_site(id: u64, owner: u32, loan: u32, mutable: bool) -> BangSite {
    let mut s = site(id, if mutable { Verb::BorrowMut } else { Verb::Borrow }, owner);
    s.loan = Some(loan);
    s.place_is_writable = mutable;
    s
}
fn share_site(id: u64, owner: u32, region: u32) -> BangSite {
    let mut s = site(id, Verb::Share, owner);
    s.region = Some(region);
    s.frozen_sync_proven = true;
    s
}

#[test]
fn strict_share_requires_explicit_sync_witness() {
    let ops = vec![init(1, true, true), Op::PublishFrozen { owner: 1, region: 5, sync_proven: true }, Op::Return];
    let mut s = share_site(2, 1, 5);
    s.frozen_sync_proven = false;
    assert_eq!(run(ops.clone(), vec![s]), Err(BangError::Invalid("E_BANG_SYNC_PROOF_REQUIRED")));
    assert!(run(ops, vec![share_site(2, 1, 5)]).is_ok());
}

#[test]
fn a_sync_witness_on_copy_is_rejected_as_unused() {
    let ops = vec![init(1, true, true), Op::Copy { from: 1, into: 2 }, Op::Return];
    let mut s = copy_site(2, 1, 2);
    s.frozen_sync_proven = true;
    assert_eq!(run(ops, vec![s]), Err(BangError::Invalid("E_BANG_UNUSED_SYNC_PROOF")));
}

#[test]
fn a_share_site_never_accepts_weakening_mir_sync_evidence() {
    let ops = vec![init(1, true, true), Op::PublishFrozen { owner: 1, region: 5, sync_proven: false }, Op::Return];
    assert_eq!(run(ops, vec![share_site(2, 1, 5)]), Err(BangError::Invalid("E_BANG_MIR_MISMATCH")));
}

#[test]
fn copy_does_not_inherit_send_from_non_send_type() {
    let ops = vec![
        init(1, true, false), Op::Copy { from: 1, into: 2 },
        Op::ActorSendCopy { owner: 2 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![copy_site(2, 1, 2)]), "E_ACTOR_COPY_SEND_PROOF_REQUIRED");
}

#[test]
fn copy_through_shared_loan_without_detach_evidence_fails_closed() {
    let ops = vec![
        init(1, true, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::CopyThrough { owner: 1, loan: 10, into: 2, detached_proven: false },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    let mut s = copy_site(3, 1, 2);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.loan = Some(10);
    assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, false), s]), "E_DETACHED_COPY_PROOF_REQUIRED");
}

#[test]
fn copied_loan_cannot_forge_detachment_against_mir() {
    let ops = vec![
        init(1, true, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::CopyThrough { owner: 1, loan: 10, into: 2, detached_proven: false },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    let mut s = copy_site(3, 1, 2);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.loan = Some(10);
    s.detached_copy_proven = true;
    assert_eq!(
        run(ops, vec![borrow_site(2, 1, 10, false), s]),
        Err(BangError::Invalid("E_BANG_MIR_MISMATCH"))
    );
}

#[test]
fn copy_through_borrow_does_not_accept_noncopy_type() {
    let ops = vec![
        init(1, false, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::CopyThrough { owner: 1, loan: 10, into: 2, detached_proven: true },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    let mut s = copy_site(3, 1, 2);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.loan = Some(10);
    s.detached_copy_proven = true;
    assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, false), s]), "E_COPY_PROOF_REQUIRED");
}

#[test]
fn copy_through_loan_bound_to_another_root_rejected() {
    let ops = vec![
        init(1, true, true), init(2, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::CopyThrough { owner: 2, loan: 10, into: 3, detached_proven: true },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    let mut s = copy_site(4, 2, 3);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.loan = Some(10);
    s.detached_copy_proven = true;
    assert_eq!(semantic_code(ops, vec![borrow_site(3, 1, 10, false), s]), "E_LOAN_NOT_ACTIVE_OR_WRONG_OWNER");
}

#[test]
fn read_through_loan_bound_to_another_root_rejected() {
    let ops = vec![
        init(1, true, true), init(2, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::ReadThrough { owner: 2, loan: 10 },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![borrow_site(3, 1, 10, false)]), "E_LOAN_NOT_ACTIVE_OR_WRONG_OWNER");
}

#[test]
fn immutable_loan_denies_write_through_even_if_loan_matches() {
    let ops = vec![
        init(1, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::WriteThrough { owner: 1, loan: 10 },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, false)]), "E_MUT_LOAN_REQUIRED");
}

#[test]
fn active_mutable_loan_denies_raw_copy_and_direct_read() {
    let borrow = Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Mutable };
    for conflicting in [Op::Copy { from: 1, into: 2 }, Op::Read { owner: 1 }, Op::Write { owner: 1 }] {
        let ops = vec![init(1, true, true), borrow.clone(), conflicting, Op::EndBorrow { loan: 10 }, Op::Return];
        assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, true)]), "E_BORROW_CONFLICT");
    }
}

#[test]
fn shared_loan_allows_copy_but_denies_take_until_release() {
    let ops = vec![
        init(1, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Copy { from: 1, into: 2 }, Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert!(run(ops, vec![borrow_site(2, 1, 10, false), copy_site(3, 1, 2)]).is_ok());
    let ops = vec![
        init(1, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Move { from: 1, into: 2 }, Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, false), take_site(3, 1, 2)]), "E_BORROW_CONFLICT");
}

#[test]
fn take_after_loan_release_succeeds_with_exactly_one_new_owner() {
    let ops = vec![
        init(1, false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::EndBorrow { loan: 10 },
        Op::Move { from: 1, into: 2 }, Op::Return,
    ];
    assert_eq!(run(ops, vec![borrow_site(2, 1, 10, false), take_site(4, 1, 2)]).unwrap().cleanup_by_exit[&0], vec![2]);
}

#[test]
fn borrowing_an_escrowed_actor_send_payload_fails_closed() {
    let ops = vec![
        init(1, true, true),
        Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::ActorSendAbort { ticket: 7 },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![borrow_site(3, 1, 10, false)]), "E_ACTOR_SEND_PENDING");
}

#[test]
fn aborting_send_escrow_allows_subsequent_borrow() {
    let ops = vec![
        init(1, true, true),
        Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendAbort { ticket: 7 },
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert!(run(ops, vec![borrow_site(4, 1, 10, false)]).is_ok());
}

#[test]
fn committed_actor_send_consumes_owner_before_copy_or_share() {
    let ops = vec![
        init(1, true, true),
        Op::ActorSendPrepare { owner: 1, ticket: 7 },
        Op::ActorSendCommit { ticket: 7 },
        Op::Copy { from: 1, into: 2 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![copy_site(4, 1, 2)]), "E_USE_AFTER_MOVE_OR_DROP");
}

#[test]
fn share_is_forbidden_until_all_shared_loans_end() {
    let ops = vec![
        init(1, true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::PublishFrozen { owner: 1, region: 7, sync_proven: true },
        Op::EndBorrow { loan: 10 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![borrow_site(2, 1, 10, false), share_site(3, 1, 7)]), "E_BORROW_CONFLICT");
}

#[test]
fn cannot_read_original_owner_after_share_publication() {
    let ops = vec![
        init(1, true, true),
        Op::PublishFrozen { owner: 1, region: 7, sync_proven: true },
        Op::Read { owner: 1 }, Op::Return,
    ];
    assert_eq!(semantic_code(ops, vec![share_site(2, 1, 7)]), "E_USE_AFTER_MOVE_OR_DROP");
}

#[test]
fn distinct_region_id_is_mandatory_even_when_source_site_matches() {
    let ops = vec![
        init(1, true, true),
        Op::PublishFrozen { owner: 1, region: 0, sync_proven: true },
        Op::Return,
    ];
    match run(ops, vec![share_site(2, 1, 0)]) {
        Err(BangError::Mir(MirError::Unsafe(diagnostic))) => assert_eq!(diagnostic.code, "E_REGION_ID_ZERO"),
        other => panic!("expected zero-region denial, got {other:?}"),
    }
}

#[test]
fn fabricated_borrowed_authority_cannot_create_a_second_loan() {
    let ops = vec![init(1, true, true), Op::Borrow { owner: 1, loan: 11, kind: BorrowKind::Shared }, Op::EndBorrow { loan: 11 }, Op::Return];
    let mut s = borrow_site(2, 1, 11, false);
    s.source_authority = SourceAuthority::BorrowedLoan;
    assert_eq!(run(ops, vec![s]), Err(BangError::Invalid("E_BANG_REBORROW_UNPROVEN")));
}

#[test]
fn wrong_bang_site_kind_and_compiler_mir_mapping_rejected() {
    let ops = vec![init(1, true, true), Op::Copy { from: 1, into: 2 }, Op::Return];
    assert_eq!(run(ops.clone(), vec![take_site(2, 1, 2)]), Err(BangError::Invalid("E_BANG_MIR_MISMATCH")));
    let mut s = copy_site(2, 1, 2);
    s.spelling = Spelling::LegacyMutablePrefix;
    assert_eq!(run(ops, vec![s]), Err(BangError::Invalid("E_BANG_SPELLING_KIND")));
}

#[test]
fn all_copy_and_take_spellings_have_identical_semantic_results() {
    for spelling in [Spelling::Preferred, Spelling::Compact, Spelling::LegacyRt] {
        let mut copy = copy_site(2, 1, 2);
        copy.spelling = spelling;
        assert_eq!(
            run(vec![init(1, true, false), Op::Copy { from: 1, into: 2 }, Op::Return], vec![copy]).unwrap().cleanup_by_exit[&0],
            vec![2, 1]
        );
        let mut take = take_site(2, 1, 2);
        take.spelling = spelling;
        assert_eq!(
            run(vec![init(1, false, false), Op::Move { from: 1, into: 2 }, Op::Return], vec![take]).unwrap().cleanup_by_exit[&0],
            vec![2]
        );
    }
}

#[test]
fn manifest_source_census_must_not_include_non_bang_ownership_events() {
    let ops = vec![init(1, true, true), Op::Copy { from: 1, into: 2 }, Op::Return];
    let mut m = manifest(vec![copy_site(2, 1, 2)]);
    m.source_bang_instruction_ids.push(1);
    assert_eq!(
        verify_bang_mir(&function(ops), &m),
        Err(BangError::Invalid("E_BANG_INCOMPLETE_SOURCE_CENSUS"))
    );
}

#[test]
fn malformed_instruction_inventory_is_rejected_even_when_site_matches() {
    let ops = vec![init(1, true, true), Op::Copy { from: 1, into: 2 }, Op::Return];
    let mut f = function(ops);
    f.expected_instruction_ids.remove(0);
    assert_eq!(
        verify_bang_mir(&f, &manifest(vec![copy_site(2, 1, 2)])),
        Err(BangError::Mir(MirError::Invalid("E_MIR_INCOMPLETE_INVENTORY")))
    );
}

#[test]
fn non_bang_program_still_verifies_full_mir_inventory() {
    assert_eq!(
        run(vec![init(1, false, false), Op::Read { owner: 1 }, Op::Return], vec![]).unwrap().cleanup_by_exit[&0],
        vec![1]
    );
}
