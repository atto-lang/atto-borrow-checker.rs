use atto_borrow_checker::mir_v1::{
    Effect, Instruction, MirBlock, MirError, MirFunction, Producer, CONTRACT_VERSION,
};
use atto_borrow_checker::ownership_bang_v1::{
    verify_bang_mir, BangError, BangManifest, BangSite, SourceAuthority, Spelling, Verb, CONTRACT_VERSION as BANG_VERSION,
};
use atto_borrow_checker::{BorrowKind, Op, Traits};

fn traits(copy: bool, send: bool) -> Traits {
    Traits { is_copy: copy, is_send: send }
}

fn mir(ops: Vec<Op>) -> MirFunction {
    let instructions: Vec<_> = ops.into_iter().enumerate().map(|(index, operation)| {
        let id = index as u64 + 1;
        let effect = match &operation {
            Op::Return => Effect::Control,
            Op::Suspend => Effect::Suspension,
            Op::PublishFrozen { .. } => Effect::ActorBoundary,
            _ => Effect::Ownership,
        };
        Instruction {
            instruction_id: id,
            source_node_id: id + 100,
            effect,
            operation,
        }
    }).collect();
    MirFunction {
        version: CONTRACT_VERSION.to_string(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 2,
        },
        entry: 0,
        expected_instruction_ids: instructions.iter().map(|item| item.instruction_id).collect(),
        blocks: vec![MirBlock {
            id: 0,
            instructions,
            successors: vec![],
        }],
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
    }
}

fn check(program: &MirFunction, sites: &[BangSite]) -> Result<atto_borrow_checker::Proof, BangError> {
    verify_bang_mir(program, &BangManifest {
        version: BANG_VERSION.to_string(),
        sites: sites.to_vec(),
        source_bang_instruction_ids: sites.iter().map(|s| s.instruction_id).collect(),
    })
}

fn unsafe_code(program: &MirFunction, sites: &[BangSite]) -> &'static str {
    match check(program, sites).unwrap_err() {
        BangError::Mir(MirError::Unsafe(diagnostic)) => diagnostic.code,
        other => panic!("expected unsafe semantic result, got {other:?}"),
    }
}

fn init(copy: bool, send: bool) -> Op {
    Op::Init { owner: 1, traits: traits(copy, send) }
}

#[test]
fn owned_copy_preserves_source_and_mints_detached_owner() {
    let p = mir(vec![
        init(true, false),
        Op::Copy { from: 1, into: 2 },
        Op::Read { owner: 1 },
        Op::Read { owner: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    assert_eq!(check(&p, &[s]).unwrap().cleanup_by_exit[&0], vec![2, 1]);
}

#[test]
fn noncopy_cannot_be_forced_through_copy_bang() {
    let p = mir(vec![init(false, true), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    assert_eq!(unsafe_code(&p, &[s]), "E_COPY_PROOF_REQUIRED");
}

#[test]
fn take_consumes_source_and_denies_use_after_move() {
    let p = mir(vec![
        init(false, false),
        Op::Move { from: 1, into: 2 },
        Op::Read { owner: 1 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    assert_eq!(unsafe_code(&p, &[s]), "E_USE_AFTER_MOVE_OR_DROP");
}

#[test]
fn take_preserves_original_acquisition_cleanup_order() {
    let p = mir(vec![init(false, false), Op::Move { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    assert_eq!(check(&p, &[s]).unwrap().cleanup_by_exit[&0], vec![2]);
}

#[test]
fn borrow_shared_allows_multiple_readers_and_loan_bound_reads() {
    let p = mir(vec![
        init(false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Borrow { owner: 1, loan: 11, kind: BorrowKind::Shared },
        Op::ReadThrough { owner: 1, loan: 10 },
        Op::ReadThrough { owner: 1, loan: 11 },
        Op::EndBorrow { loan: 11 },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mut a = site(2, Verb::Borrow);
    a.loan = Some(10);
    let mut b = site(3, Verb::Borrow);
    b.loan = Some(11);
    check(&p, &[a, b]).unwrap();
}

#[test]
fn mutable_borrow_requires_writable_place_and_authorizes_loan_write() {
    let p = mir(vec![
        init(false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Mutable },
        Op::ReadThrough { owner: 1, loan: 10 },
        Op::WriteThrough { owner: 1, loan: 10 },
        Op::EndBorrow { loan: 10 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::BorrowMut);
    s.loan = Some(10);
    assert_eq!(check(&p, &[s.clone()]), Err(BangError::Invalid("E_BANG_MUTABLE_PLACE_REQUIRED")));
    s.place_is_writable = true;
    check(&p, &[s]).unwrap();
}

#[test]
fn mutable_borrow_conflicts_with_any_outstanding_shared_loan() {
    let p = mir(vec![
        init(false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Borrow { owner: 1, loan: 11, kind: BorrowKind::Mutable },
        Op::Return,
    ]);
    let mut a = site(2, Verb::Borrow);
    a.loan = Some(10);
    let mut b = site(3, Verb::BorrowMut);
    b.loan = Some(11);
    b.place_is_writable = true;
    assert_eq!(unsafe_code(&p, &[a, b]), "E_BORROW_CONFLICT");
}

#[test]
fn no_loan_use_after_end_or_against_wrong_owner() {
    let p = mir(vec![
        init(true, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::EndBorrow { loan: 10 },
        Op::ReadThrough { owner: 1, loan: 10 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Borrow);
    s.loan = Some(10);
    assert_eq!(unsafe_code(&p, &[s]), "E_LOAN_NOT_ACTIVE_OR_WRONG_OWNER");
}

#[test]
fn borrowed_copy_creates_owned_snapshot_that_may_be_shared_later() {
    let p = mir(vec![
        init(true, true),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::CopyThrough { owner: 1, loan: 10, into: 2 },
        Op::EndBorrow { loan: 10 },
        Op::PublishFrozen { owner: 2, region: 3, sync_proven: true },
        Op::Return,
    ]);
    let mut borrow = site(2, Verb::Borrow);
    borrow.loan = Some(10);
    let mut snapshot = site(3, Verb::Copy);
    snapshot.loan = Some(10);
    snapshot.into = Some(2);
    snapshot.source_authority = SourceAuthority::BorrowedLoan;
    let mut share = site(5, Verb::Share);
    share.from = 2;
    share.region = Some(3);
    check(&p, &[borrow, snapshot, share]).unwrap();
}

#[test]
fn borrowed_copy_requires_an_actually_live_matching_loan() {
    let p = mir(vec![
        init(true, true),
        Op::CopyThrough { owner: 1, loan: 999, into: 2 },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Copy);
    s.source_authority = SourceAuthority::BorrowedLoan;
    s.into = Some(2);
    s.loan = Some(999);
    assert_eq!(unsafe_code(&p, &[s]), "E_LOAN_NOT_ACTIVE_OR_WRONG_OWNER");
}

#[test]
fn frozen_share_consumes_owner_without_copying_it() {
    let p = mir(vec![
        init(false, true),
        Op::PublishFrozen { owner: 1, region: 3, sync_proven: true },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Share);
    s.region = Some(3);
    assert!(check(&p, &[s]).unwrap().cleanup_by_exit[&0].is_empty());
}

#[test]
fn share_requires_independent_send_and_sync_witnesses() {
    let mut s = site(2, Verb::Share);
    s.region = Some(3);
    let no_send = mir(vec![
        init(false, false),
        Op::PublishFrozen { owner: 1, region: 3, sync_proven: true },
        Op::Return,
    ]);
    assert_eq!(unsafe_code(&no_send, &[s.clone()]), "E_SHARED_FROZEN_PROOF_REQUIRED");
    let no_sync = mir(vec![
        init(false, true),
        Op::PublishFrozen { owner: 1, region: 3, sync_proven: false },
        Op::Return,
    ]);
    assert_eq!(check(&no_sync, &[s]), Err(BangError::Invalid("E_BANG_MIR_MISMATCH")));
}

#[test]
fn cannot_launder_borrowed_or_actor_owned_state_into_shared_authority() {
    let p = mir(vec![
        init(true, true),
        Op::PublishFrozen { owner: 1, region: 3, sync_proven: true },
        Op::Return,
    ]);
    let mut s = site(2, Verb::Share);
    s.region = Some(3);
    s.source_authority = SourceAuthority::BorrowedLoan;
    assert_eq!(check(&p, &[s.clone()]), Err(BangError::Invalid("E_BANG_SHARE_BORROWED")));
    s.source_authority = SourceAuthority::ActorState;
    assert_eq!(check(&p, &[s.clone()]), Err(BangError::Invalid("E_BANG_AUTHORITY")));
    s.source_authority = SourceAuthority::Unknown;
    assert_eq!(check(&p, &[s]), Err(BangError::Invalid("E_BANG_AUTHORITY")));
}

#[test]
fn cannot_take_or_unproven_reborrow_through_borrowed_authority() {
    let p = mir(vec![init(true, false), Op::Move { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    s.source_authority = SourceAuthority::BorrowedLoan;
    assert_eq!(check(&p, &[s]), Err(BangError::Invalid("E_BANG_TAKE_BORROWED")));
}

#[test]
fn borrow_lifetime_cannot_cross_unproved_suspend_or_return() {
    let mut s = site(2, Verb::Borrow);
    s.loan = Some(10);
    let suspend = mir(vec![
        init(false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Suspend,
        Op::Return,
    ]);
    assert_eq!(unsafe_code(&suspend, &[s.clone()]), "E_SUSPEND_WITH_LIVE_LOAN");
    let escape = mir(vec![
        init(false, false),
        Op::Borrow { owner: 1, loan: 10, kind: BorrowKind::Shared },
        Op::Return,
    ]);
    assert_eq!(unsafe_code(&escape, &[s]), "E_LOAN_ESCAPE");
}

#[test]
fn all_spelling_aliases_have_the_exact_same_mir_semantics() {
    let p = mir(vec![init(true, true), Op::Move { from: 1, into: 2 }, Op::Return]);
    for spelling in [Spelling::Preferred, Spelling::Compact, Spelling::LegacyRt] {
        let mut s = site(2, Verb::Take);
        s.into = Some(2);
        s.spelling = spelling;
        check(&p, &[s]).unwrap();
    }
    let p_mut = mir(vec![
        init(true, true),
        Op::Borrow { owner: 1, loan: 4, kind: BorrowKind::Mutable },
        Op::EndBorrow { loan: 4 },
        Op::Return,
    ]);
    for spelling in [
        Spelling::Preferred,
        Spelling::Compact,
        Spelling::LegacyRt,
        Spelling::LegacyMutablePrefix,
    ] {
        let mut s = site(2, Verb::BorrowMut);
        s.loan = Some(4);
        s.place_is_writable = true;
        s.spelling = spelling;
        check(&p_mut, &[s]).unwrap();
    }
}

#[test]
fn unrelated_legacy_mutable_prefix_cannot_relabel_copy() {
    let p = mir(vec![init(true, true), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    s.spelling = Spelling::LegacyMutablePrefix;
    assert_eq!(check(&p, &[s]), Err(BangError::Invalid("E_BANG_SPELLING_KIND")));
}

#[test]
fn source_census_is_independent_and_must_match_sites_and_mir() {
    let p = mir(vec![init(true, false), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    assert_eq!(
        verify_bang_mir(&p, &BangManifest { version: BANG_VERSION.to_string(), sites: vec![s.clone()], source_bang_instruction_ids: vec![2, 99] }),
        Err(BangError::Invalid("E_BANG_INCOMPLETE_SOURCE_CENSUS"))
    );
    assert_eq!(
        verify_bang_mir(&p, &BangManifest { version: BANG_VERSION.to_string(), sites: vec![s.clone()], source_bang_instruction_ids: vec![2, 2] }),
        Err(BangError::Invalid("E_BANG_SOURCE_CENSUS"))
    );
    assert_eq!(
        verify_bang_mir(&p, &BangManifest { version: BANG_VERSION.to_string(), sites: vec![s.clone(), s.clone()], source_bang_instruction_ids: vec![2] }),
        Err(BangError::Invalid("E_BANG_DUPLICATE_SITE"))
    );
    s.instruction_id = 99;
    s.source_node_id = 199;
    assert_eq!(
        verify_bang_mir(&p, &BangManifest { version: BANG_VERSION.to_string(), sites: vec![s], source_bang_instruction_ids: vec![99] }),
        Err(BangError::Invalid("E_BANG_MISSING_MIR_SITE"))
    );
}

#[test]
fn type_or_source_id_mir_mismatch_is_never_silently_accepted() {
    let p = mir(vec![init(true, false), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Take);
    s.into = Some(2);
    assert_eq!(check(&p, &[s.clone()]), Err(BangError::Invalid("E_BANG_MIR_MISMATCH")));
    s.verb = Verb::Copy;
    s.source_node_id += 1;
    assert_eq!(check(&p, &[s]), Err(BangError::Invalid("E_BANG_MIR_MISMATCH")));
}

#[test]
fn unknown_effect_cannot_be_laundered_by_a_valid_bang_site() {
    let mut p = mir(vec![init(true, false), Op::Copy { from: 1, into: 2 }, Op::Return]);
    p.blocks[0].instructions[1].effect = Effect::Unsupported;
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    assert_eq!(check(&p, &[s]), Err(BangError::Mir(MirError::Invalid("E_MIR_UNSUPPORTED_EFFECT"))));
}

#[test]
fn invalid_operand_shape_rejected_before_semantic_verification() {
    let p = mir(vec![init(true, false), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Copy);
    assert_eq!(check(&p, &[s.clone()]), Err(BangError::Invalid("E_BANG_OPERANDS")));
    s.into = Some(1);
    assert_eq!(check(&p, &[s]), Err(BangError::Invalid("E_BANG_DESTINATION")));
}

#[test]
fn rejects_bang_manifest_version_skew() {
    let p = mir(vec![init(true, false), Op::Copy { from: 1, into: 2 }, Op::Return]);
    let mut s = site(2, Verb::Copy);
    s.into = Some(2);
    let manifest = BangManifest {
        version: "atto-ownership-bang-v0".to_string(),
        sites: vec![s],
        source_bang_instruction_ids: vec![2],
    };
    assert_eq!(verify_bang_mir(&p, &manifest), Err(BangError::Invalid("E_BANG_VERSION")));
}
