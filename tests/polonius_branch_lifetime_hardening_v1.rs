//! Adversarial CFG/lifetime regression cases for the experimental facts model.
//! These do not certify complete typed-MIR liveness or Atto guest semantics.
use atto_borrow_checker::polonius_facts_v1::{analyze, Code, Facts, Point};

fn p(id: u32, successors: &[u32], live_origins: &[u32]) -> Point {
    Point {
        id,
        successors: successors.to_vec(),
        live_origins: live_origins.to_vec(),
        subset: vec![],
        issue: vec![],
        kill: vec![],
        invalidate: vec![],
    }
}

fn verify(
    points: Vec<Point>,
) -> Result<
    atto_borrow_checker::polonius_facts_v1::Report,
    atto_borrow_checker::polonius_facts_v1::Error,
> {
    analyze(&Facts { entry: 1, points })
}

#[test]
fn map_get_or_insert_borrow_only_on_some_path() {
    // 1: map.get_mut; 2: Some(value) returns the old loan.
    // 3: None inserts, invalidating an old loan *if it were live*.
    // 4: None obtains a fresh mutable loan and returns that instead.
    let mut lookup = p(1, &[2, 3], &[10]);
    lookup.issue.push((10, 7));
    let returned_some = p(2, &[], &[10]);
    let mut insert_none = p(3, &[4], &[]);
    insert_none.invalidate.push(7);
    let mut reborrow_none = p(4, &[5], &[20]);
    reborrow_none.issue.push((20, 8));
    let returned_none = p(5, &[], &[20]);
    let report = verify(vec![
        lookup.clone(),
        returned_some.clone(),
        insert_none.clone(),
        reborrow_none,
        returned_none,
    ])
    .expect("the Some return must not poison None's later mutation");
    assert!(report.live_loans_on_entry[&2].contains(&7));
    assert!(!report.live_loans_on_entry[&3].contains(&7));
    assert!(report.live_loans_on_entry[&5].contains(&8));

    // If the old loan remains live on the mutation path, the same write
    // must be rejected, not silently downgraded to a non-conflict.
    insert_none.live_origins = vec![10];
    let err = verify(vec![
        lookup,
        returned_some,
        insert_none,
        p(4, &[5], &[20]),
        p(5, &[], &[20]),
    ])
    .unwrap_err();
    assert_eq!(
        (err.code, err.point, err.loan),
        (Code::InvalidatedLoan, 3, Some(7))
    );
}

#[test]
fn a_may_live_loan_from_either_branch_blocks_join_mutation() {
    let entry = p(1, &[2, 3], &[]);
    let mut left = p(2, &[4], &[10]);
    left.issue.push((10, 7));
    let mut right = p(3, &[4], &[20]);
    right.issue.push((20, 8));
    let mut joined = p(4, &[], &[10, 20]);
    joined.invalidate.push(8);
    let err = verify(vec![entry, left, right, joined]).unwrap_err();
    assert_eq!(
        (err.code, err.point, err.loan),
        (Code::InvalidatedLoan, 4, Some(8))
    );
}

#[test]
fn transitive_reborrow_survives_dead_intermediate_origins_across_points() {
    let mut issue = p(1, &[2], &[10]);
    issue.issue.push((10, 7));
    let mut first = p(2, &[3], &[20]);
    first.subset.push((10, 20));
    let mut second = p(3, &[4], &[30]);
    second.subset.push((20, 30));
    let mut final_access = p(4, &[], &[30]);
    final_access.invalidate.push(7);
    let err = verify(vec![issue, first, second, final_access]).unwrap_err();
    assert_eq!(
        (err.code, err.point, err.loan),
        (Code::InvalidatedLoan, 4, Some(7))
    );
}

#[test]
fn explicit_kill_releases_all_subset_aliases_for_successors() {
    let mut issue = p(1, &[2], &[10]);
    issue.issue.push((10, 7));
    let mut end_loan = p(2, &[3], &[10, 20]);
    end_loan.subset.push((10, 20));
    end_loan.kill.push(7);
    let mut successor = p(3, &[], &[20]);
    successor.invalidate.push(7);
    let report = verify(vec![issue, end_loan, successor]).unwrap();
    assert!(!report.live_loans_on_entry[&3].contains(&7));
}

#[test]
fn loop_backedge_must_not_launder_live_loan() {
    let mut issue = p(1, &[2], &[10]);
    issue.issue.push((10, 7));
    // The loop body's invalidating write is prohibited on the first
    // iteration, regardless of the backedge fixed point.
    let mut body = p(2, &[2, 3], &[10]);
    body.invalidate.push(7);
    let err = verify(vec![issue, body, p(3, &[], &[])]).unwrap_err();
    assert_eq!(
        (err.code, err.point, err.loan),
        (Code::InvalidatedLoan, 2, Some(7))
    );
}

#[test]
fn insertion_order_cannot_change_branch_liveness_verdict() {
    let mut issue = p(1, &[2, 3], &[10]);
    issue.issue.push((10, 7));
    let returned = p(2, &[], &[10]);
    let mut insert = p(3, &[], &[]);
    insert.invalidate.push(7);
    let a = verify(vec![issue.clone(), returned.clone(), insert.clone()]).unwrap();
    let b = verify(vec![insert, returned, issue]).unwrap();
    assert_eq!(a, b);
}
