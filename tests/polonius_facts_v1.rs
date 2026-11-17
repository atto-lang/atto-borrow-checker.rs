use atto_borrow_checker::polonius_facts_v1::{analyze, Code, Error, Facts, Point, Report};

fn point(id: u32, next: &[u32], live: &[u32]) -> Point {
    Point {
        id,
        successors: next.to_vec(),
        live_origins: live.to_vec(),
        subset: vec![],
        issue: vec![],
        kill: vec![],
        invalidate: vec![],
    }
}

fn run(points: Vec<Point>) -> Result<Report, Error> {
    analyze(&Facts { entry: 1, points })
}

#[test]
fn conditional_return_versus_mutate_branch_is_precise() {
    let mut entry = point(1, &[2, 3], &[10]);
    entry.issue.push((10, 7));
    let returned_ref = point(2, &[], &[10]);
    let mut mutation = point(3, &[4], &[]);
    mutation.invalidate.push(7);
    let exit = point(4, &[], &[]);
    let report = run(vec![entry, returned_ref, mutation, exit]).unwrap();
    assert!(report.live_loans_on_entry[&2].contains(&7));
    assert!(!report.live_loans_on_entry[&3].contains(&7));
    assert!(!report.live_loans_on_entry[&4].contains(&7));
}

#[test]
fn live_borrow_in_branch_blocks_mutation() {
    let mut entry = point(1, &[2, 3], &[10]);
    entry.issue.push((10, 7));
    let mut invalidation = point(2, &[], &[10]);
    invalidation.invalidate.push(7);
    let error = run(vec![entry, invalidation, point(3, &[], &[])]).unwrap_err();
    assert_eq!((error.code, error.point, error.loan), (Code::InvalidatedLoan, 2, Some(7)));
}

#[test]
fn joining_branches_unions_may_live_loans() {
    let mut entry = point(1, &[2, 3], &[10]);
    entry.issue.push((10, 7));
    let left = point(2, &[4], &[10]);
    let right = point(3, &[4], &[]);
    let mut join = point(4, &[], &[10]);
    join.invalidate.push(7);
    assert_eq!(run(vec![entry, left, right, join]).unwrap_err().code, Code::InvalidatedLoan);
}

#[test]
fn transitive_subsets_flow_through_dead_intermediate_origins() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    let mut later = point(2, &[], &[30]);
    later.subset.extend([(10, 20), (20, 30)]);
    later.invalidate.push(7);
    assert_eq!(run(vec![entry, later]).unwrap_err().code, Code::InvalidatedLoan);
}

#[test]
fn subset_edges_have_direction() {
    let mut entry = point(1, &[2], &[20]);
    entry.issue.push((20, 7));
    let mut later = point(2, &[], &[10]);
    later.subset.push((10, 20));
    later.invalidate.push(7);
    run(vec![entry, later]).unwrap();
}

#[test]
fn kill_affects_successor_not_current_invalidation() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    let mut kill = point(2, &[3], &[10]);
    kill.kill.push(7);
    let mut later = point(3, &[], &[10]);
    later.invalidate.push(7);
    run(vec![entry.clone(), kill.clone(), later]).unwrap();
    kill.invalidate.push(7);
    assert_eq!(
        run(vec![entry, kill, point(3, &[], &[10])]).unwrap_err().code,
        Code::InvalidatedLoan
    );
}

#[test]
fn issue_at_point_is_visible_to_successors_only() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    entry.invalidate.push(7);
    let mut next = point(2, &[], &[10]);
    next.invalidate.push(7);
    let e = run(vec![entry, next]).unwrap_err();
    assert_eq!((e.point, e.loan), (2, Some(7)));
}

#[test]
fn cyclic_fixed_point_carries_loans_and_respects_kills() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    let mut loop_point = point(2, &[2, 3], &[10]);
    loop_point.invalidate.push(7);
    assert_eq!(
        run(vec![entry, loop_point, point(3, &[], &[])]).unwrap_err().code,
        Code::InvalidatedLoan
    );

    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    let mut loop_point = point(2, &[2, 3], &[10]);
    loop_point.kill.push(7);
    let mut exit = point(3, &[], &[10]);
    exit.invalidate.push(7);
    run(vec![entry, loop_point, exit]).unwrap();
}

#[test]
fn unknown_or_duplicate_loan_ids_are_rejected() {
    let mut p = point(1, &[], &[10]);
    p.invalidate.push(99);
    assert_eq!(run(vec![p]).unwrap_err().code, Code::UnknownLoan);
    let mut p = point(1, &[2], &[10]);
    p.issue.push((10, 7));
    let mut q = point(2, &[], &[10]);
    q.issue.push((10, 7));
    assert_eq!(run(vec![p, q]).unwrap_err().code, Code::DuplicateFact);
}

#[test]
fn issue_requires_live_origin_at_issuance() {
    let mut p = point(1, &[], &[]);
    p.issue.push((10, 7));
    assert_eq!(run(vec![p]).unwrap_err().code, Code::InvalidFact);
}

#[test]
fn cfg_must_be_complete_and_all_points_reachable() {
    let p = point(1, &[], &[]);
    assert_eq!(run(vec![p.clone(), point(2, &[], &[])]).unwrap_err().code, Code::UnreachablePoint);
    assert_eq!(run(vec![p.clone(), p]).unwrap_err().code, Code::InvalidGraph);
    assert_eq!(run(vec![point(1, &[999], &[])]).unwrap_err().code, Code::InvalidGraph);
    assert_eq!(
        run(vec![point(1, &[2, 2], &[]), point(2, &[], &[])]).unwrap_err().code,
        Code::InvalidGraph
    );
}

#[test]
fn duplicate_live_regions_and_subsets_are_rejected() {
    let p = point(1, &[], &[10, 10]);
    assert_eq!(run(vec![p]).unwrap_err().code, Code::DuplicateFact);
    let mut p = point(1, &[], &[10]);
    p.subset.extend([(10, 11), (10, 11)]);
    assert_eq!(run(vec![p]).unwrap_err().code, Code::DuplicateFact);
}

#[test]
fn malformed_identifiers_and_kill_of_new_issue_are_rejected() {
    assert_eq!(run(vec![point(0, &[], &[])]).unwrap_err().code, Code::InvalidGraph);
    let mut p = point(1, &[], &[10]);
    p.issue.push((10, 7));
    p.kill.push(7);
    assert_eq!(run(vec![p]).unwrap_err().code, Code::InvalidFact);
}

#[test]
fn excessive_input_is_rejected_before_solver_work() {
    let mut p = point(1, &[], &[10]);
    p.invalidate = vec![10; 100_001];
    assert_eq!(run(vec![p]).unwrap_err().code, Code::Budget);
}

#[test]
fn proof_and_work_are_deterministic_across_block_listing_order() {
    let mut entry = point(1, &[2, 3], &[10]);
    entry.issue.push((10, 7));
    let left = point(2, &[], &[10]);
    let right = point(3, &[], &[]);
    let a = run(vec![entry.clone(), left.clone(), right.clone()]).unwrap();
    let b = run(vec![right, entry, left]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn newly_issued_loans_follow_same_point_subset_edges() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    entry.subset.push((10, 20));
    let mut successor = point(2, &[], &[20]);
    successor.invalidate.push(7);
    let err = run(vec![entry, successor]).unwrap_err();
    assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 2, Some(7)));
}
