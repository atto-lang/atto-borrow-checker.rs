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
    assert_eq!(
        (error.code, error.point, error.loan),
        (Code::InvalidatedLoan, 2, Some(7))
    );
}

#[test]
fn joining_branches_unions_may_live_loans() {
    let mut entry = point(1, &[2, 3], &[10]);
    entry.issue.push((10, 7));
    let left = point(2, &[4], &[10]);
    let right = point(3, &[4], &[]);
    let mut join = point(4, &[], &[10]);
    join.invalidate.push(7);
    assert_eq!(
        run(vec![entry, left, right, join]).unwrap_err().code,
        Code::InvalidatedLoan
    );
}

#[test]
fn transitive_subsets_flow_through_dead_intermediate_origins() {
    let mut entry = point(1, &[2], &[10]);
    entry.issue.push((10, 7));
    let mut later = point(2, &[], &[30]);
    later.subset.extend([(10, 20), (20, 30)]);
    later.invalidate.push(7);
    assert_eq!(
        run(vec![entry, later]).unwrap_err().code,
        Code::InvalidatedLoan
    );
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
        run(vec![entry, kill, point(3, &[], &[10])])
            .unwrap_err()
            .code,
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
        run(vec![entry, loop_point, point(3, &[], &[])])
            .unwrap_err()
            .code,
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
    assert_eq!(
        run(vec![p.clone(), point(2, &[], &[])]).unwrap_err().code,
        Code::UnreachablePoint
    );
    assert_eq!(
        run(vec![p.clone(), p]).unwrap_err().code,
        Code::InvalidGraph
    );
    assert_eq!(
        run(vec![point(1, &[999], &[])]).unwrap_err().code,
        Code::InvalidGraph
    );
    assert_eq!(
        run(vec![point(1, &[2, 2], &[]), point(2, &[], &[])])
            .unwrap_err()
            .code,
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
    assert_eq!(
        run(vec![point(0, &[], &[])]).unwrap_err().code,
        Code::InvalidGraph
    );
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
    assert_eq!(
        (err.code, err.point, err.loan),
        (Code::InvalidatedLoan, 2, Some(7))
    );
}


// The following tests derive region liveness rather than manually supplying
// live_origins, reproducing Polonius Alpha's get_mut / None / insert scenario.
mod inferred_liveness {
    use atto_borrow_checker::polonius_facts_v1::{
        analyze_with_inferred_liveness, Code, Error, Facts, InferredReport, OriginUse, Point,
    };

    fn point(id: u32, successors: &[u32]) -> Point {
        Point {
            id,
            successors: successors.to_vec(),
            live_origins: vec![],
            subset: vec![],
            issue: vec![],
            kill: vec![],
            invalidate: vec![],
        }
    }

    fn check(points: Vec<Point>, uses: &[(u32, u32)]) -> Result<InferredReport, Error> {
        analyze_with_inferred_liveness(
            &Facts { entry: 1, points },
            &uses
                .iter()
                .map(|&(point, origin)| OriginUse { point, origin })
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn hashmap_get_mut_some_return_none_insert_retry_passes() {
        // 1: initial get_mut issues L1 into origin 10; branch to Some or None.
        // 2: Some(value) => return value (only branch that uses region 10).
        // 3: None => map.insert (invalidates L1 if L1 were live).
        // 4: map.get_mut again issues a distinct L2 into origin 20.
        // 5: return the new mutable value through L2.
        let mut lookup = point(1, &[2, 3]);
        lookup.issue.push((10, 7));
        let some_return = point(2, &[]);
        let mut insert = point(3, &[4]);
        insert.invalidate.push(7);
        let mut retry = point(4, &[5]);
        retry.issue.push((20, 8));
        let second_return = point(5, &[]);

        let result = check(
            vec![lookup, some_return, insert, retry, second_return],
            &[(2, 10), (5, 20)],
        )
        .unwrap();

        assert!(result.live_origins_on_entry[&2].contains(&10));
        assert!(!result.live_origins_on_entry[&3].contains(&10));
        assert!(!result.live_origins_on_entry[&4].contains(&10));
        assert!(result.live_origins_on_entry[&5].contains(&20));
        assert!(result.loans.live_loans_on_entry[&2].contains(&7));
        assert!(!result.loans.live_loans_on_entry[&3].contains(&7));
        assert!(result.loans.live_loans_on_entry[&5].contains(&8));
    }

    #[test]
    fn insertion_rejected_when_original_loan_is_used_on_none_path() {
        let mut lookup = point(1, &[2, 3]);
        lookup.issue.push((10, 7));
        let some_return = point(2, &[]);
        let mut insert = point(3, &[]);
        insert.invalidate.push(7);
        let err = check(vec![lookup, some_return, insert], &[(2, 10), (3, 10)]).unwrap_err();
        assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 3, Some(7)));
    }

    #[test]
    fn mutation_on_some_path_is_rejected() {
        let mut lookup = point(1, &[2, 3]);
        lookup.issue.push((10, 7));
        let mut some = point(2, &[]);
        some.invalidate.push(7);
        let none = point(3, &[]);
        let err = check(vec![lookup, some, none], &[(2, 10)]).unwrap_err();
        assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 2, Some(7)));
    }

    #[test]
    fn join_use_keeps_loan_live_on_both_predecessor_branches() {
        let mut lookup = point(1, &[2, 3]);
        lookup.issue.push((10, 7));
        let left = point(2, &[4]);
        let mut right = point(3, &[4]);
        right.invalidate.push(7);
        let join = point(4, &[]);
        let err = check(vec![lookup, left, right, join], &[(4, 10)]).unwrap_err();
        assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 3, Some(7)));
    }

    #[test]
    fn outlives_subset_infers_source_loan_from_return_target_use() {
        let mut lookup = point(1, &[2]);
        lookup.issue.push((10, 7));
        lookup.subset.extend([(10, 20), (20, 30)]);
        let mut returned = point(2, &[]);
        returned.invalidate.push(7);
        let err = check(vec![lookup, returned], &[(2, 30)]).unwrap_err();
        assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 2, Some(7)));
    }

    #[test]
    fn subset_direction_does_not_invent_reverse_loan() {
        let mut lookup = point(1, &[2]);
        lookup.issue.push((20, 7));
        lookup.subset.push((10, 20));
        let mut returned = point(2, &[]);
        returned.invalidate.push(7);
        let result = check(vec![lookup, returned], &[(2, 10)]).unwrap();
        assert!(!result.loans.live_loans_on_entry[&2].contains(&7));
    }

    #[test]
    fn loop_backedge_retains_loan_when_used_on_exit() {
        let mut lookup = point(1, &[2]);
        lookup.issue.push((10, 7));
        let mut loop_body = point(2, &[2, 3]);
        loop_body.invalidate.push(7);
        let exit = point(3, &[]);
        let err = check(vec![lookup, loop_body, exit], &[(3, 10)]).unwrap_err();
        assert_eq!((err.code, err.point, err.loan), (Code::InvalidatedLoan, 2, Some(7)));
    }

    #[test]
    fn dead_loan_can_be_killed_before_mutation() {
        let mut lookup = point(1, &[2]);
        lookup.issue.push((10, 7));
        let mut end_loan = point(2, &[3]);
        end_loan.kill.push(7);
        let mut mutation = point(3, &[]);
        mutation.invalidate.push(7);
        check(vec![lookup, end_loan, mutation], &[]).unwrap();
    }

    #[test]
    fn rejects_untrusted_manual_live_origins_and_unknown_use_point() {
        let mut lookup = point(1, &[]);
        lookup.issue.push((10, 7));
        lookup.live_origins.push(10);
        let err = check(vec![lookup], &[]).unwrap_err();
        assert_eq!(err.code, Code::InvalidFact);

        let mut lookup = point(1, &[]);
        lookup.issue.push((10, 7));
        let err = check(vec![lookup], &[(99, 10)]).unwrap_err();
        assert_eq!(err.code, Code::InvalidFact);
    }

    #[test]
    fn rejects_undeclared_or_duplicate_or_zero_origin_uses() {
        let mut lookup = point(1, &[]);
        lookup.issue.push((10, 7));
        let err = check(vec![lookup.clone()], &[(1, 99)]).unwrap_err();
        assert_eq!(err.code, Code::InvalidFact);
        let err = check(vec![lookup.clone()], &[(1, 10), (1, 10)]).unwrap_err();
        assert_eq!(err.code, Code::InvalidFact);
        let err = check(vec![lookup], &[(1, 0)]).unwrap_err();
        assert_eq!(err.code, Code::InvalidFact);
    }

    #[test]
    fn inferred_result_is_independent_of_point_listing_order() {
        let mut entry = point(1, &[2, 3]);
        entry.issue.push((10, 7));
        let returned = point(2, &[]);
        let mut inserted = point(3, &[]);
        inserted.invalidate.push(7);
        let a = check(
            vec![entry.clone(), returned.clone(), inserted.clone()],
            &[(2, 10)],
        )
        .unwrap();
        let b = check(vec![inserted, entry, returned], &[(2, 10)]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn huge_untrusted_use_census_rejected_before_worklist() {
        let mut entry = point(1, &[]);
        entry.issue.push((10, 7));
        let uses = vec![(1, 10); 100_001];
        let err = check(vec![entry], &uses).unwrap_err();
        assert_eq!(err.code, Code::Budget);
    }
}
