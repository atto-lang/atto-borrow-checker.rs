use atto_borrow_checker::polonius_facts_v1::{Code, Facts, OriginUse, Point};
use atto_borrow_checker::polonius_ssa_v1::{analyze_ssa, loan_ids, Definition, Input, PhiInput};

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
fn definition(point: u32, origin: u32) -> Definition {
    Definition { point, origin }
}
fn used(point: u32, origin: u32) -> OriginUse {
    OriginUse { point, origin }
}
fn sample() -> Input {
    let mut entry = point(1, &[2, 3]);
    entry.issue.push((10, 7));
    let mut none = point(3, &[4]);
    none.invalidate.push(7);
    let mut reborrow = point(4, &[5]);
    reborrow.issue.push((20, 8));
    Input {
        template: Facts {
            entry: 1,
            points: vec![entry, point(2, &[]), none, reborrow, point(5, &[])],
        },
        uses: vec![used(2, 10), used(5, 20)],
        definitions: vec![definition(1, 10), definition(4, 20)],
        phi_inputs: vec![],
    }
}
#[test]
fn rust_get_mut_some_return_and_none_insert_then_reborrow() {
    let report = analyze_ssa(&sample()).unwrap();
    assert!(loan_ids(&report, 2).unwrap().contains(&7));
    assert!(!loan_ids(&report, 3).unwrap().contains(&7));
    assert!(loan_ids(&report, 5).unwrap().contains(&8));
    assert!(!report.live_before_definition[&1].contains(&10));
    assert!(!report.live_before_definition[&4].contains(&20));
}
#[test]
fn a_live_old_loan_on_none_path_forbids_insert() {
    let mut input = sample();
    input.uses.push(used(3, 10));
    let e = analyze_ssa(&input).unwrap_err();
    assert_eq!(
        (e.code, e.point, e.loan),
        (Code::InvalidatedLoan, 3, Some(7))
    );
}
#[test]
fn fresh_ssa_definition_does_not_keep_old_loan_alive() {
    let mut first = point(1, &[2]);
    first.issue.push((10, 7));
    let mut overwrite = point(2, &[3]);
    overwrite.issue.push((20, 8));
    overwrite.invalidate.push(7);
    let input = Input {
        template: Facts {
            entry: 1,
            points: vec![first, overwrite, point(3, &[])],
        },
        uses: vec![used(3, 20)],
        definitions: vec![definition(1, 10), definition(2, 20)],
        phi_inputs: vec![],
    };
    let report = analyze_ssa(&input).unwrap();
    assert!(!loan_ids(&report, 2).unwrap().contains(&7));
    assert!(loan_ids(&report, 3).unwrap().contains(&8));
}
#[test]
fn duplicate_ssa_origin_definitions_fail_closed() {
    let mut input = sample();
    input.definitions.push(definition(3, 10));
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::DuplicateFact);
}
#[test]
fn uses_without_dominating_definition_fail_closed() {
    let mut input = sample();
    input.uses.push(used(3, 20));
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
#[test]
fn same_point_definition_and_use_has_ambiguous_order_and_is_rejected() {
    let mut input = sample();
    input.uses.push(used(4, 20));
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
fn phi_sample() -> Input {
    let mut left = point(2, &[4]);
    left.issue.push((10, 7));
    let mut right = point(3, &[4]);
    right.issue.push((20, 8));
    Input {
        template: Facts {
            entry: 1,
            points: vec![
                point(1, &[2, 3]),
                left,
                right,
                point(4, &[5]),
                point(5, &[]),
            ],
        },
        uses: vec![used(5, 30)],
        definitions: vec![definition(2, 10), definition(3, 20), definition(4, 30)],
        phi_inputs: vec![
            PhiInput {
                predecessor: 2,
                successor: 4,
                source: 10,
                destination: 30,
            },
            PhiInput {
                predecessor: 3,
                successor: 4,
                source: 20,
                destination: 30,
            },
        ],
    }
}
#[test]
fn phi_inputs_are_live_only_on_the_corresponding_incoming_edge() {
    let report = analyze_ssa(&phi_sample()).unwrap();
    assert!(report.live_at_instruction[&2].contains(&10));
    assert!(!report.live_at_instruction[&2].contains(&20));
    assert!(report.live_at_instruction[&3].contains(&20));
    assert!(!report.live_at_instruction[&3].contains(&10));
    assert!(!report.live_before_definition[&4].contains(&30));
    assert!(loan_ids(&report, 5).unwrap().contains(&7));
    assert!(loan_ids(&report, 5).unwrap().contains(&8));
}
#[test]
fn live_phi_return_does_not_launder_conflicting_writes() {
    let mut input = phi_sample();
    input.template.points[4].invalidate.push(7);
    let e = analyze_ssa(&input).unwrap_err();
    assert_eq!(
        (e.code, e.point, e.loan),
        (Code::InvalidatedLoan, 5, Some(7))
    );
}
#[test]
fn incomplete_phi_inputs_are_rejected() {
    let mut input = phi_sample();
    input.phi_inputs.pop();
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
#[test]
fn duplicate_phi_edge_inputs_are_rejected() {
    let mut input = phi_sample();
    input.phi_inputs.push(input.phi_inputs[0]);
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
#[test]
fn invalid_phi_predecessor_is_rejected() {
    let mut input = phi_sample();
    input.phi_inputs[0].predecessor = 1;
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
#[test]
fn incomplete_cfg_is_not_silently_accepted() {
    let mut input = sample();
    input.template.points[0].successors = vec![2, 12345];
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidGraph);
}
#[test]
fn a_loop_backedge_cannot_launder_a_live_loan() {
    let mut entry = point(1, &[2]);
    entry.issue.push((10, 7));
    let body = point(2, &[2, 3]);
    let mut invalidation = point(3, &[]);
    invalidation.invalidate.push(7);
    let input = Input {
        template: Facts {
            entry: 1,
            points: vec![entry, body, invalidation],
        },
        uses: vec![used(3, 10)],
        definitions: vec![definition(1, 10)],
        phi_inputs: vec![],
    };
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidatedLoan);
}
#[test]
fn raw_caller_liveness_is_not_accepted() {
    let mut input = sample();
    input.template.points[0].live_origins = vec![10];
    assert_eq!(analyze_ssa(&input).unwrap_err().code, Code::InvalidFact);
}
