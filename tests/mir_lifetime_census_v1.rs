use atto_borrow_checker::mir_lifetime_census_v1::{
    verify_closed_census, Census, Code, Event, EventKind, CONTRACT_VERSION,
};
use atto_borrow_checker::polonius_facts_v1::Code as LoanCode;

fn census(items: &[(u32, EventKind)]) -> Census {
    let records: Vec<Event> = items
        .iter()
        .enumerate()
        .map(|(i, &(point, kind))| Event {
            id: i as u64 + 1,
            source_node_id: i as u64 + 100,
            point,
            kind,
        })
        .collect();
    Census {
        version: CONTRACT_VERSION,
        entry: 1,
        expected_events: records.clone(),
        observed_events: records,
    }
}

fn lookup_insert_retry() -> Census {
    use EventKind::*;
    census(&[
        (1, Point),
        (2, Point),
        (3, Point),
        (4, Point),
        (5, Point),
        (1, Edge { to: 2 }),
        (1, Edge { to: 3 }),
        (3, Edge { to: 4 }),
        (4, Edge { to: 5 }),
        (1, Issue { origin: 10, loan: 7 }),
        (2, Use { origin: 10 }),
        (3, Invalidate { loan: 7 }),
        (4, Issue { origin: 20, loan: 8 }),
        (5, Use { origin: 20 }),
    ])
}

#[test]
fn complete_compiler_census_allows_some_return_none_insert_retry() {
    let r = verify_closed_census(&lookup_insert_retry()).unwrap();
    assert!(r.loans.live_loans_on_entry[&2].contains(&7));
    assert!(!r.loans.live_loans_on_entry[&3].contains(&7));
    assert!(r.loans.live_loans_on_entry[&5].contains(&8));
}

#[test]
fn independent_expected_inventory_rejects_missing_loan_use() {
    let mut c = lookup_insert_retry();
    c.observed_events.retain(|x| x.kind != EventKind::Use { origin: 10 });
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::Mismatch);
}

#[test]
fn identical_length_but_modified_invalidation_is_rejected() {
    let mut c = lookup_insert_retry();
    let event = c.observed_events.iter_mut().find(|x| x.kind == EventKind::Invalidate { loan: 7 }).unwrap();
    event.kind = EventKind::Kill { loan: 7 };
    assert!(matches!(verify_closed_census(&c).unwrap_err().code, Code::Mismatch));
}

#[test]
fn independently_proven_conflicting_mutation_rejects_loan() {
    let mut c = lookup_insert_retry();
    let new_id = c.expected_events.len() as u64 + 1;
    let use_on_none_path = Event {
        id: new_id,
        source_node_id: new_id + 100,
        point: 3,
        kind: EventKind::Use { origin: 10 },
    };
    c.expected_events.push(use_on_none_path);
    c.observed_events.push(use_on_none_path);
    let err = verify_closed_census(&c).unwrap_err();
    match err.code {
        Code::Lifetime(e) => {
            assert_eq!((e.code, e.point, e.loan), (LoanCode::InvalidatedLoan, 3, Some(7)));
        }
        other => panic!("expected lifetime invalidation, got {other:?}"),
    }
}

#[test]
fn duplicate_mir_event_id_is_never_permitted() {
    let mut c = lookup_insert_retry();
    c.expected_events[0].id = c.expected_events[1].id;
    c.observed_events[0].id = c.observed_events[1].id;
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::MissingOrDuplicateId);
}

#[test]
fn stale_or_unsupported_version_is_rejected() {
    let mut c = lookup_insert_retry();
    c.version += 1;
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::Version);
}

#[test]
fn missing_source_node_or_zero_point_is_rejected() {
    let mut c = lookup_insert_retry();
    c.expected_events[0].source_node_id = 0;
    c.observed_events[0].source_node_id = 0;
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::InvalidEvent);
}

#[test]
fn claimed_compiler_source_node_mismatch_fails_closed() {
    let mut c = lookup_insert_retry();
    c.observed_events[7].source_node_id += 1;
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::Mismatch);
}

#[test]
fn unknown_effect_is_rejected_even_if_both_censuses_match() {
    let mut c = lookup_insert_retry();
    c.expected_events[10].kind = EventKind::Unsupported;
    c.observed_events[10].kind = EventKind::Unsupported;
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::Unsupported);
}

#[test]
fn no_forged_edge_destination_without_point_declaration() {
    let mut c = lookup_insert_retry();
    let e = c.expected_events.iter_mut().find(|x| x.kind == EventKind::Edge { to: 5 }).unwrap();
    e.kind = EventKind::Edge { to: 999 };
    let e = c.observed_events.iter_mut().find(|x| x.kind == EventKind::Edge { to: 5 }).unwrap();
    e.kind = EventKind::Edge { to: 999 };
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::MissingPoint);
}

#[test]
fn duplicate_declared_points_rejected_even_if_different_event_ids() {
    let mut c = lookup_insert_retry();
    let new_id = c.expected_events.len() as u64 + 1;
    let dup = Event {
        id: new_id,
        source_node_id: new_id + 100,
        point: 5,
        kind: EventKind::Point,
    };
    c.expected_events.push(dup);
    c.observed_events.push(dup);
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::DuplicatePoint);
}

#[test]
fn every_effect_requires_an_existing_point_and_reachable_graph() {
    let mut c = lookup_insert_retry();
    let new_id = c.expected_events.len() as u64 + 1;
    let orphan = Event {
        id: new_id,
        source_node_id: new_id + 100,
        point: 999,
        kind: EventKind::Invalidate { loan: 7 },
    };
    c.expected_events.push(orphan);
    c.observed_events.push(orphan);
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::MissingPoint);
}

#[test]
fn results_do_not_depend_on_event_listing_order() {
    let original = lookup_insert_retry();
    let mut scrambled = original.clone();
    scrambled.expected_events.reverse();
    scrambled.observed_events.rotate_left(4);
    assert_eq!(verify_closed_census(&original), verify_closed_census(&scrambled));
}

#[test]
fn zero_input_and_oversized_inventory_fail_closed() {
    let empty = census(&[]);
    assert_eq!(verify_closed_census(&empty).unwrap_err().code, Code::Budget);
    let mut c = lookup_insert_retry();
    c.expected_events = vec![c.expected_events[0]; 100_001];
    c.observed_events = c.expected_events.clone();
    assert_eq!(verify_closed_census(&c).unwrap_err().code, Code::Budget);
}
