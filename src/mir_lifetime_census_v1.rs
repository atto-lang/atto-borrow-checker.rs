//! Strict, experimental typed-MIR lifetime event census bridge.
//!
//! This checks TWO submitted manifests for exact, complete event equality
//! and reconstructs the entire CFG/loan model from the observed events.
//! Neither manifest is cryptographically authenticated: an independently
//! trusted frontend must produce the expected census from source/typed MIR,
//! and a separate lowering pass must produce the observed census. Both
//! inventories must include every exceptional/cancellation and return edge.
//! This is HOST MODEL ONLY, never permission to emit executable guest code.

use std::collections::{BTreeMap, BTreeSet};

use crate::polonius_facts_v1::{
    analyze_with_inferred_liveness, Error as LoanError, Facts, InferredReport, OriginUse, Point,
};

pub const CONTRACT_VERSION: u32 = 1;
const MAX_EVENTS: usize = 100_000;
const MAX_POINTS: usize = 4096;

/// Every event has a unique stable MIR ID, a nonzero source node ID and a
/// point ID. An independent source-vs-lowered inventory must contain exactly
/// the same events (including edges and return-borrow uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Event {
    pub id: u64,
    pub source_node_id: u64,
    pub point: u32,
    pub kind: EventKind,
}

/// Closed vocabulary: unknown FFI, suspension, actor-transfer, unwinding,
/// cleanup or dynamically aliased effects must be represented as Unsupported
/// and rejected. The absence of an event is NOT proof of safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventKind {
    Point,
    Edge {
        to: u32,
    },
    Issue {
        origin: u32,
        loan: u32,
    },
    Kill {
        loan: u32,
    },
    Invalidate {
        loan: u32,
    },
    Subset {
        from: u32,
        to: u32,
    },
    /// SSA phi incoming edge. Must be represented by a dedicated CFG edge
    /// split point having exactly one predecessor and one successor. This
    /// prevents incorrectly mixing both predecessors' region identities.
    PhiEdge {
        from: u32,
        to: u32,
    },
    /// Includes return-borrow and captured-borrow uses at their own points.
    Use {
        origin: u32,
    },
    Unsupported,
}

/// The expected_events inventory MUST be independently enumerated from the
/// source/typed MIR, not computed by copying observed_events. A source
/// digest or compiler SHA is not authenticated by this API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    pub version: u32,
    pub entry: u32,
    pub expected_events: Vec<Event>,
    pub observed_events: Vec<Event>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Version,
    Budget,
    MissingOrDuplicateId,
    Mismatch,
    Unsupported,
    MissingPoint,
    DuplicatePoint,
    InvalidEvent,
    Lifetime(LoanError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub event_id: u64,
}
fn fail(code: Code, event_id: u64) -> Error {
    Error { code, event_id }
}

fn inventory(events: &[Event]) -> Result<BTreeMap<u64, Event>, Error> {
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(fail(Code::Budget, 0));
    }
    let mut inventory = BTreeMap::new();
    for &event in events {
        if event.id == 0 || event.source_node_id == 0 || event.point == 0 {
            return Err(fail(Code::InvalidEvent, event.id));
        }
        if matches!(event.kind, EventKind::Unsupported) {
            return Err(fail(Code::Unsupported, event.id));
        }
        if inventory.insert(event.id, event).is_some() {
            return Err(fail(Code::MissingOrDuplicateId, event.id));
        }
    }
    Ok(inventory)
}

/// Strictly compare the submitted independent source and lowering censuses,
/// then rebuild and analyze the loan graph. A successful report is *not*
/// authentication of either census and must not override existing V0/cyclic
/// rejections or compiler-local type/effect checking.
pub fn verify_closed_census(census: &Census) -> Result<InferredReport, Error> {
    if census.version != CONTRACT_VERSION {
        return Err(fail(Code::Version, 0));
    }
    if census.entry == 0 || census.expected_events.len() != census.observed_events.len() {
        return Err(fail(Code::Mismatch, 0));
    }
    let expected = inventory(&census.expected_events)?;
    let observed = inventory(&census.observed_events)?;
    if expected.len() != observed.len() {
        return Err(fail(Code::Mismatch, 0));
    }
    for (&id, source_event) in &expected {
        if observed.get(&id) != Some(source_event) {
            return Err(fail(Code::Mismatch, id));
        }
    }

    let mut points = BTreeMap::<u32, Point>::new();
    let mut point_declarations = BTreeSet::new();
    // Build all point declarations first, so no event can refer to an
    // implicit or fabricated instruction boundary.
    for event in observed.values() {
        if event.kind == EventKind::Point {
            if !point_declarations.insert(event.point) {
                return Err(fail(Code::DuplicatePoint, event.id));
            }
            if points.len() >= MAX_POINTS {
                return Err(fail(Code::Budget, event.id));
            }
            points.insert(
                event.point,
                Point {
                    id: event.point,
                    successors: Vec::new(),
                    live_origins: Vec::new(),
                    subset: Vec::new(),
                    issue: Vec::new(),
                    kill: Vec::new(),
                    invalidate: Vec::new(),
                },
            );
        }
    }
    if !points.contains_key(&census.entry) {
        return Err(fail(Code::MissingPoint, 0));
    }
    let mut uses = Vec::new();
    let mut phi_points = BTreeSet::new();
    let mut seen_events = BTreeSet::new();
    for event in observed.values() {
        let Some(point) = points.get_mut(&event.point) else {
            return Err(fail(Code::MissingPoint, event.id));
        };
        if !seen_events.insert((event.point, event.kind)) {
            return Err(fail(Code::InvalidEvent, event.id));
        }
        match event.kind {
            EventKind::Point => {}
            EventKind::Edge { to } => {
                if to == 0 || !point_declarations.contains(&to) {
                    return Err(fail(Code::MissingPoint, event.id));
                }
                point.successors.push(to);
            }
            EventKind::Issue { origin, loan } => {
                if origin == 0 || loan == 0 {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                point.issue.push((origin, loan));
            }
            EventKind::Kill { loan } => {
                if loan == 0 {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                point.kill.push(loan);
            }
            EventKind::Invalidate { loan } => {
                if loan == 0 {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                point.invalidate.push(loan);
            }
            EventKind::Subset { from, to } => {
                if from == 0 || to == 0 {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                point.subset.push((from, to));
            }
            EventKind::PhiEdge { from, to } => {
                if from == 0 || to == 0 || from == to || !phi_points.insert(event.point) {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                point.subset.push((from, to));
            }
            EventKind::Use { origin } => {
                if origin == 0 {
                    return Err(fail(Code::InvalidEvent, event.id));
                }
                uses.push(OriginUse {
                    point: event.point,
                    origin,
                });
            }
            EventKind::Unsupported => {
                return Err(fail(Code::Unsupported, event.id));
            }
        }
    }
    // An edge-local SSA phi must not be lowered as a join-wide subset:
    // each incoming predecessor gets its OWN explicit edge split point.
    let mut predecessors = BTreeMap::<u32, usize>::new();
    for point in points.values() {
        for &successor in &point.successors {
            *predecessors.entry(successor).or_insert(0) += 1;
        }
    }
    for &id in &phi_points {
        let point = &points[&id];
        if id == census.entry
            || predecessors.get(&id) != Some(&1)
            || point.successors.len() != 1
            || point.subset.len() != 1
            || !point.issue.is_empty()
            || !point.kill.is_empty()
            || !point.invalidate.is_empty()
            || uses.iter().any(|used| used.point == id)
        {
            return Err(fail(Code::InvalidEvent, 0));
        }
    }
    let facts = Facts {
        entry: census.entry,
        points: points.into_values().collect(),
    };
    analyze_with_inferred_liveness(&facts, &uses).map_err(|e| fail(Code::Lifetime(e), 0))
}
