//! Experimental SSA-aware, path-sensitive lifetime facts.
//!
//! Only a *diagnostic model*: caller-supplied uses, CFG, alias/provenance facts,
//! and omissions are NOT authenticated. This must never authorize codegen or
//! relax the production V0/cyclic ownership verifiers.
use crate::polonius_facts_v1::{
    analyze, Code, Error, Facts, LoanId, OriginId, OriginUse, PointId, Report,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_POINTS: usize = 4096;
const MAX_EDGES: usize = 16_384;
const MAX_ORIGINS: usize = 512;
const MAX_FACTS: usize = 100_000;
const MAX_WORK: usize = 2_000_000;

/// SSA definitions are unique per origin. An overwrite gets a *fresh* origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Definition {
    pub point: PointId,
    pub origin: OriginId,
}

/// An incoming SSA phi operand belongs to ONE concrete CFG edge.
/// A destination must have one operand per predecessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhiInput {
    pub predecessor: PointId,
    pub successor: PointId,
    pub source: OriginId,
    pub destination: OriginId,
}

/// All fields are claimed facts, not compiler-issued proof or permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub template: Facts,
    pub uses: Vec<OriginUse>,
    pub definitions: Vec<Definition>,
    pub phi_inputs: Vec<PhiInput>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaReport {
    /// Before definitions at a point. Phi destinations do not leak upstream.
    pub live_before_definition: BTreeMap<PointId, BTreeSet<OriginId>>,
    /// Includes origins introduced at a point and locally needed phi sources.
    pub live_at_instruction: BTreeMap<PointId, BTreeSet<OriginId>>,
    pub loan_report: Report,
    pub inference_steps: usize,
}
fn err(code: Code, point: PointId) -> Error {
    Error {
        code,
        point,
        loan: None,
    }
}
fn charge(steps: &mut usize, point: PointId) -> Result<(), Error> {
    *steps = steps
        .checked_add(1)
        .ok_or_else(|| err(Code::WorkBudget, point))?;
    if *steps > MAX_WORK {
        return Err(err(Code::WorkBudget, point));
    }
    Ok(())
}

fn dominated(
    entry: PointId,
    def: PointId,
    target: PointId,
    graph: &BTreeMap<PointId, Vec<PointId>>,
    steps: &mut usize,
) -> Result<bool, Error> {
    if target == def {
        return Ok(true);
    }
    let mut queue = VecDeque::from([entry]);
    let mut seen = BTreeSet::new();
    while let Some(point) = queue.pop_front() {
        charge(steps, point)?;
        if point == def || !seen.insert(point) {
            continue;
        }
        if point == target {
            return Ok(false);
        }
        for &successor in &graph[&point] {
            queue.push_back(successor);
        }
    }
    Ok(true)
}

/// SSA-aware bounded backwards MAY liveness and forward loan invalidation.
///
/// The function rejects duplicate definitions, undeclared origins, use before
/// definition, incomplete phi operands, invalid CFG and excessive solver work.
/// Missing uses, exceptional edges or alias invalidations are still UNSOUND.
/// No caller is granted a compiler/runtime authority by the returned report.
pub fn analyze_ssa(input: &Input) -> Result<SsaReport, Error> {
    let facts = &input.template;
    if facts.entry == 0 || facts.points.is_empty() || facts.points.len() > MAX_POINTS {
        return Err(err(Code::InvalidGraph, facts.entry));
    }
    if input
        .uses
        .len()
        .saturating_add(input.definitions.len())
        .saturating_add(input.phi_inputs.len())
        > MAX_FACTS
    {
        return Err(err(Code::Budget, facts.entry));
    }
    let mut graph: BTreeMap<PointId, Vec<PointId>> = BTreeMap::new();
    let mut points = BTreeMap::new();
    let mut predecessors: BTreeMap<PointId, Vec<PointId>> = BTreeMap::new();
    let mut edge_count = 0usize;
    for point in &facts.points {
        if point.id == 0
            || !point.live_origins.is_empty()
            || points.insert(point.id, point).is_some()
        {
            return Err(err(Code::InvalidFact, point.id));
        }
        edge_count = edge_count.saturating_add(point.successors.len());
        if edge_count > MAX_EDGES {
            return Err(err(Code::Budget, point.id));
        }
        graph.insert(point.id, point.successors.clone());
        predecessors.insert(point.id, vec![]);
    }
    if !points.contains_key(&facts.entry) {
        return Err(err(Code::InvalidGraph, facts.entry));
    }
    for point in &facts.points {
        let mut unique = BTreeSet::new();
        for &next in &point.successors {
            if !predecessors.contains_key(&next) || !unique.insert(next) {
                return Err(err(Code::InvalidGraph, point.id));
            }
            predecessors
                .get_mut(&next)
                .expect("validated")
                .push(point.id);
        }
    }
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::from([facts.entry]);
    let mut steps = 0usize;
    while let Some(point) = queue.pop_front() {
        charge(&mut steps, point)?;
        if reachable.insert(point) {
            for &next in &graph[&point] {
                queue.push_back(next);
            }
        }
    }
    if reachable.len() != points.len() {
        return Err(err(Code::UnreachablePoint, facts.entry));
    }

    let mut definitions = BTreeMap::<OriginId, PointId>::new();
    let mut defined_at = BTreeMap::<PointId, BTreeSet<OriginId>>::new();
    for &d in &input.definitions {
        if d.origin == 0
            || !points.contains_key(&d.point)
            || definitions.insert(d.origin, d.point).is_some()
        {
            return Err(err(Code::DuplicateFact, d.point));
        }
        defined_at.entry(d.point).or_default().insert(d.origin);
    }
    if definitions.len() > MAX_ORIGINS {
        return Err(err(Code::Budget, facts.entry));
    }
    let mut local_uses = BTreeMap::<PointId, BTreeSet<OriginId>>::new();
    for &u in &input.uses {
        let Some(&defpoint) = definitions.get(&u.origin) else {
            return Err(err(Code::InvalidFact, u.point));
        };
        if !points.contains_key(&u.point)
            || u.point == defpoint
            || !local_uses.entry(u.point).or_default().insert(u.origin)
            || !dominated(facts.entry, defpoint, u.point, &graph, &mut steps)?
        {
            return Err(err(Code::InvalidFact, u.point));
        }
    }
    for point in &facts.points {
        for &(origin, _loan) in &point.issue {
            let Some(&defpoint) = definitions.get(&origin) else {
                return Err(err(Code::InvalidFact, point.id));
            };
            if !dominated(facts.entry, defpoint, point.id, &graph, &mut steps)? {
                return Err(err(Code::InvalidFact, point.id));
            }
        }
        for &(from, to) in &point.subset {
            for origin in [from, to] {
                let Some(&defpoint) = definitions.get(&origin) else {
                    return Err(err(Code::InvalidFact, point.id));
                };
                if !dominated(facts.entry, defpoint, point.id, &graph, &mut steps)? {
                    return Err(err(Code::InvalidFact, point.id));
                }
            }
        }
    }

    // A phi's incoming operands are *edge* uses, not uses in all branches.
    let mut phi_by_edge = BTreeMap::<(PointId, PointId, OriginId), OriginId>::new();
    let mut phi_destinations = BTreeMap::<PointId, BTreeSet<OriginId>>::new();
    for &phi in &input.phi_inputs {
        // Entry is reached from the caller as well as potential backedges;
        // a CFG-only predecessor census cannot account for that implicit edge.
        // An entry-block phi would therefore silently omit one operand.
        if phi.successor == facts.entry
            || phi.source == phi.destination
            || !points.contains_key(&phi.predecessor)
            || !points.contains_key(&phi.successor)
            || !graph[&phi.predecessor].contains(&phi.successor)
            || definitions.get(&phi.destination) != Some(&phi.successor)
        {
            return Err(err(Code::InvalidFact, phi.successor));
        }
        let Some(&source_def) = definitions.get(&phi.source) else {
            return Err(err(Code::InvalidFact, phi.predecessor));
        };
        if !dominated(facts.entry, source_def, phi.predecessor, &graph, &mut steps)?
            || phi_by_edge
                .insert(
                    (phi.predecessor, phi.successor, phi.destination),
                    phi.source,
                )
                .is_some()
        {
            return Err(err(Code::InvalidFact, phi.predecessor));
        }
        phi_destinations
            .entry(phi.successor)
            .or_default()
            .insert(phi.destination);
    }
    for (&successor, destinations) in &phi_destinations {
        for &predecessor in &predecessors[&successor] {
            for &dest in destinations {
                if !phi_by_edge.contains_key(&(predecessor, successor, dest)) {
                    return Err(err(Code::InvalidFact, successor));
                }
            }
        }
    }

    let mut at = BTreeMap::<PointId, BTreeSet<OriginId>>::new();
    let mut before = BTreeMap::<PointId, BTreeSet<OriginId>>::new();
    for &id in points.keys() {
        at.insert(id, BTreeSet::new());
        before.insert(id, BTreeSet::new());
    }
    let mut pending: BTreeSet<PointId> = points.keys().copied().collect();
    let mut worklist: VecDeque<PointId> = points.keys().copied().collect();
    while let Some(id) = worklist.pop_front() {
        pending.remove(&id);
        charge(&mut steps, id)?;
        let point = points[&id];
        let mut necessary = local_uses.get(&id).cloned().unwrap_or_default();
        for &(origin, _loan) in &point.issue {
            necessary.insert(origin);
        }
        for &succ in &point.successors {
            for &origin in &before[&succ] {
                charge(&mut steps, id)?;
                necessary.insert(origin);
            }
            if let Some(destinations) = phi_destinations.get(&succ) {
                for &dest in destinations {
                    charge(&mut steps, id)?;
                    if at[&succ].contains(&dest) {
                        necessary.insert(phi_by_edge[&(id, succ, dest)]);
                    }
                }
            }
        }
        // Outlives edges are local: a needed target requires its source.
        let mut close: VecDeque<OriginId> = necessary.iter().copied().collect();
        while let Some(target) = close.pop_front() {
            charge(&mut steps, id)?;
            for &(source, destination) in &point.subset {
                charge(&mut steps, id)?;
                if destination == target && necessary.insert(source) {
                    close.push_back(source);
                }
            }
            if necessary.len() > MAX_ORIGINS {
                return Err(err(Code::Budget, id));
            }
        }
        let new_before: BTreeSet<_> = necessary
            .difference(&defined_at.get(&id).cloned().unwrap_or_default())
            .copied()
            .collect();
        if necessary.len() > MAX_ORIGINS || new_before.len() > MAX_ORIGINS {
            return Err(err(Code::Budget, id));
        }
        if necessary != at[&id] || new_before != before[&id] {
            at.insert(id, necessary);
            before.insert(id, new_before);
            for &pred in &predecessors[&id] {
                charge(&mut steps, id)?;
                if pending.insert(pred) {
                    worklist.push_back(pred);
                }
            }
        }
    }

    // The existing forward solver closes local subset edges, so the phi
    // mappings must appear as local subset edges at the successor. Include
    // sources for the forward check without contaminating backwards liveness
    // on unrelated incoming edges. This can be conservative at joins.
    let mut enriched = facts.clone();
    for point in &mut enriched.points {
        let mut live = at[&point.id].clone();
        let mut subsets: BTreeSet<(OriginId, OriginId)> = point.subset.iter().copied().collect();
        if let Some(destinations) = phi_destinations.get(&point.id) {
            for &dest in destinations {
                if at[&point.id].contains(&dest) {
                    for &pred in &predecessors[&point.id] {
                        let from = phi_by_edge[&(pred, point.id, dest)];
                        live.insert(from);
                        subsets.insert((from, dest));
                    }
                }
            }
        }
        point.subset = subsets.into_iter().collect();
        point.live_origins = live.into_iter().collect();
    }
    let loan_report = analyze(&enriched)?;
    Ok(SsaReport {
        live_before_definition: before,
        live_at_instruction: at,
        loan_report,
        inference_steps: steps,
    })
}

/// Returns just the set of distinct live loan IDs at each point for easy
/// differential comparison. This does not authorize runtime permissions.
pub fn loan_ids(report: &SsaReport, point: PointId) -> Option<&BTreeSet<LoanId>> {
    report.loan_report.live_loans_on_entry.get(&point)
}
