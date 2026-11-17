//! Experimental point-sensitive loan reachability, inspired by Polonius.
//!
//! This is a bounded fact oracle, NOT rustc Polonius Alpha, nor an
//! authenticated typed-MIR or AttoLang guest-code emission proof.
//! Incorrect or incomplete caller-provided liveness facts are UNSOUND.
//! Existing V0 and cyclic ownership verifiers stay authoritative.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type PointId = u32;
pub type OriginId = u32;
pub type LoanId = u32;

const MAX_POINTS: usize = 4096;
const MAX_EDGES: usize = 16384;
const MAX_ORIGINS: usize = 512;
const MAX_LOANS: usize = 2048;
const MAX_INPUT_FACTS: usize = 100_000;
const MAX_FACTS_PER_POINT: usize = 8192;
const MAX_RETAINED_FACTS: usize = 200_000;
const MAX_WORK: usize = 2_000_000;

/// All effects occur at instruction points. Invalidations inspect entry,
/// while kills and issuances modify the facts passed to successors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub id: PointId,
    pub successors: Vec<PointId>,
    pub live_origins: Vec<OriginId>,
    /// Point-local directed subset edges: a loan in from flows into to.
    pub subset: Vec<(OriginId, OriginId)>,
    /// A loan created at this point is visible to successor instructions.
    pub issue: Vec<(OriginId, LoanId)>,
    pub kill: Vec<LoanId>,
    pub invalidate: Vec<LoanId>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub entry: PointId,
    pub points: Vec<Point>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidGraph,
    InvalidFact,
    DuplicateFact,
    UnknownLoan,
    UnreachablePoint,
    Budget,
    WorkBudget,
    InvalidatedLoan,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub point: PointId,
    pub loan: Option<LoanId>,
}
fn error(code: Code, point: PointId) -> Error {
    Error {
        code,
        point,
        loan: None,
    }
}
/// MAY-live loans on each instruction's entry. This is an observation, not an
/// independently authenticated compiler / runtime capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub live_loans_on_entry: BTreeMap<PointId, BTreeSet<LoanId>>,
    pub steps: usize,
}
fn charge(steps: &mut usize, cost: usize, point: PointId) -> Result<(), Error> {
    *steps = steps
        .checked_add(cost)
        .ok_or_else(|| error(Code::WorkBudget, point))?;
    if *steps > MAX_WORK {
        return Err(error(Code::WorkBudget, point));
    }
    Ok(())
}
fn preflight(facts: &Facts) -> Result<BTreeMap<PointId, &Point>, Error> {
    if facts.entry == 0 || facts.points.is_empty() || facts.points.len() > MAX_POINTS {
        return Err(error(Code::InvalidGraph, facts.entry));
    }
    let mut points = BTreeMap::new();
    let mut origins = BTreeSet::new();
    let mut issued = BTreeSet::new();
    let mut loan_references = Vec::new();
    let mut edges = 0usize;
    let mut fact_count = 0usize;
    // Bound untrusted input before creating a reachability worklist.
    for p in &facts.points {
        if p.id == 0 || points.insert(p.id, p).is_some() {
            return Err(error(Code::InvalidGraph, p.id));
        }
        edges = edges
            .checked_add(p.successors.len())
            .ok_or_else(|| error(Code::Budget, p.id))?;
        let n = p
            .live_origins
            .len()
            .checked_add(p.subset.len())
            .and_then(|n| n.checked_add(p.issue.len()))
            .and_then(|n| n.checked_add(p.kill.len()))
            .and_then(|n| n.checked_add(p.invalidate.len()))
            .ok_or_else(|| error(Code::Budget, p.id))?;
        fact_count = fact_count
            .checked_add(n)
            .ok_or_else(|| error(Code::Budget, p.id))?;
        if edges > MAX_EDGES || fact_count > MAX_INPUT_FACTS {
            return Err(error(Code::Budget, p.id));
        }
    }
    if !points.contains_key(&facts.entry) {
        return Err(error(Code::InvalidGraph, facts.entry));
    }
    for p in &facts.points {
        let mut outgoing = BTreeSet::new();
        for &succ in &p.successors {
            if !points.contains_key(&succ) || !outgoing.insert(succ) {
                return Err(error(Code::InvalidGraph, p.id));
            }
        }
        let mut live = BTreeSet::new();
        for &origin in &p.live_origins {
            if origin == 0 || !live.insert(origin) {
                return Err(error(Code::DuplicateFact, p.id));
            }
            origins.insert(origin);
        }
        let mut subset = BTreeSet::new();
        for &(from, to) in &p.subset {
            if from == 0 || to == 0 || !subset.insert((from, to)) {
                return Err(error(Code::DuplicateFact, p.id));
            }
            origins.insert(from);
            origins.insert(to);
        }
        for &(origin, loan) in &p.issue {
            if origin == 0 || loan == 0 || !live.contains(&origin) {
                return Err(error(Code::InvalidFact, p.id));
            }
            if !issued.insert(loan) {
                return Err(error(Code::DuplicateFact, p.id));
            }
        }
        let mut kills = BTreeSet::new();
        let mut invalidations = BTreeSet::new();
        for &loan in &p.kill {
            if loan == 0 || !kills.insert(loan) {
                return Err(error(Code::DuplicateFact, p.id));
            }
            loan_references.push((p.id, loan));
        }
        for &loan in &p.invalidate {
            if loan == 0 || !invalidations.insert(loan) {
                return Err(error(Code::DuplicateFact, p.id));
            }
            loan_references.push((p.id, loan));
        }
        if p.issue.iter().any(|&(_, loan)| kills.contains(&loan)) {
            return Err(error(Code::InvalidFact, p.id));
        }
    }
    if origins.len() > MAX_ORIGINS || issued.len() > MAX_LOANS {
        return Err(error(Code::Budget, facts.entry));
    }
    for (point, loan) in loan_references {
        if !issued.contains(&loan) {
            return Err(Error {
                code: Code::UnknownLoan,
                point,
                loan: Some(loan),
            });
        }
    }
    // Orphan points could hide omitted CFG effects; fail closed.
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(facts.entry);
    while let Some(point) = queue.pop_front() {
        if visited.insert(point) {
            for &succ in &points[&point].successors {
                queue.push_back(succ);
            }
        }
    }
    if visited.len() != points.len() {
        return Err(error(Code::UnreachablePoint, facts.entry));
    }
    Ok(points)
}
/// Computes a forward MAY fixed point for already-proven, complete loan facts.
///
/// A source compiler may NOT bypass its ownership checker on this report.
/// Incorrect origin liveness, exceptional edges or invalidation inventory may
/// cause false acceptance. The caller must prove all three independently.
pub fn analyze(facts: &Facts) -> Result<Report, Error> {
    let points = preflight(facts)?;
    type Pair = (OriginId, LoanId);
    let mut incoming: BTreeMap<PointId, BTreeSet<Pair>> =
        points.keys().map(|&p| (p, BTreeSet::new())).collect();
    let mut active = BTreeMap::new();
    // Seed every point, including those with no incoming loan facts.
    let mut queue: VecDeque<PointId> = points.keys().copied().collect();
    let mut pending: BTreeSet<PointId> = points.keys().copied().collect();
    let mut steps = 0usize;
    let mut retained = 0usize;
    while let Some(point) = queue.pop_front() {
        pending.remove(&point);
        charge(&mut steps, 1, point)?;
        let p = points[&point];
        let mut local = incoming[&point].clone();
        let mut closure: VecDeque<Pair> = local.iter().copied().collect();
        // Close transitive point-local subset edges BEFORE removing dead
        // intermediaries, or a live downstream origin can lose its loan.
        while let Some((origin, loan)) = closure.pop_front() {
            charge(&mut steps, 1, point)?;
            for &(from, to) in &p.subset {
                charge(&mut steps, 1, point)?;
                if origin == from && local.insert((to, loan)) {
                    if local.len() > MAX_FACTS_PER_POINT {
                        return Err(error(Code::Budget, point));
                    }
                    closure.push_back((to, loan));
                }
            }
        }
        let live: BTreeSet<OriginId> = p.live_origins.iter().copied().collect();
        local.retain(|(origin, _)| live.contains(origin));
        let loans: BTreeSet<LoanId> = local.iter().map(|&(_, loan)| loan).collect();
        for &loan in &p.invalidate {
            if loans.contains(&loan) {
                return Err(Error {
                    code: Code::InvalidatedLoan,
                    point,
                    loan: Some(loan),
                });
            }
        }
        active.insert(point, loans);
        let killed: BTreeSet<LoanId> = p.kill.iter().copied().collect();
        local.retain(|(_, loan)| !killed.contains(loan));
        for &pair in &p.issue {
            local.insert(pair);
        }
        // Newly issued loans must also traverse subset edges at this
        // instruction. Otherwise an issue in A followed by A -> B here,
        // with only B live at the successor, could be unsafely dropped.
        let mut issued_closure: VecDeque<Pair> = p.issue.iter().copied().collect();
        while let Some((origin, loan)) = issued_closure.pop_front() {
            charge(&mut steps, 1, point)?;
            for &(from, to) in &p.subset {
                charge(&mut steps, 1, point)?;
                if origin == from && local.insert((to, loan)) {
                    if local.len() > MAX_FACTS_PER_POINT {
                        return Err(error(Code::Budget, point));
                    }
                    issued_closure.push_back((to, loan));
                }
            }
        }
        if local.len() > MAX_FACTS_PER_POINT {
            return Err(error(Code::Budget, point));
        }
        for &succ in &p.successors {
            let target = incoming.get_mut(&succ).expect("validated CFG");
            let mut changed = false;
            for &pair in &local {
                charge(&mut steps, 1, point)?;
                if target.insert(pair) {
                    retained = retained
                        .checked_add(1)
                        .ok_or_else(|| error(Code::Budget, succ))?;
                    if target.len() > MAX_FACTS_PER_POINT || retained > MAX_RETAINED_FACTS {
                        return Err(error(Code::Budget, succ));
                    }
                    changed = true;
                }
            }
            if changed && pending.insert(succ) {
                queue.push_back(succ);
            }
        }
    }
    Ok(Report {
        live_loans_on_entry: active,
        steps,
    })
}


/// A verified MIR use of one loan-bearing origin at an instruction point.
///
/// A terminal return carrying a borrow MUST appear as a use. Input argument
/// loans MUST be represented by an entry-point issuance. These obligations
/// cannot be established from the data supplied to this host-only oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginUse {
    pub point: PointId,
    pub origin: OriginId,
}

/// Inferred origin lifetimes and the resulting pointwise loan report.
///
/// This is not a compiler proof: the MIR producer still must independently
/// certify all uses, CFG edges, exceptional exits, issuances and invalidations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredReport {
    pub live_origins_on_entry: BTreeMap<PointId, BTreeSet<OriginId>>,
    pub loans: Report,
    pub inference_steps: usize,
}

/// Backward MAY liveness from authenticated typed-MIR origin uses, then
/// forward loan checking. This avoids extending a returned borrow through
/// an alternate branch that never uses it.
///
/// For this API, the template's live_origins MUST be empty: no caller may
/// smuggle manually chosen liveness into the derived result. Origins are
/// conservative: this V1 inference has no overwrite/phi-kill facts, so it
/// may retain loans longer than necessary. Missing MIR uses are UNSOUND;
/// production callers must independently certify the complete use census.
/// Existing V0/cyclic verifiers remain authoritative.
pub fn analyze_with_inferred_liveness(
    template: &Facts,
    uses: &[OriginUse],
) -> Result<InferredReport, Error> {
    if template.points.is_empty()
        || template.points.len() > MAX_POINTS
        || uses.len() > MAX_INPUT_FACTS
    {
        return Err(error(Code::Budget, template.entry));
    }

    let mut points = BTreeMap::new();
    let mut predecessors: BTreeMap<PointId, Vec<PointId>> = BTreeMap::new();
    let mut live: BTreeMap<PointId, BTreeSet<OriginId>> = BTreeMap::new();
    let mut origins = BTreeSet::new();
    let mut declared_origins = BTreeSet::new();
    let mut edge_count = 0usize;

    for point in &template.points {
        if point.id == 0 || !point.live_origins.is_empty() || points.insert(point.id, point).is_some()
        {
            return Err(error(Code::InvalidFact, point.id));
        }
        predecessors.insert(point.id, Vec::new());
        live.insert(point.id, BTreeSet::new());
        edge_count = edge_count
            .checked_add(point.successors.len())
            .ok_or_else(|| error(Code::Budget, point.id))?;
        if edge_count > MAX_EDGES {
            return Err(error(Code::Budget, point.id));
        }
        for &(origin, _) in &point.issue {
            if origin == 0 {
                return Err(error(Code::InvalidFact, point.id));
            }
            origins.insert(origin);
            declared_origins.insert(origin);
        }
        for &(from, to) in &point.subset {
            if from == 0 || to == 0 {
                return Err(error(Code::InvalidFact, point.id));
            }
            origins.insert(from);
            origins.insert(to);
            declared_origins.insert(from);
            declared_origins.insert(to);
        }
    }

    if template.entry == 0 || !points.contains_key(&template.entry) {
        return Err(error(Code::InvalidGraph, template.entry));
    }
    // Enforce the finite graph budget before allocating predecessor lists.
    for point in &template.points {
        for &succ in &point.successors {
            let Some(preds) = predecessors.get_mut(&succ) else {
                return Err(error(Code::InvalidGraph, point.id));
            };
            preds.push(point.id);
        }
    }

    let mut seen_uses = BTreeSet::new();
    for &used in uses {
        if used.point == 0
            || used.origin == 0
            || !points.contains_key(&used.point)
            || !seen_uses.insert(used)
        {
            return Err(error(Code::InvalidFact, used.point));
        }
        if !declared_origins.contains(&used.origin) {
            return Err(error(Code::InvalidFact, used.point));
        }
        origins.insert(used.origin);
        live.get_mut(&used.point)
            .expect("validated use point")
            .insert(used.origin);
    }
    if origins.len() > MAX_ORIGINS {
        return Err(error(Code::Budget, template.entry));
    }

    // Each issued origin is needed at least at its issuance instruction.
    for point in &template.points {
        for &(origin, _) in &point.issue {
            live.get_mut(&point.id)
                .expect("validated issue point")
                .insert(origin);
        }
    }

    let mut retained = 0usize;
    for (&id, origins_at_point) in &live {
        if origins_at_point.len() > MAX_ORIGINS {
            return Err(error(Code::Budget, id));
        }
        retained = retained
            .checked_add(origins_at_point.len())
            .ok_or_else(|| error(Code::Budget, id))?;
    }
    if retained > MAX_RETAINED_FACTS {
        return Err(error(Code::Budget, template.entry));
    }

    let mut queue: VecDeque<PointId> = points.keys().copied().collect();
    let mut pending: BTreeSet<PointId> = points.keys().copied().collect();
    let mut steps = 0usize;
    while let Some(id) = queue.pop_front() {
        pending.remove(&id);
        charge(&mut steps, 1, id)?;
        let point = points[&id];
        let mut needed = live[&id].clone();

        // Backwards through *all* possible successors: a use on only the
        // Some/return arm does NOT make that origin live in the None arm.
        for &succ in &point.successors {
            for &origin in &live[&succ] {
                charge(&mut steps, 1, id)?;
                needed.insert(origin);
            }
        }

        // A target region used later also requires the source region of
        // each local outlives/subset edge. Traverse the reverse closure.
        let mut closure: VecDeque<OriginId> = needed.iter().copied().collect();
        while let Some(target) = closure.pop_front() {
            charge(&mut steps, 1, id)?;
            for &(from, to) in &point.subset {
                charge(&mut steps, 1, id)?;
                if to == target && needed.insert(from) {
                    if needed.len() > MAX_ORIGINS {
                        return Err(error(Code::Budget, id));
                    }
                    closure.push_back(from);
                }
            }
        }

        let old_len = live[&id].len();
        if needed.len() > MAX_ORIGINS {
            return Err(error(Code::Budget, id));
        }
        if needed.len() > old_len {
            retained = retained
                .checked_add(needed.len() - old_len)
                .ok_or_else(|| error(Code::Budget, id))?;
            if retained > MAX_RETAINED_FACTS {
                return Err(error(Code::Budget, id));
            }
            live.insert(id, needed);
            for &pred in &predecessors[&id] {
                charge(&mut steps, 1, id)?;
                if pending.insert(pred) {
                    queue.push_back(pred);
                }
            }
        }
    }

    let enriched = Facts {
        entry: template.entry,
        points: template
            .points
            .iter()
            .map(|point| {
                let mut point = point.clone();
                point.live_origins = live[&point.id].iter().copied().collect();
                point
            })
            .collect(),
    };

    // This performs the existing independent CFG/fact structural preflight,
    // bounded forward loan propagation and invalidation checks.
    let loans = analyze(&enriched)?;
    Ok(InferredReport {
        live_origins_on_entry: live,
        loans,
        inference_steps: steps,
    })
}
