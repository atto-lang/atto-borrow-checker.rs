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
