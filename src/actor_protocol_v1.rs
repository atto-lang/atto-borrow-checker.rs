//! Source-derived, bounded affine actor-protocol CFG verification.
//!
//! This checker is an independent *model of typed MIR*, not a source parser,
//! backend permit, authenticated runtime stream, or actor-generation fence.
//! The compiler must prove every submitted operation and successor is real.
//! No guest can forge an Init, successful EOF or actor incarnation witness.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type BlockId = u32;
pub type PlaceId = u32;
pub type LeaseId = u32;
pub type LoanId = u32;

const MAX_BLOCKS: usize = 1024;
const MAX_EDGES: usize = 4096;
const MAX_OPS: usize = 16_384;
const MAX_HANDLES: usize = 128;
const MAX_LEASES: usize = 256;
const MAX_LOANS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode { Unary, Stream }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub from: String,
    pub message: String,
    pub payload: Option<String>,
    pub to: String,
    pub mode: Mode,
    pub response: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Protocol {
    pub name: String,
    pub initial: String,
    pub states: BTreeSet<String>,
    pub terminal: BTreeSet<String>,
    pub transitions: Vec<Transition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoanKind { Read, Exclusive }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Op {
    /// Compiler-authenticated actor-spawn result; only allowed in entry block.
    Init { place: PlaceId, protocol: String },
    Take { from: PlaceId, into: PlaceId },
    /// A protocol capability is not Copy, even when its representation is.
    Copy { from: PlaceId, into: PlaceId },
    Borrow { place: PlaceId, loan: LoanId, kind: LoanKind },
    EndBorrow { loan: LoanId },
    /// Moves authority from handle to a request/stream lease before suspension.
    Begin { from: PlaceId, lease: LeaseId, message: String,
            payload: Option<String>, mode: Mode, response: String },
    MoveLease { from: LeaseId, into: LeaseId },
    /// Four ordered successors: success, error, timeout, cancel.
    AwaitUnary { lease: LeaseId, into: PlaceId },
    /// Five ordered successors: item, EOF, error, timeout, cancel.
    AwaitStream { lease: LeaseId, into: PlaceId },
    CancelLease { lease: LeaseId },
    ReturnHandle { place: PlaceId },
    DisposeTerminal { place: PlaceId },
    Suspend,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub id: BlockId,
    pub ops: Vec<Op>,
    pub successors: Vec<BlockId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub entry: BlockId,
    pub suspending: bool,
    pub protocols: Vec<Protocol>,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub block: BlockId,
    pub op: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof { pub blocks: usize, pub operations: usize }

fn err(code: &'static str, block: BlockId, op: usize) -> Diagnostic {
    Diagnostic { code, block, op }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Owner { protocol: String, states: BTreeSet<String>, maybe_absent: bool }
impl Owner {
    fn moved(&self) -> Self {
        Self { protocol: self.protocol.clone(), states: BTreeSet::new(), maybe_absent: true }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Lease { protocol: String, next: BTreeSet<String>, mode: Mode }

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct Facts {
    owners: BTreeMap<PlaceId, Owner>,
    leases: BTreeMap<LeaseId, Lease>,
    loans: BTreeMap<LoanId, (PlaceId, LoanKind)>,
    /// One returned affine capability per path in the bounded single-result ABI.
    returned_handles: u8,
}

fn live<'a>(facts: &'a Facts, id: PlaceId, block: BlockId, i: usize) -> Result<&'a Owner, Diagnostic> {
    match facts.owners.get(&id) {
        Some(x) if !x.maybe_absent && !x.states.is_empty() => Ok(x),
        _ => Err(err("E_PROTOCOL_HANDLE_NOT_LIVE", block, i)),
    }
}
fn target(facts: &Facts, id: PlaceId, block: BlockId, i: usize) -> Result<(), Diagnostic> {
    if facts.owners.get(&id).is_some_and(|o| !o.maybe_absent || !o.states.is_empty()) {
        return Err(err("E_PROTOCOL_TARGET_LIVE", block, i));
    }
    if !facts.owners.contains_key(&id) && facts.owners.len() >= MAX_HANDLES {
        return Err(err("E_PROTOCOL_HANDLE_BUDGET", block, i));
    }
    Ok(())
}
fn no_loans(facts: &Facts, block: BlockId, i: usize) -> Result<(), Diagnostic> {
    if facts.loans.is_empty() { Ok(()) } else { Err(err("E_PROTOCOL_LOAN_ACROSS_AWAIT", block, i)) }
}
fn loan_on(facts: &Facts, place: PlaceId) -> bool {
    facts.loans.values().any(|(p, _)| *p == place)
}
fn join(mut left: Facts, right: &Facts, block: BlockId) -> Result<Facts, Diagnostic> {
    if left.leases != right.leases { return Err(err("E_PROTOCOL_LEASE_JOIN", block, 0)); }
    if left.loans != right.loans { return Err(err("E_PROTOCOL_LOAN_JOIN", block, 0)); }
    if left.returned_handles != right.returned_handles {
        return Err(err("E_PROTOCOL_RETURN_JOIN", block, 0));
    }
    let ids: BTreeSet<_> = left.owners.keys().chain(right.owners.keys()).copied().collect();
    if ids.len() > MAX_HANDLES { return Err(err("E_PROTOCOL_HANDLE_BUDGET", block, 0)); }
    for id in ids {
        match (left.owners.get(&id).cloned(), right.owners.get(&id)) {
            (Some(a), Some(b)) => {
                if a.protocol != b.protocol { return Err(err("E_PROTOCOL_HANDLE_JOIN", block, 0)); }
                let mut states = a.states;
                states.extend(b.states.iter().cloned());
                left.owners.insert(id, Owner {
                    protocol: a.protocol, states, maybe_absent: a.maybe_absent || b.maybe_absent,
                });
            }
            (None, Some(b)) => { let mut b = b.clone(); b.maybe_absent = true; left.owners.insert(id, b); }
            (Some(mut a), None) => { a.maybe_absent = true; left.owners.insert(id, a); }
            (None, None) => {}
        }
    }
    Ok(left)
}

fn checked_protocols(program: &Program) -> Result<BTreeMap<&str, &Protocol>, Diagnostic> {
    if program.protocols.is_empty() || program.protocols.len() > 16 {
        return Err(err("E_PROTOCOL_BUDGET", program.entry, 0));
    }
    let mut protocols = BTreeMap::new();
    for p in &program.protocols {
        if p.name.is_empty() || p.states.is_empty() || p.states.len() > 64
            || !p.states.contains(&p.initial) || p.terminal.is_empty()
            || !p.terminal.is_subset(&p.states) || p.terminal.contains(&p.initial)
            || p.transitions.len() > 256 || protocols.insert(p.name.as_str(), p).is_some() {
            return Err(err("E_PROTOCOL_INVALID", program.entry, 0));
        }
        let mut keys = BTreeSet::new();
        for t in &p.transitions {
            if !p.states.contains(&t.from) || !p.states.contains(&t.to)
                || p.terminal.contains(&t.from) || t.message.is_empty()
                || t.response.is_empty() || !keys.insert((&t.from, &t.message)) {
                return Err(err("E_PROTOCOL_INVALID", program.entry, 0));
            }
        }
    }
    Ok(protocols)
}

/// Verify *only* the exact source-derived MIR operations. Authentication of
/// Init, actor generation, successful EOF and terminal events is an external
/// compiler+runtime obligation. This result is never a guest authorization.
pub fn verify(program: &Program) -> Result<Proof, Diagnostic> {
    let protocols = checked_protocols(program)?;
    if program.blocks.is_empty() || program.blocks.len() > MAX_BLOCKS {
        return Err(err("E_PROTOCOL_CFG_BUDGET", program.entry, 0));
    }
    let mut blocks = BTreeMap::new();
    let (mut edges, mut operations) = (0usize, 0usize);
    let mut issued_init = BTreeSet::new();
    let mut issued_leases = BTreeSet::new();
    let mut issued_loans = BTreeSet::new();
    for b in &program.blocks {
        if blocks.insert(b.id, b).is_some() { return Err(err("E_PROTOCOL_CFG_DUPLICATE", b.id, 0)); }
        edges += b.successors.len();
        operations += b.ops.len();
        if edges > MAX_EDGES || operations > MAX_OPS || b.ops.len() > 1024 {
            return Err(err("E_PROTOCOL_CFG_BUDGET", b.id, 0));
        }
        if b.successors.is_empty() && !matches!(b.ops.last(), Some(Op::Return)) {
            return Err(err("E_PROTOCOL_IMPLICIT_EXIT", b.id, b.ops.len()));
        }
        for (i, op) in b.ops.iter().enumerate() {
            match op {
                Op::Init { place, .. } => {
                    if b.id != program.entry || !issued_init.insert(*place)
                        || issued_init.len() > MAX_HANDLES {
                        return Err(err("E_PROTOCOL_INIT_PROVENANCE", b.id, i));
                    }
                }
                Op::Begin { lease, .. } => {
                    if !issued_leases.insert(*lease) || issued_leases.len() > MAX_LEASES {
                        return Err(err("E_PROTOCOL_LEASE_ID", b.id, i));
                    }
                }
                Op::MoveLease { into, .. } => {
                    if !issued_leases.insert(*into) || issued_leases.len() > MAX_LEASES {
                        return Err(err("E_PROTOCOL_LEASE_ID", b.id, i));
                    }
                }
                Op::Borrow { loan, .. } => {
                    if !issued_loans.insert(*loan) || issued_loans.len() > MAX_LOANS {
                        return Err(err("E_PROTOCOL_LOAN_ID", b.id, i));
                    }
                }
                Op::AwaitUnary { .. } | Op::AwaitStream { .. } => {
                    let expected = if matches!(op, Op::AwaitUnary { .. }) { 4 } else { 5 };
                    if i + 1 != b.ops.len() || b.successors.len() != expected {
                        return Err(err("E_PROTOCOL_OUTCOME_SHAPE", b.id, i));
                    }
                }
                Op::Return if i + 1 != b.ops.len() || !b.successors.is_empty() => {
                    return Err(err("E_PROTOCOL_CFG_SHAPE", b.id, i));
                }
                _ => {}
            }
        }
    }
    if !blocks.contains_key(&program.entry) { return Err(err("E_PROTOCOL_CFG_ENTRY", program.entry, 0)); }
    let mut degree: BTreeMap<BlockId, usize> = blocks.keys().map(|k| (*k, 0)).collect();
    for b in blocks.values() {
        let mut targets = BTreeSet::new();
        for target in &b.successors {
            if !targets.insert(*target) || !degree.contains_key(target) {
                return Err(err("E_PROTOCOL_CFG_EDGE", b.id, 0));
            }
            *degree.get_mut(target).expect("checked") += 1;
        }
    }
    let mut visited = BTreeSet::new();
    let mut q = VecDeque::from([program.entry]);
    while let Some(id) = q.pop_front() {
        if visited.insert(id) { q.extend(blocks[&id].successors.iter().copied()); }
    }
    if visited.len() != blocks.len() { return Err(err("E_PROTOCOL_CFG_UNREACHABLE", program.entry, 0)); }
    let mut ready: VecDeque<_> = degree.iter().filter(|(_, n)| **n == 0).map(|(k, _)| *k).collect();
    let mut order = Vec::new();
    while let Some(id) = ready.pop_front() {
        order.push(id);
        for target in &blocks[&id].successors {
            let d = degree.get_mut(target).expect("checked");
            *d -= 1;
            if *d == 0 { ready.push_back(*target); }
        }
    }
    if order.len() != blocks.len() { return Err(err("E_PROTOCOL_CFG_CYCLE", program.entry, 0)); }

    let mut incoming = BTreeMap::from([(program.entry, Facts::default())]);
    for id in order {
        let b = blocks[&id];
        let mut f = incoming.remove(&id).ok_or_else(|| err("E_PROTOCOL_CFG_UNREACHABLE", id, 0))?;
        let mut outcome: Option<(LeaseId, PlaceId, bool)> = None;
        for (i, op) in b.ops.iter().enumerate() {
            match op {
                Op::Init { place, protocol } => {
                    let p = protocols.get(protocol.as_str()).ok_or_else(|| err("E_PROTOCOL_UNKNOWN", id, i))?;
                    target(&f, *place, id, i)?;
                    f.owners.insert(*place, Owner {
                        protocol: protocol.clone(), states: BTreeSet::from([p.initial.clone()]),
                        maybe_absent: false,
                    });
                }
                Op::Take { from, into } => {
                    if from == into { return Err(err("E_PROTOCOL_ALIAS_TAKE", id, i)); }
                    let a = live(&f, *from, id, i)?.clone();
                    if loan_on(&f, *from) { return Err(err("E_PROTOCOL_LOAN_CONFLICT", id, i)); }
                    target(&f, *into, id, i)?;
                    f.owners.insert(*into, a.clone());
                    f.owners.insert(*from, a.moved());
                }
                Op::Copy { from, .. } => {
                    live(&f, *from, id, i)?;
                    return Err(err("E_PROTOCOL_AFFINE_COPY", id, i));
                }
                Op::Borrow { place, loan, kind } => {
                    live(&f, *place, id, i)?;
                    if f.loans.values().any(|(p, k)| p == place
                        && (*kind == LoanKind::Exclusive || *k == LoanKind::Exclusive)) {
                        return Err(err("E_PROTOCOL_LOAN_CONFLICT", id, i));
                    }
                    f.loans.insert(*loan, (*place, *kind));
                }
                Op::EndBorrow { loan } => {
                    if f.loans.remove(loan).is_none() { return Err(err("E_PROTOCOL_UNKNOWN_LOAN", id, i)); }
                }
                Op::Begin { from, lease, message, payload, mode, response } => {
                    let a = live(&f, *from, id, i)?.clone();
                    if loan_on(&f, *from) { return Err(err("E_PROTOCOL_LOAN_CONFLICT", id, i)); }
                    let proto = protocols[a.protocol.as_str()];
                    let mut next = BTreeSet::new();
                    for state in &a.states {
                        let t = proto.transitions.iter().find(|t| &t.from == state && &t.message == message)
                            .ok_or_else(|| err("E_PROTOCOL_ILLEGAL_MESSAGE_STATE", id, i))?;
                        if t.mode != *mode { return Err(err("E_PROTOCOL_RESPONSE_MODE", id, i)); }
                        if &t.response != response { return Err(err("E_PROTOCOL_RESPONSE_TYPE", id, i)); }
                        if &t.payload != payload { return Err(err("E_PROTOCOL_MESSAGE_PAYLOAD", id, i)); }
                        next.insert(t.to.clone());
                    }
                    if f.leases.contains_key(lease) { return Err(err("E_PROTOCOL_LEASE_ID", id, i)); }
                    f.leases.insert(*lease, Lease { protocol: a.protocol.clone(), next, mode: *mode });
                    f.owners.insert(*from, a.moved());
                }
                Op::MoveLease { from, into } => {
                    if from == into || f.leases.contains_key(into) {
                        return Err(err("E_PROTOCOL_LEASE_ID", id, i));
                    }
                    let l = f.leases.remove(from).ok_or_else(|| err("E_PROTOCOL_LEASE_NOT_LIVE", id, i))?;
                    f.leases.insert(*into, l);
                }
                Op::CancelLease { lease } => {
                    if f.leases.remove(lease).is_none() {
                        return Err(err("E_PROTOCOL_LEASE_NOT_LIVE", id, i));
                    }
                }
                Op::AwaitUnary { lease, into } | Op::AwaitStream { lease, into } => {
                    if !program.suspending { return Err(err("E_PROTOCOL_AWAIT_CONTEXT", id, i)); }
                    no_loans(&f, id, i)?;
                    let l = f.leases.get(lease).ok_or_else(|| err("E_PROTOCOL_LEASE_NOT_LIVE", id, i))?;
                    let expected = if matches!(op, Op::AwaitUnary { .. }) { Mode::Unary } else { Mode::Stream };
                    if l.mode != expected { return Err(err("E_PROTOCOL_RESPONSE_MODE", id, i)); }
                    target(&f, *into, id, i)?;
                    outcome = Some((*lease, *into, expected == Mode::Stream));
                }
                Op::Suspend => {
                    if !program.suspending { return Err(err("E_PROTOCOL_AWAIT_CONTEXT", id, i)); }
                    no_loans(&f, id, i)?;
                }
                Op::ReturnHandle { place } => {
                    let owner = live(&f, *place, id, i)?.clone();
                    if loan_on(&f, *place) { return Err(err("E_PROTOCOL_LOAN_CONFLICT", id, i)); }
                    if f.returned_handles != 0 {
                        return Err(err("E_PROTOCOL_MULTIPLE_RETURN_HANDLES", id, i));
                    }
                    f.owners.insert(*place, owner.moved());
                    f.returned_handles += 1;
                }
                Op::DisposeTerminal { place } => {
                    let owner = live(&f, *place, id, i)?.clone();
                    let p = protocols[owner.protocol.as_str()];
                    if loan_on(&f, *place) { return Err(err("E_PROTOCOL_LOAN_CONFLICT", id, i)); }
                    if !owner.states.is_subset(&p.terminal) {
                        return Err(err("E_PROTOCOL_NONTERMINAL_DISPOSE", id, i));
                    }
                    f.owners.insert(*place, owner.moved());
                }
                Op::Return => {
                    if !f.loans.is_empty() { return Err(err("E_PROTOCOL_LOAN_ESCAPE", id, i)); }
                    if !f.leases.is_empty() { return Err(err("E_PROTOCOL_LEASE_ESCAPE", id, i)); }
                    if f.owners.values().any(|o| !o.states.is_empty()) {
                        return Err(err("E_PROTOCOL_HANDLE_ESCAPE", id, i));
                    }
                }
            }
        }
        for (edge, next) in b.successors.iter().enumerate() {
            let mut next_f = f.clone();
            if let Some((lease, into, stream)) = outcome {
                let l = next_f.leases.get(&lease).expect("validated in block").clone();
                let item = stream && edge == 0;
                let complete = if stream { edge == 1 } else { edge == 0 };
                if !item { next_f.leases.remove(&lease); }
                if complete {
                    next_f.owners.insert(into, Owner {
                        protocol: l.protocol, states: l.next, maybe_absent: false,
                    });
                }
            }
            if let Some(previous) = incoming.remove(next) {
                incoming.insert(*next, join(previous, &next_f, *next)?);
            } else {
                incoming.insert(*next, next_f);
            }
        }
    }
    Ok(Proof { blocks: blocks.len(), operations })
}
