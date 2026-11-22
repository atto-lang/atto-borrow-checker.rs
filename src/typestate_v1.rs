//! Restricted, bounded typestate oracle for AttoLang-owned resources.
//!
//! A frontend must derive nominal protocols, ownership roots, complete operations,
//! mutability and CFG edges from *typed* source/MIR. This module checks the
//! submitted graph; it cannot authenticate source or emitted guest instructions.
//! V1 rejects cycles, implicit/exceptional exits, and divergent live loans.
//! Successful model verification is NOT backend or deterministic-cleanup proof.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type PlaceId = u32;
pub type ProtocolId = u16;
pub type StateId = u16;
pub type LoanId = u32;
pub type BlockId = u32;

const MAX_PROTOCOLS: usize = 64;
const MAX_STATES: usize = 128;
const MAX_METHODS: usize = 256;
const MAX_PLACES: usize = 64;
const MAX_LOANS: usize = 1024;
const MAX_BLOCKS: usize = 4096;
const MAX_EDGES: usize = 16_384;
const MAX_OPS_PER_BLOCK: usize = 1024;
const MAX_OPS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cleanup {
    /// No live external resource is held in this state (e.g. Closed).
    Inert,
    /// A *separately verified* destructor releases this state on all exits.
    VerifiedDestructor,
    /// Caller must transition before dropping or returning (e.g. Active txn).
    ExplicitTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Exclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub id: StateId,
    pub name: String,
    pub cleanup: Cleanup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Method {
    pub name: String,
    /// Every possible state must be allowed, not merely one branch's state.
    pub from: Vec<StateId>,
    /// None means a state-preserving operation; Some changes typestate.
    pub to: Option<StateId>,
    pub access: Access,
    /// Derived from an authenticated suspension effect on the resolved callable.
    pub suspends: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Protocol {
    pub id: ProtocolId,
    pub name: String,
    pub states: Vec<State>,
    pub methods: Vec<Method>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BorrowKind {
    Shared,
    Mutable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Op {
    /// A typed constructor/reinitialization, never a dynamic unchecked cast.
    Init { place: PlaceId, protocol: ProtocolId, state: StateId },
    /// An operation on the owner itself (the adapter must prove receiver rights).
    /// Read-only receiver access; cannot execute state-changing methods.
    Call { place: PlaceId, method: String },
    /// A separately typechecked exclusive `mut` owning receiver.
    CallMut { place: PlaceId, method: String },
    /// An operation through the exact checked loan.
    CallThrough { loan: LoanId, method: String },
    /// Awaited, state-preserving read from a suspension-marked method.
    AwaitCall { place: PlaceId, method: String },
    /// Awaited, state-preserving exclusive operation; no in-flight state changes.
    AwaitCallMut { place: PlaceId, method: String },
    /// Suspension unrelated to a resource operation; resource owner stays live.
    Suspend,
    Borrow { place: PlaceId, loan: LoanId, kind: BorrowKind },
    EndBorrow { loan: LoanId },
    /// Consuming `take!` transfers typestate to a *distinct* place.
    Take { from: PlaceId, into: PlaceId },
    /// `drop!` / explicit cleanup. Cannot discard required-transition states.
    Drop { place: PlaceId },
    /// All scope/exception/cancellation exits must be represented independently.
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
    /// Authenticated callable suspension effect, not inferred from an await op.
    pub suspending: bool,
    pub protocols: Vec<Protocol>,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub block: BlockId,
    pub operation: usize,
}

fn err(code: &'static str, block: BlockId, operation: usize) -> Diagnostic {
    Diagnostic { code, block, operation }
}

/// None in a state set means the place might be uninitialized, moved or dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Fact {
    protocol: ProtocolId,
    states: BTreeSet<Option<StateId>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Loan {
    place: PlaceId,
    kind: BorrowKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Facts {
    places: BTreeMap<PlaceId, Fact>,
    loans: BTreeMap<LoanId, Loan>,
}

/// A proof over the exact submitted *acyclic* operation graph only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub verified_blocks: usize,
    pub verified_operations: usize,
}

fn checked_protocols(protocols: &[Protocol]) -> Result<BTreeMap<ProtocolId, &Protocol>, Diagnostic> {
    if protocols.is_empty() || protocols.len() > MAX_PROTOCOLS {
        return Err(err("E_TYPESTATE_PROTOCOL_BUDGET", 0, 0));
    }
    let mut by_id = BTreeMap::new();
    for protocol in protocols {
        if protocol.name.is_empty() || by_id.insert(protocol.id, protocol).is_some()
            || protocol.states.is_empty() || protocol.states.len() > MAX_STATES
            || protocol.methods.len() > MAX_METHODS
        {
            return Err(err("E_TYPESTATE_INVALID_PROTOCOL", 0, 0));
        }
        let mut states = BTreeSet::new();
        let mut names = BTreeSet::new();
        for state in &protocol.states {
            if state.name.is_empty() || !states.insert(state.id) || !names.insert(&state.name) {
                return Err(err("E_TYPESTATE_INVALID_PROTOCOL", 0, 0));
            }
        }
        let mut methods = BTreeSet::new();
        for method in &protocol.methods {
            if method.name.is_empty() || !methods.insert(&method.name) || method.from.is_empty()
                || method.from.len() > MAX_STATES || method.from.iter().any(|s| !states.contains(s))
                || method.to.is_some_and(|s| !states.contains(&s))
                || (method.to.is_some() && method.access != Access::Exclusive)
            {
                return Err(err("E_TYPESTATE_INVALID_PROTOCOL", 0, 0));
            }
            if method.from.iter().collect::<BTreeSet<_>>().len() != method.from.len() {
                return Err(err("E_TYPESTATE_INVALID_PROTOCOL", 0, 0));
            }
        }
    }
    Ok(by_id)
}

fn graph(program: &Program) -> Result<(BTreeMap<BlockId, &Block>, Vec<BlockId>, usize), Diagnostic> {
    if program.blocks.is_empty() || program.blocks.len() > MAX_BLOCKS {
        return Err(err("E_TYPESTATE_CFG_BUDGET", 0, 0));
    }
    let mut blocks = BTreeMap::new();
    let mut edges = 0usize;
    let mut total = 0usize;
    let mut issued_loans = BTreeSet::new();
    for block in &program.blocks {
        edges = edges.saturating_add(block.successors.len());
        total = total.saturating_add(block.ops.len());
        if edges > MAX_EDGES || total > MAX_OPS || block.ops.len() > MAX_OPS_PER_BLOCK {
            return Err(err("E_TYPESTATE_CFG_BUDGET", block.id, 0));
        }
        if blocks.insert(block.id, block).is_some() {
            return Err(err("E_TYPESTATE_INVALID_CFG", block.id, 0));
        }
        if block.successors.is_empty() {
            if !matches!(block.ops.last(), Some(Op::Return)) {
                return Err(err("E_TYPESTATE_IMPLICIT_EXIT", block.id, block.ops.len()));
            }
        } else if block.ops.iter().any(|op| matches!(op, Op::Return)) {
            return Err(err("E_TYPESTATE_INVALID_CFG", block.id, 0));
        }
        for (i, op) in block.ops.iter().enumerate() {
            if i + 1 != block.ops.len() && matches!(op, Op::Return) {
                return Err(err("E_TYPESTATE_INVALID_CFG", block.id, i));
            }
            if let Op::Borrow { loan, .. } = op {
                if !issued_loans.insert(*loan) || issued_loans.len() > MAX_LOANS {
                    return Err(err("E_TYPESTATE_LOAN_ID", block.id, i));
                }
            }
        }
    }
    if !blocks.contains_key(&program.entry) {
        return Err(err("E_TYPESTATE_INVALID_CFG", program.entry, 0));
    }
    let mut degree: BTreeMap<_, usize> = blocks.keys().map(|id| (*id, 0)).collect();
    for block in blocks.values() {
        let mut targets = BTreeSet::new();
        for target in &block.successors {
            if !targets.insert(*target) || !degree.contains_key(target) {
                return Err(err("E_TYPESTATE_INVALID_CFG", block.id, 0));
            }
            *degree.get_mut(target).expect("checked target") += 1;
        }
    }
    // Require every supplied block to be reachable. A dead block cannot conceal
    // unverified resource effects from the compiler's operation census.
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::from([program.entry]);
    while let Some(id) = queue.pop_front() {
        if reachable.insert(id) {
            queue.extend(blocks[&id].successors.iter().copied());
        }
    }
    if reachable.len() != blocks.len() {
        return Err(err("E_TYPESTATE_UNREACHABLE_BLOCK", program.entry, 0));
    }
    let mut ready: VecDeque<_> = degree.iter().filter(|(_, n)| **n == 0).map(|(id, _)| *id).collect();
    let mut order = Vec::with_capacity(blocks.len());
    while let Some(id) = ready.pop_front() {
        order.push(id);
        for target in &blocks[&id].successors {
            let n = degree.get_mut(target).expect("checked edge");
            *n -= 1;
            if *n == 0 { ready.push_back(*target); }
        }
    }
    if order.len() != blocks.len() {
        return Err(err("E_TYPESTATE_CFG_CYCLE", program.entry, 0));
    }
    Ok((blocks, order, total))
}

fn join(into: &mut Facts, rhs: &Facts, block: BlockId) -> Result<(), Diagnostic> {
    // Divergent live loan provenance cannot be silently merged.
    if into.loans != rhs.loans {
        return Err(err("E_TYPESTATE_LOAN_JOIN", block, 0));
    }
    let ids: BTreeSet<_> = into.places.keys().chain(rhs.places.keys()).copied().collect();
    for id in ids {
        match (into.places.get_mut(&id), rhs.places.get(&id)) {
            (Some(lhs), Some(rhs)) => {
                if lhs.protocol != rhs.protocol {
                    return Err(err("E_TYPESTATE_PROTOCOL_JOIN", block, 0));
                }
                lhs.states.extend(rhs.states.iter().copied());
            }
            (Some(lhs), None) => { lhs.states.insert(None); }
            (None, Some(rhs)) => {
                let mut fact = rhs.clone();
                fact.states.insert(None);
                into.places.insert(id, fact);
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn live<'a>(facts: &'a Facts, place: PlaceId, block: BlockId, i: usize) -> Result<&'a Fact, Diagnostic> {
    let fact = facts.places.get(&place).ok_or_else(|| err("E_TYPESTATE_NOT_LIVE", block, i))?;
    if fact.states.contains(&None) || fact.states.is_empty() {
        return Err(err("E_TYPESTATE_NOT_LIVE", block, i));
    }
    Ok(fact)
}

fn can_release(fact: &Fact, protocol: &Protocol) -> bool {
    fact.states.iter().flatten().all(|id| {
        protocol.states.iter().find(|s| s.id == *id)
            .is_some_and(|s| s.cleanup != Cleanup::ExplicitTransition)
    })
}

fn apply_method(facts: &mut Facts, protocols: &BTreeMap<ProtocolId, &Protocol>,
    place: PlaceId, method_name: &str, through: Option<BorrowKind>,
    receiver: Access, awaited: bool, block: BlockId, i: usize) -> Result<(), Diagnostic> {
    let fact = live(facts, place, block, i)?;
    let protocol = protocols[&fact.protocol];
    let method = protocol.methods.iter().find(|m| m.name == method_name)
        .ok_or_else(|| err("E_TYPESTATE_UNKNOWN_METHOD", block, i))?;
    if method.suspends && !awaited {
        return Err(err("E_TYPESTATE_AWAIT_REQUIRED", block, i));
    }
    if !method.suspends && awaited {
        return Err(err("E_TYPESTATE_NOT_SUSPENDING", block, i));
    }
    // Awaited state-changing calls need an explicit escrow and outcome CFG.
    // V1 must not pretend that a fallible or cancelled close has succeeded.
    if awaited && method.to.is_some() {
        return Err(err("E_TYPESTATE_ASYNC_TRANSITION_UNSUPPORTED", block, i));
    }
    if awaited && !facts.loans.is_empty() {
        return Err(err("E_TYPESTATE_SUSPEND_LOAN", block, i));
    }
    if fact.states.iter().flatten().any(|s| !method.from.contains(s)) {
        return Err(err("E_TYPESTATE_ILLEGAL_OPERATION", block, i));
    }
    if method.access == Access::Exclusive && receiver != Access::Exclusive {
        return Err(err("E_TYPESTATE_MUT_BORROW_REQUIRED", block, i));
    }
    let loans: Vec<_> = facts.loans.values().filter(|loan| loan.place == place).collect();
    if through.is_none() && (receiver == Access::Exclusive && !loans.is_empty()
        || receiver == Access::Read && loans.iter().any(|loan| loan.kind == BorrowKind::Mutable)) {
        return Err(err("E_TYPESTATE_LOAN_CONFLICT", block, i));
    }
    if let Some(to) = method.to {
        let f = facts.places.get_mut(&place).expect("checked live owner");
        f.states.clear();
        f.states.insert(Some(to));
    }
    Ok(())
}

/// Verify only the closed, typed, complete acyclic CFG supplied by a compiler.
/// Source and backend effect completeness remain external proof obligations.
pub fn verify(program: &Program) -> Result<Proof, Diagnostic> {
    let protocols = checked_protocols(&program.protocols)?;
    let (blocks, order, total) = graph(program)?;
    let mut incoming: BTreeMap<BlockId, Facts> = BTreeMap::new();
    incoming.insert(program.entry, Facts::default());
    for id in order {
        let block = blocks[&id];
        let mut facts = incoming.remove(&id).ok_or_else(|| err("E_TYPESTATE_INVALID_CFG", id, 0))?;
        for (i, op) in block.ops.iter().enumerate() {
            match op {
                Op::Init { place, protocol, state } => {
                    let proto = protocols.get(protocol).ok_or_else(|| err("E_TYPESTATE_UNKNOWN_PROTOCOL", id, i))?;
                    if !proto.states.iter().any(|s| s.id == *state) {
                        return Err(err("E_TYPESTATE_UNKNOWN_STATE", id, i));
                    }
                    if let Some(old) = facts.places.get(place) {
                        if old.protocol != *protocol || old.states != BTreeSet::from([None]) {
                            return Err(err("E_TYPESTATE_DOUBLE_INIT", id, i));
                        }
                    }
                    facts.places.insert(*place, Fact { protocol: *protocol, states: BTreeSet::from([Some(*state)]) });
                    if facts.places.len() > MAX_PLACES {
                        return Err(err("E_TYPESTATE_PLACE_BUDGET", id, i));
                    }
                }
                Op::Call { place, method } => {
                    apply_method(&mut facts, &protocols, *place, method, None, Access::Read, false, id, i)?;
                }
                Op::CallMut { place, method } => {
                    apply_method(&mut facts, &protocols, *place, method, None, Access::Exclusive, false, id, i)?;
                }
                Op::CallThrough { loan, method } => {
                    let source = *facts.loans.get(loan).ok_or_else(|| err("E_TYPESTATE_UNKNOWN_LOAN", id, i))?;
                    let mode = if source.kind == BorrowKind::Mutable { Access::Exclusive } else { Access::Read };
                    apply_method(&mut facts, &protocols, source.place, method, Some(source.kind), mode, false, id, i)?;
                }
                Op::AwaitCall { place, method } | Op::AwaitCallMut { place, method } => {
                    if !program.suspending {
                        return Err(err("E_TYPESTATE_AWAIT_CONTEXT", id, i));
                    }
                    // V1 cannot infer pinned, cancellation-safe loan lifetimes.
                    if !facts.loans.is_empty() {
                        return Err(err("E_TYPESTATE_SUSPEND_LOAN", id, i));
                    }
                    let mode = if matches!(op, Op::AwaitCallMut { .. }) {
                        Access::Exclusive
                    } else {
                        Access::Read
                    };
                    apply_method(&mut facts, &protocols, *place, method, None, mode, true, id, i)?;
                }
                Op::Suspend => {
                    if !program.suspending {
                        return Err(err("E_TYPESTATE_AWAIT_CONTEXT", id, i));
                    }
                    if !facts.loans.is_empty() {
                        return Err(err("E_TYPESTATE_SUSPEND_LOAN", id, i));
                    }
                }
                Op::Borrow { place, loan, kind } => {
                    live(&facts, *place, id, i)?;
                    if facts.loans.values().any(|l| l.place == *place &&
                        (*kind == BorrowKind::Mutable || l.kind == BorrowKind::Mutable)) {
                        return Err(err("E_TYPESTATE_LOAN_CONFLICT", id, i));
                    }
                    facts.loans.insert(*loan, Loan { place: *place, kind: *kind });
                }
                Op::EndBorrow { loan } => {
                    if facts.loans.remove(loan).is_none() {
                        return Err(err("E_TYPESTATE_UNKNOWN_LOAN", id, i));
                    }
                }
                Op::Take { from, into } => {
                    if from == into { return Err(err("E_TYPESTATE_ALIAS_TRANSFER", id, i)); }
                    let source = live(&facts, *from, id, i)?.clone();
                    if facts.loans.values().any(|l| l.place == *from) {
                        return Err(err("E_TYPESTATE_LOAN_CONFLICT", id, i));
                    }
                    if let Some(target) = facts.places.get(into) {
                        if target.protocol != source.protocol || target.states != BTreeSet::from([None]) {
                            return Err(err("E_TYPESTATE_TARGET_LIVE", id, i));
                        }
                    }
                    facts.places.insert(*into, source);
                    facts.places.get_mut(from).expect("checked source").states = BTreeSet::from([None]);
                    if facts.places.len() > MAX_PLACES {
                        return Err(err("E_TYPESTATE_PLACE_BUDGET", id, i));
                    }
                }
                Op::Drop { place } => {
                    let fact = live(&facts, *place, id, i)?;
                    if facts.loans.values().any(|loan| loan.place == *place) {
                        return Err(err("E_TYPESTATE_LOAN_CONFLICT", id, i));
                    }
                    if !can_release(fact, protocols[&fact.protocol]) {
                        return Err(err("E_TYPESTATE_INCOMPLETE", id, i));
                    }
                    facts.places.get_mut(place).expect("checked drop").states = BTreeSet::from([None]);
                }
                Op::Return => {
                    if !facts.loans.is_empty() { return Err(err("E_TYPESTATE_LOAN_ESCAPE", id, i)); }
                    if facts.places.values().any(|f| !can_release(f, protocols[&f.protocol])) {
                        return Err(err("E_TYPESTATE_INCOMPLETE", id, i));
                    }
                }
            }
        }
        for target in &block.successors {
            if let Some(existing) = incoming.get_mut(target) {
                join(existing, &facts, *target)?;
            } else {
                incoming.insert(*target, facts.clone());
            }
        }
    }
    Ok(Proof { verified_blocks: blocks.len(), verified_operations: total })
}
