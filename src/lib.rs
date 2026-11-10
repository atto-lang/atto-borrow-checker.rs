//! Canonical AttoLang borrow checker, **restricted V0**.
//!
//! This module checks a typed ownership-event CFG. It does not parse AttoLang,
//! infer traits from syntax, verify FFI witnesses, or authorize a backend's codegen.
//! The frontend MUST derive owner identities and Copy/Send witnesses independently.
//! Loops, pin-across-suspension, exceptional exits and divergent cleanup joins are
//! conservatively rejected until a versioned full CFG model proves them.
use std::collections::{BTreeMap, BTreeSet};

pub type OwnerId = u32;
pub type LoanId = u32;
pub type BlockId = u32;

const MAX_OWNERS: usize = 64;
const MAX_LOANS: usize = 1024;
const MAX_BLOCKS: usize = 4096;
const MAX_EDGES: usize = 16384;
const MAX_OPERATIONS_PER_BLOCK: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traits {
    /// Must be established by the frontend's nominal/structural type rules.
    pub is_copy: bool,
    /// Moving into a Task requires a separate transitive Send proof.
    pub is_send: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowKind {
    Shared,
    Mutable,
}

/// All OwnerId operands denote canonical alias roots, not arbitrary field IDs.
/// A field projection must be resolved to a root unless disjointness is proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Init { owner: OwnerId, traits: Traits },
    Read { owner: OwnerId },
    Write { owner: OwnerId },
    Borrow { owner: OwnerId, loan: LoanId, kind: BorrowKind },
    WriteThrough { owner: OwnerId, loan: LoanId },
    EndBorrow { loan: LoanId },
    Move { from: OwnerId, into: OwnerId },
    Copy { from: OwnerId, into: OwnerId },
    Drop { owner: OwnerId },
    TaskCaptureCopy { owner: OwnerId },
    TaskCaptureMove { owner: OwnerId },
    Suspend,
    ActorHopBorrow { owner: OwnerId },
    Return,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    pub operations: Vec<Op>,
    pub successors: Vec<BlockId>,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub entry: BlockId,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub block: BlockId,
    pub operation: usize,
}

impl Diagnostic {
    fn at(code: &'static str, block: BlockId, operation: usize) -> Self {
        Self { code, block, operation }
    }
}

/// Exit owners appear in deterministic reverse acquisition order.
/// This is a *proposed* plan; the compiler must independently prove all
/// destruction, unwinding and runtime callback paths before emitting code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEventV0 {
    pub block: BlockId,
    pub operation: usize,
    pub kind: &'static str,
    pub owner: Option<OwnerId>,
}

fn shadow_kind(op: &Op) -> (&'static str, Option<OwnerId>) {
    match *op {
        Op::Init { owner, .. } => ("INIT", Some(owner)),
        Op::Read { owner } => ("READ", Some(owner)),
        Op::Write { owner } => ("WRITE", Some(owner)),
        Op::Borrow { owner, kind: BorrowKind::Shared, .. } => ("BORROW_SHARED", Some(owner)),
        Op::Borrow { owner, kind: BorrowKind::Mutable, .. } => ("BORROW_MUT", Some(owner)),
        Op::WriteThrough { owner, .. } => ("WRITE_VIA_MUT", Some(owner)),
        Op::EndBorrow { .. } => ("END_BORROW", None),
        Op::Move { from, .. } => ("MOVE", Some(from)),
        Op::Copy { from, .. } => ("COPY", Some(from)),
        Op::Drop { owner } => ("DROP", Some(owner)),
        Op::TaskCaptureCopy { owner } => ("TASK_COPY", Some(owner)),
        Op::TaskCaptureMove { owner } => ("TASK_MOVE", Some(owner)),
        Op::Suspend => ("SUSPEND_SAFE", None),
        Op::ActorHopBorrow { owner } => ("ACTOR_HOP_BORROW", Some(owner)),
        Op::Return => ("RETURN", None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub cleanup_by_exit: BTreeMap<BlockId, Vec<OwnerId>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Owner {
    traits: Traits,
    acquisition: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Loan {
    owner: OwnerId,
    kind: BorrowKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    live: BTreeMap<OwnerId, Owner>,
    ever_owned: BTreeSet<OwnerId>,
    loans: BTreeMap<LoanId, Loan>,
    ever_loaned: BTreeSet<LoanId>,
    next_acquisition: u64,
}

fn is_live(s: &State, owner: OwnerId) -> bool {
    s.live.contains_key(&owner)
}

fn has_any_loan(s: &State, owner: OwnerId) -> bool {
    s.loans.values().any(|loan| loan.owner == owner)
}

fn has_mut_loan(s: &State, owner: OwnerId) -> bool {
    s.loans.values().any(|loan| loan.owner == owner && loan.kind == BorrowKind::Mutable)
}

fn fresh_destination(s: &State, owner: OwnerId) -> bool {
    !s.ever_owned.contains(&owner) && s.ever_owned.len() < MAX_OWNERS
}

fn next_acquisition(s: &mut State) -> u64 {
    let result = s.next_acquisition;
    s.next_acquisition += 1; // bounded by MAX_OWNERS
    result
}

fn apply(state: &mut State, op: &Op, block: BlockId, index: usize) -> Result<(), Diagnostic> {
    let bad = |code| Diagnostic::at(code, block, index);
    match *op {
        Op::Init { owner, traits } => {
            if !fresh_destination(state, owner) {
                return Err(bad("E_OWNER_ID_REUSED_OR_BUDGET"));
            }
            let acquisition = next_acquisition(state);
            state.ever_owned.insert(owner);
            state.live.insert(owner, Owner { traits, acquisition });
        }
        Op::Read { owner } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if has_mut_loan(state, owner) { return Err(bad("E_BORROW_CONFLICT")); }
        }
        Op::Write { owner } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if has_any_loan(state, owner) { return Err(bad("E_BORROW_CONFLICT")); }
        }
        Op::Borrow { owner, loan, kind } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if state.ever_loaned.contains(&loan) { return Err(bad("E_LOAN_ID_REUSED")); }
            if state.ever_loaned.len() >= MAX_LOANS { return Err(bad("E_LOAN_BUDGET")); }
            if has_mut_loan(state, owner) || (kind == BorrowKind::Mutable && has_any_loan(state, owner)) {
                return Err(bad("E_BORROW_CONFLICT"));
            }
            state.ever_loaned.insert(loan);
            state.loans.insert(loan, Loan { owner, kind });
        }
        Op::WriteThrough { owner, loan } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if !matches!(state.loans.get(&loan), Some(Loan { owner: o, kind: BorrowKind::Mutable }) if *o == owner) {
                return Err(bad("E_MUT_LOAN_REQUIRED"));
            }
        }
        Op::EndBorrow { loan } => {
            if state.loans.remove(&loan).is_none() { return Err(bad("E_UNKNOWN_LOAN")); }
        }
        Op::Move { from, into } => {
            if !is_live(state, from) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if has_any_loan(state, from) { return Err(bad("E_BORROW_CONFLICT")); }
            if !fresh_destination(state, into) { return Err(bad("E_OWNER_ID_REUSED_OR_BUDGET")); }
            let moved = state.live.remove(&from).expect("checked live");
            state.ever_owned.insert(into);
            state.live.insert(into, moved); // preserve original acquisition order
        }
        Op::Copy { from, into } => {
            let source = state.live.get(&from).ok_or_else(|| bad("E_USE_AFTER_MOVE_OR_DROP"))?;
            if !source.traits.is_copy { return Err(bad("E_COPY_PROOF_REQUIRED")); }
            if has_mut_loan(state, from) { return Err(bad("E_BORROW_CONFLICT")); }
            if !fresh_destination(state, into) { return Err(bad("E_OWNER_ID_REUSED_OR_BUDGET")); }
            let traits = source.traits;
            let acquisition = next_acquisition(state);
            state.ever_owned.insert(into);
            state.live.insert(into, Owner { traits, acquisition });
        }
        Op::Drop { owner } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            if has_any_loan(state, owner) { return Err(bad("E_BORROW_CONFLICT")); }
            state.live.remove(&owner);
        }
        Op::TaskCaptureCopy { owner } => {
            let source = state.live.get(&owner).ok_or_else(|| bad("E_USE_AFTER_MOVE_OR_DROP"))?;
            if !source.traits.is_copy || !source.traits.is_send {
                return Err(bad("E_TASK_CAPTURE_PROOF"));
            }
            if has_mut_loan(state, owner) { return Err(bad("E_BORROW_CONFLICT")); }
        }
        Op::TaskCaptureMove { owner } => {
            let source = state.live.get(&owner).ok_or_else(|| bad("E_USE_AFTER_MOVE_OR_DROP"))?;
            if !source.traits.is_send { return Err(bad("E_TASK_CAPTURE_PROOF")); }
            if has_any_loan(state, owner) { return Err(bad("E_BORROW_CONFLICT")); }
            state.live.remove(&owner);
        }
        Op::Suspend => {
            // Pinned continuation ownership is a future separate proof profile.
            if !state.loans.is_empty() { return Err(bad("E_SUSPEND_WITH_LIVE_LOAN")); }
        }
        Op::ActorHopBorrow { owner } => {
            if !is_live(state, owner) { return Err(bad("E_USE_AFTER_MOVE_OR_DROP")); }
            return Err(bad("E_ACTOR_BORROW_ESCAPE"));
        }
        Op::Return => {
            if !state.loans.is_empty() { return Err(bad("E_LOAN_ESCAPE")); }
        }
    }
    Ok(())
}

/// Acyclic conservative V0 fixed-provenance CFG verification.
///
/// An independently validated, immutable typed compiler IR is required before
/// invoking this API. Unproven syntax or effects must fail closed in the frontend.
pub fn verify(program: &Program) -> Result<Proof, Diagnostic> {
    verify_internal(program, None)
}

/// An opt-in observation hook integrated into the canonical verification loop.
/// Observations are emitted only AFTER the current operation validates.
/// An error from the consumer aborts verification before Proof can be returned.
/// This is an operation trace, not independent source/AST provenance proof.
pub fn verify_with_shadow_v0(
    program: &Program,
    sink: &mut dyn FnMut(ShadowEventV0) -> Result<(), Diagnostic>,
) -> Result<Proof, Diagnostic> {
    verify_internal(program, Some(sink))
}

fn verify_internal(
    program: &Program,
    mut sink: Option<&mut dyn FnMut(ShadowEventV0) -> Result<(), Diagnostic>>,
) -> Result<Proof, Diagnostic> {
    let structural = |code| Diagnostic::at(code, program.entry, 0);
    if program.blocks.is_empty() || program.blocks.len() > MAX_BLOCKS {
        return Err(structural("E_CFG_BUDGET"));
    }
    let mut blocks = BTreeMap::new();
    for block in &program.blocks {
        if blocks.insert(block.id, block).is_some() {
            return Err(structural("E_CFG_DUPLICATE_BLOCK"));
        }
    }
    if !blocks.contains_key(&program.entry) {
        return Err(structural("E_CFG_ENTRY"));
    }
    let mut indegrees = BTreeMap::new();
    for &id in blocks.keys() { indegrees.insert(id, 0usize); }
    let mut edges = 0usize;
    for block in blocks.values() {
        if block.operations.len() > MAX_OPERATIONS_PER_BLOCK { return Err(structural("E_CFG_BUDGET")); }
        let mut seen = BTreeSet::new();
        for &next in &block.successors {
            if !blocks.contains_key(&next) || !seen.insert(next) {
                return Err(structural("E_CFG_EDGE"));
            }
            edges += 1;
            if edges > MAX_EDGES { return Err(structural("E_CFG_BUDGET")); }
            *indegrees.get_mut(&next).expect("validated successor") += 1;
        }
        let return_positions: Vec<_> = block.operations.iter().enumerate()
            .filter_map(|(index, op)| if matches!(op, Op::Return) { Some(index) } else { None })
            .collect();
        let returns = return_positions.first().copied();
        if block.successors.is_empty() {
            if return_positions.len() != 1 || returns != Some(block.operations.len() - 1) {
                return Err(Diagnostic::at("E_IMPLICIT_EXIT", block.id, block.operations.len()));
            }
        } else if returns.is_some() {
            return Err(Diagnostic::at("E_RETURN_WITH_SUCCESSOR", block.id, returns.unwrap_or(0)));
        }
    }
    let mut ready: BTreeSet<BlockId> = indegrees.iter()
        .filter_map(|(&id, &count)| if count == 0 { Some(id) } else { None }).collect();
    let mut ordering = Vec::new();
    while let Some(&id) = ready.iter().next() {
        ready.remove(&id);
        ordering.push(id);
        for next in &blocks[&id].successors {
            let degree = indegrees.get_mut(next).expect("validated successor");
            *degree -= 1;
            if *degree == 0 { ready.insert(*next); }
        }
    }
    if ordering.len() != blocks.len() {
        return Err(structural("E_CFG_CYCLE_UNPROVEN"));
    }
    let mut incoming = BTreeMap::<BlockId, Vec<State>>::new();
    incoming.insert(program.entry, vec![State::default()]);
    let mut cleanup_by_exit = BTreeMap::new();
    for id in ordering {
        let paths = incoming.remove(&id).ok_or_else(|| Diagnostic::at("E_CFG_UNREACHABLE", id, 0))?;
        let first = paths.first().expect("nonempty incoming");
        if paths.iter().any(|p| p != first) {
            return Err(Diagnostic::at("E_CFG_JOIN_UNPROVEN", id, 0));
        }
        let mut state = first.clone();
        let block = blocks[&id];
        for (index, op) in block.operations.iter().enumerate() {
            apply(&mut state, op, id, index)?;
            if let Some(observer) = sink.as_deref_mut() {
                let (kind, owner) = shadow_kind(op);
                observer(ShadowEventV0 { block: id, operation: index, kind, owner })?;
            }
        }
        if block.successors.is_empty() {
            let mut live: Vec<_> = state.live.iter()
                .map(|(&owner, value)| (value.acquisition, owner)).collect();
            live.sort_by(|a, b| b.cmp(a));
            cleanup_by_exit.insert(id, live.into_iter().map(|(_, owner)| owner).collect());
        }
        for &next in &block.successors {
            incoming.entry(next).or_default().push(state.clone());
        }
    }
    Ok(Proof { cleanup_by_exit })
}
