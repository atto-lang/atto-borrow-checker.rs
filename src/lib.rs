//! Conservative, backend-neutral ownership oracle.
//!
//! This is a deliberately bounded v0 checker, not a complete AttoLang borrow
//! checker or proof of backend emission. Unknown constructs must be rejected
//! by adapters before constructing this IR.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_BLOCKS: usize = 1024;
const MAX_ROOTS: usize = 2048;
const MAX_OPS: usize = 100_000;
const MAX_LOANS: usize = 4096;
const MAX_PATH: usize = 16;
const MAX_ITERATIONS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Place {
    pub root: u32,
    pub fields: Vec<u32>,
}

impl Place {
    pub fn root(root: u32) -> Self {
        Self { root, fields: Vec::new() }
    }

    pub fn field(mut self, field: u32) -> Self {
        self.fields.push(field);
        self
    }

    fn is_prefix_of(&self, other: &Self) -> bool {
        self.root == other.root && other.fields.starts_with(&self.fields)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.is_prefix_of(other) || other.is_prefix_of(self)
    }
}

/// Trusted type/effect facts must come from independently checked typed IR.
/// The oracle cannot authenticate a frontend that lies about these facts.
#[derive(Clone, Debug)]
pub struct Root {
    pub id: u32,
    pub is_copy: bool,
    pub is_transferable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoanKind {
    Shared,
    Exclusive,
}

#[derive(Clone, Debug)]
pub enum Op {
    Read(Place),
    Write(Place),
    Move(Place),
    Copy(Place),
    Drop(Place),
    Reinitialize(Place),
    Borrow { loan: u32, place: Place, kind: LoanKind },
    UseLoan(u32),
    EndLoan(u32),
    /// Whole-root handoff. This invalidates the sender's root.
    Transfer(Place),
    /// Await, select or any other suspension boundary.
    Suspend,
    Nop,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub id: u32,
    pub ops: Vec<Op>,
    pub successors: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct Program {
    pub roots: Vec<Root>,
    pub blocks: Vec<Block>,
    pub entry: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Code {
    InvalidIr,
    ResourceLimit,
    UseAfterMove,
    LoanConflict,
    LoanNotLive,
    LoanEscape,
    NotCopy,
    NotTransferable,
    ReinitializeNotProven,
    UnsupportedSuspension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckError {
    pub code: Code,
    pub block: u32,
    pub operation: usize,
    pub message: &'static str,
}

fn failure(code: Code, block: u32, operation: usize, message: &'static str) -> CheckError {
    CheckError { code, block, operation, message }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct State {
    // MAY sets are unions at joins; MUST sets are intersections.
    maybe_moved: BTreeSet<Place>,
    definitely_moved: BTreeSet<Place>,
    maybe_loans: BTreeMap<u32, (Place, LoanKind)>,
    definitely_loans: BTreeSet<u32>,
}

impl State {
    fn moved_overlap(&self, place: &Place) -> bool {
        self.maybe_moved.iter().any(|p| p.overlaps(place))
    }

    fn loan_overlap(&self, place: &Place) -> bool {
        self.maybe_loans.values().any(|(p, _)| p.overlaps(place))
    }

    fn exclusive_overlap(&self, place: &Place) -> bool {
        self.maybe_loans.values().any(|(p, kind)| {
            *kind == LoanKind::Exclusive && p.overlaps(place)
        })
    }

    fn mark_moved(&mut self, place: Place) {
        self.maybe_moved.insert(place.clone());
        self.definitely_moved.insert(place);
    }

    fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.maybe_moved.extend(other.maybe_moved.iter().cloned());
        self.definitely_moved.retain(|p| other.definitely_moved.contains(p));
        for (id, loan) in &other.maybe_loans {
            // Global LoanId uniqueness is checked before dataflow.
            self.maybe_loans.entry(*id).or_insert_with(|| loan.clone());
        }
        self.definitely_loans.retain(|id| other.definitely_loans.contains(id));
        *self != before
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub reachable_blocks: usize,
    pub validated_operations: usize,
    pub dataflow_iterations: usize,
}

fn place_of(op: &Op) -> Option<&Place> {
    match op {
        Op::Read(p) | Op::Write(p) | Op::Move(p) | Op::Copy(p)
        | Op::Drop(p) | Op::Reinitialize(p) | Op::Transfer(p)
        | Op::Borrow { place: p, .. } => Some(p),
        _ => None,
    }
}

fn validate(program: &Program) -> Result<(BTreeMap<u32, &Root>, BTreeMap<u32, &Block>, usize), CheckError> {
    if program.blocks.is_empty() || program.blocks.len() > MAX_BLOCKS
        || program.roots.len() > MAX_ROOTS
    {
        return Err(failure(Code::ResourceLimit, program.entry, 0, "invalid block/root count"));
    }
    let mut roots = BTreeMap::new();
    for root in &program.roots {
        if roots.insert(root.id, root).is_some() {
            return Err(failure(Code::InvalidIr, program.entry, 0, "duplicate root id"));
        }
    }
    let mut blocks = BTreeMap::new();
    for block in &program.blocks {
        if blocks.insert(block.id, block).is_some() {
            return Err(failure(Code::InvalidIr, block.id, 0, "duplicate block id"));
        }
    }
    if !blocks.contains_key(&program.entry) {
        return Err(failure(Code::InvalidIr, program.entry, 0, "missing entry block"));
    }
    let mut operations = 0usize;
    let mut loans = BTreeSet::new();
    for block in &program.blocks {
        operations = operations.saturating_add(block.ops.len());
        if operations > MAX_OPS {
            return Err(failure(Code::ResourceLimit, block.id, 0, "too many operations"));
        }
        for &successor in &block.successors {
            if !blocks.contains_key(&successor) {
                return Err(failure(Code::InvalidIr, block.id, 0, "missing successor block"));
            }
        }
        for (index, op) in block.ops.iter().enumerate() {
            if let Some(place) = place_of(op) {
                if !roots.contains_key(&place.root) || place.fields.len() > MAX_PATH {
                    return Err(failure(Code::InvalidIr, block.id, index, "unknown root or excessive projection"));
                }
            }
            if let Op::Borrow { loan, .. } = op {
                if !loans.insert(*loan) {
                    return Err(failure(Code::InvalidIr, block.id, index, "duplicate LoanId definition"));
                }
                if loans.len() > MAX_LOANS {
                    return Err(failure(Code::ResourceLimit, block.id, index, "too many loans"));
                }
            }
        }
    }
    // No unvalidated orphan blocks or unknown edges are allowed in v0.
    let mut reached = BTreeSet::from([program.entry]);
    let mut queue = VecDeque::from([program.entry]);
    while let Some(id) = queue.pop_front() {
        for &next in &blocks[&id].successors {
            if reached.insert(next) {
                queue.push_back(next);
            }
        }
    }
    if reached.len() != blocks.len() {
        return Err(failure(Code::InvalidIr, program.entry, 0, "unreachable block in submitted IR"));
    }
    Ok((roots, blocks, operations))
}

fn apply(op: &Op, state: &mut State, roots: &BTreeMap<u32, &Root>, block: u32, index: usize) -> Result<(), CheckError> {
    let error = |code, message| failure(code, block, index, message);
    match op {
        Op::Nop => {}
        Op::Read(p) => {
            if state.moved_overlap(p) {
                return Err(error(Code::UseAfterMove, "read of possibly moved place"));
            }
            if state.exclusive_overlap(p) {
                return Err(error(Code::LoanConflict, "owner read overlaps exclusive loan"));
            }
        }
        Op::Copy(p) => {
            if !roots[&p.root].is_copy {
                return Err(error(Code::NotCopy, "type lacks verified Copy property"));
            }
            if state.moved_overlap(p) {
                return Err(error(Code::UseAfterMove, "copy of possibly moved place"));
            }
            if state.exclusive_overlap(p) {
                return Err(error(Code::LoanConflict, "copy overlaps exclusive loan"));
            }
        }
        Op::Write(p) => {
            if state.moved_overlap(p) {
                return Err(error(Code::UseAfterMove, "write requires owned initialized place; use checked reinitialization"));
            }
            if state.loan_overlap(p) {
                return Err(error(Code::LoanConflict, "write overlaps an active loan"));
            }
        }
        Op::Reinitialize(p) => {
            if !state.definitely_moved.contains(p)
                || state.maybe_moved.iter().any(|m| m != p && m.is_prefix_of(p))
            {
                return Err(error(Code::ReinitializeNotProven, "exact place not definitely moved on all incoming paths"));
            }
            if state.loan_overlap(p) {
                return Err(error(Code::LoanConflict, "reinitialization overlaps a loan"));
            }
            state.maybe_moved.retain(|m| !p.overlaps(m));
            state.definitely_moved.retain(|m| !p.overlaps(m));
        }
        Op::Move(p) | Op::Drop(p) | Op::Transfer(p) => {
            if let Op::Transfer(_) = op {
                if !p.fields.is_empty() || !roots[&p.root].is_transferable {
                    return Err(error(Code::NotTransferable, "transfer needs a verified transferable whole root"));
                }
            }
            if state.moved_overlap(p) {
                return Err(error(Code::UseAfterMove, "consume of possibly moved place"));
            }
            if state.loan_overlap(p) {
                return Err(error(Code::LoanConflict, "consume overlaps an active loan"));
            }
            state.mark_moved(p.clone());
        }
        Op::Borrow { loan, place, kind } => {
            if state.moved_overlap(place) {
                return Err(error(Code::UseAfterMove, "borrow of possibly moved place"));
            }
            if state.maybe_loans.contains_key(loan) {
                return Err(error(Code::LoanConflict, "LoanId already active"));
            }
            let conflicts = match kind {
                LoanKind::Exclusive => state.loan_overlap(place),
                LoanKind::Shared => state.exclusive_overlap(place),
            };
            if conflicts {
                return Err(error(Code::LoanConflict, "incompatible overlapping borrows"));
            }
            state.maybe_loans.insert(*loan, (place.clone(), *kind));
            state.definitely_loans.insert(*loan);
        }
        Op::UseLoan(loan) | Op::EndLoan(loan) => {
            if !state.definitely_loans.contains(loan) {
                return Err(error(Code::LoanNotLive, "loan not live on every incoming path"));
            }
            if let Op::EndLoan(_) = op {
                state.definitely_loans.remove(loan);
                state.maybe_loans.remove(loan);
            }
        }
        Op::Suspend => {
            // Future refinement: authenticated pinned-frame loans with explicit
            // suspension-safe lifetime/effect proof.
            if !state.maybe_loans.is_empty() {
                return Err(error(Code::UnsupportedSuspension, "loan crosses suspension without pinned-frame proof"));
            }
        }
    }
    Ok(())
}

/// Returns success only for this deliberately restricted IR subset.
/// Backends must map all emitted ownership-relevant effects into the IR.
pub fn check(program: &Program) -> Result<Report, CheckError> {
    let (roots, blocks, operations) = validate(program)?;
    let mut entry_states = BTreeMap::new();
    entry_states.insert(program.entry, State::default());
    let mut queue = VecDeque::from([program.entry]);
    let mut iterations = 0usize;
    while let Some(block_id) = queue.pop_front() {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            return Err(failure(Code::ResourceLimit, block_id, 0, "dataflow did not converge within budget"));
        }
        let block = blocks[&block_id];
        let mut state = entry_states[&block_id].clone();
        for (index, op) in block.ops.iter().enumerate() {
            apply(op, &mut state, &roots, block_id, index)?;
        }
        if block.successors.is_empty() && !state.maybe_loans.is_empty() {
            return Err(failure(Code::LoanEscape, block_id, block.ops.len(), "live loan reaches function exit"));
        }
        for &successor in &block.successors {
            match entry_states.get_mut(&successor) {
                Some(existing) => {
                    if existing.join(&state) {
                        queue.push_back(successor);
                    }
                }
                None => {
                    entry_states.insert(successor, state.clone());
                    queue.push_back(successor);
                }
            }
        }
    }
    Ok(Report { reachable_blocks: blocks.len(), validated_operations: operations, dataflow_iterations: iterations })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Place { Place::root(1) }
    fn q() -> Place { Place::root(2) }
    fn borrow(id: u32, place: Place, kind: LoanKind) -> Op { Op::Borrow { loan: id, place, kind } }
    fn program(ops: Vec<Op>) -> Program {
        Program {
            roots: vec![Root { id: 1, is_copy: true, is_transferable: true },
                        Root { id: 2, is_copy: false, is_transferable: false }],
            entry: 0,
            blocks: vec![Block { id: 0, ops, successors: vec![] }],
        }
    }
    fn rejects(program: Program, code: Code) {
        assert_eq!(check(&program).unwrap_err().code, code);
    }

    #[test]
    fn shared_readers_are_compatible() {
        check(&program(vec![borrow(10, p(), LoanKind::Shared), borrow(11, p(), LoanKind::Shared),
             Op::Read(p()), Op::EndLoan(11), Op::EndLoan(10), Op::Write(p())])).unwrap();
    }
    #[test]
    fn write_during_read_loan_rejects() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared), Op::Write(p())]), Code::LoanConflict);
    }
    #[test]
    fn exclusive_conflicts_with_shared() {
        rejects(program(vec![borrow(10, p(), LoanKind::Exclusive),
            borrow(11, p(), LoanKind::Shared)]), Code::LoanConflict);
    }
    #[test]
    fn exclusive_owner_read_rejects() {
        rejects(program(vec![borrow(10, p(), LoanKind::Exclusive), Op::Read(p())]), Code::LoanConflict);
    }
    #[test]
    fn reborrow_after_release() {
        check(&program(vec![borrow(10, p(), LoanKind::Exclusive),
            Op::UseLoan(10), Op::EndLoan(10), borrow(11, p(), LoanKind::Shared),
            Op::EndLoan(11)])).unwrap();
    }
    #[test]
    fn duplicate_id_rejects_structurally() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared),
            Op::EndLoan(10), borrow(10, p(), LoanKind::Shared)]), Code::InvalidIr);
    }
    #[test]
    fn use_after_move_rejects() {
        rejects(program(vec![Op::Move(p()), Op::Read(p())]), Code::UseAfterMove);
    }
    #[test]
    fn moved_field_does_not_block_sibling() {
        check(&program(vec![Op::Move(p().field(1)), Op::Read(p().field(2))])).unwrap();
        rejects(program(vec![Op::Move(p().field(1)), Op::Read(p())]), Code::UseAfterMove);
    }
    #[test]
    fn copy_requires_trait_evidence() {
        check(&program(vec![Op::Copy(p())])).unwrap();
        rejects(program(vec![Op::Copy(q())]), Code::NotCopy);
    }
    #[test]
    fn transfer_requires_no_loans() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared),
            Op::Transfer(p())]), Code::LoanConflict);
    }
    #[test]
    fn transfer_requires_verified_whole_root() {
        rejects(program(vec![Op::Transfer(q())]), Code::NotTransferable);
        rejects(program(vec![Op::Transfer(p().field(1))]), Code::NotTransferable);
    }
    #[test]
    fn reinitialization_requires_definite_move() {
        check(&program(vec![Op::Move(p()), Op::Reinitialize(p()), Op::Read(p())])).unwrap();
        rejects(program(vec![Op::Reinitialize(p())]), Code::ReinitializeNotProven);
    }
    #[test]
    fn suspension_with_loan_rejects() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared), Op::Suspend]), Code::UnsupportedSuspension);
        check(&program(vec![borrow(10, p(), LoanKind::Shared), Op::EndLoan(10), Op::Suspend])).unwrap();
    }
    #[test]
    fn unclosed_loan_at_exit_rejects() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared)]), Code::LoanEscape);
    }
    #[test]
    fn ended_loan_is_not_usable() {
        rejects(program(vec![borrow(10, p(), LoanKind::Shared), Op::EndLoan(10),
            Op::UseLoan(10)]), Code::LoanNotLive);
    }
    #[test]
    fn maybe_moved_on_one_branch_blocks_join_read() {
        let mut ir = program(vec![]);
        ir.blocks = vec![
            Block { id: 0, ops: vec![], successors: vec![1, 2] },
            Block { id: 1, ops: vec![Op::Move(p())], successors: vec![3] },
            Block { id: 2, ops: vec![], successors: vec![3] },
            Block { id: 3, ops: vec![Op::Read(p())], successors: vec![] },
        ];
        rejects(ir, Code::UseAfterMove);
    }
    #[test]
    fn reinit_after_branch_move_is_not_proven() {
        let mut ir = program(vec![]);
        ir.blocks = vec![
            Block { id: 0, ops: vec![], successors: vec![1, 2] },
            Block { id: 1, ops: vec![Op::Move(p())], successors: vec![3] },
            Block { id: 2, ops: vec![], successors: vec![3] },
            Block { id: 3, ops: vec![Op::Reinitialize(p())], successors: vec![] },
        ];
        rejects(ir, Code::ReinitializeNotProven);
    }
    #[test]
    fn joining_live_loan_from_one_branch_cannot_end_unconditionally() {
        let mut ir = program(vec![]);
        ir.blocks = vec![
            Block { id: 0, ops: vec![], successors: vec![1, 2] },
            Block { id: 1, ops: vec![borrow(10, p(), LoanKind::Shared)], successors: vec![3] },
            Block { id: 2, ops: vec![], successors: vec![3] },
            Block { id: 3, ops: vec![Op::EndLoan(10)], successors: vec![] },
        ];
        rejects(ir, Code::LoanNotLive);
    }
    #[test]
    fn closed_loan_loop_reaches_fixed_point() {
        let mut ir = program(vec![]);
        ir.blocks = vec![
            Block { id: 0, ops: vec![], successors: vec![1] },
            Block { id: 1, ops: vec![borrow(10, p(), LoanKind::Shared),
                Op::UseLoan(10), Op::EndLoan(10)], successors: vec![1, 2] },
            Block { id: 2, ops: vec![Op::Read(p())], successors: vec![] },
        ];
        check(&ir).unwrap();
    }
    #[test]
    fn missing_edge_rejects() {
        let mut ir = program(vec![]);
        ir.blocks[0].successors.push(99);
        rejects(ir, Code::InvalidIr);
    }
    #[test]
    fn unreachable_block_rejects() {
        let mut ir = program(vec![]);
        ir.blocks.push(Block { id: 8, ops: vec![Op::Read(p())], successors: vec![] });
        rejects(ir, Code::InvalidIr);
    }
}
