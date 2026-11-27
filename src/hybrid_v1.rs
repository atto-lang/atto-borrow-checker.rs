//! Hybrid canonical verdict for conformance: V0 first, then `cyclic_v1` when
//! V0 stops only at its restricted-CFG model limits.
//!
//! V0 (`crate::verify`) rejects every cycle and every divergent join
//! (`E_CFG_CYCLE_UNPROVEN`, `E_CFG_JOIN_UNPROVEN`). Those are conservative
//! model limits, not AttoLang rules, so for conformance they would leave all
//! ordinary branches and loops `OUT_OF_SCOPE`. This module lowers such a
//! graph onto the independently implemented MAY/MUST fixed-point model in
//! `cyclic_v1` and maps its result back to canonical V0 codes at the original
//! block and operation.
//!
//! Scope and trust boundary:
//! - Only the root-level ownership subset with an exact `cyclic_v1`
//!   counterpart is lowered: `Init`, `Read`, `Write`, `Borrow`,
//!   `WriteThrough`, `EndBorrow`, `Move`, `Copy`, `Drop`, `Suspend`,
//!   `TaskCaptureMove`, `ActorSendMove` and `Return`. Any other operation
//!   returns `None` and the caller keeps V0's model-limit verdict.
//! - An accepted hybrid graph has NO V0 cleanup plan. It is a conformance
//!   verdict about ownership safety of the submitted graph; it never
//!   authorizes code emission for a program V0 rejects.
//! - Owners start uninitialized: a synthetic entry block marks every owner
//!   the graph introduces as moved, so `Init` lowers to a checked
//!   `Reinitialize` that `cyclic_v1` only admits when the place is definitely
//!   moved on every incoming path. Re-introducing a live owner (e.g. an
//!   `Init` in a loop body without a `Drop`/`Move` before the back-edge) is an
//!   adapter defect (`E_OWNER_DEF_REUSED`).

use std::collections::{BTreeMap, BTreeSet};

use crate::cyclic_v1::{self, Code, LoanKind, Place};
use crate::{BorrowKind, Diagnostic, Op, Program};

/// The two models whose MAY/MUST loop semantics this module composes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    V0,
    CyclicV1,
}

impl Engine {
    pub fn name(self) -> &'static str {
        return match self {
            Engine::V0 => "v0",
            Engine::CyclicV1 => "cyclic_v1",
        };
    }
}

/// The V0 codes after which the hybrid consults `cyclic_v1`.
pub fn is_cfg_model_limit(code: &str) -> bool {
    return code == "E_CFG_JOIN_UNPROVEN" || code == "E_CFG_CYCLE_UNPROVEN";
}

/// Where a lowered operation came from.
#[derive(Clone, Copy, Debug)]
enum Origin {
    /// The synthetic entry block's uninitialization of an owner.
    Synthetic,
    /// Original operation index in the original block.
    Op(usize),
}

struct Lowered {
    program: cyclic_v1::Program,
    /// Per lowered block id: original op origin of each lowered op.
    origins: BTreeMap<u32, (u32, Vec<Origin>)>,
    /// Original ops by (block, index), to pick codes for failures.
    original: BTreeMap<(u32, usize), Op>,
}

/// Run the hybrid check. `None` means "not representable in cyclic_v1":
/// the caller must keep V0's verdict. `Some(Ok(()))` is an ownership-safe
/// graph without a cleanup plan; `Some(Err(d))` is a canonical rejection.
pub fn check(program: &Program) -> Option<Result<(), Diagnostic>> {
    let lowered = match lower(program)? {
        Ok(lowered) => lowered,
        Err(diagnostic) => return Some(Err(diagnostic)),
    };
    return Some(match cyclic_v1::check(&lowered.program) {
        Ok(_) => Ok(()),
        Err(error) => Err(map_error(&lowered, &error)),
    });
}

fn place(owner: u32) -> Place {
    return Place::root(owner);
}

fn lower(program: &Program) -> Option<Result<Lowered, Diagnostic>> {
    // Exit shape, which V0 also requires: every terminal block ends in
    // exactly one Return and Return never has successors or later ops.
    for block in &program.blocks {
        for (index, op) in block.operations.iter().enumerate() {
            if *op == Op::Return
                && (index + 1 != block.operations.len() || !block.successors.is_empty())
            {
                return Some(Err(diag("E_RETURN_WITH_SUCCESSOR", block.id, index)));
            }
        }
        if block.successors.is_empty() && block.operations.last() != Some(&Op::Return) {
            return Some(Err(diag(
                "E_IMPLICIT_EXIT",
                block.id,
                block.operations.len(),
            )));
        }
    }

    // Owner traits: from Init, propagated to Move/Copy destinations.
    let mut traits: BTreeMap<u32, crate::Traits> = BTreeMap::new();
    let mut introduced: BTreeSet<u32> = BTreeSet::new();
    let mut referenced: BTreeSet<u32> = BTreeSet::new();
    let mut loan_owner: BTreeMap<u32, u32> = BTreeMap::new();
    for block in &program.blocks {
        for op in &block.operations {
            match *op {
                Op::Init { owner, traits: t } => {
                    introduced.insert(owner);
                    if let Some(previous) = traits.insert(owner, t) {
                        if previous != t {
                            return None; // conflicting trait facts: not representable
                        }
                    }
                }
                Op::Move { from, into } | Op::Copy { from, into } => {
                    introduced.insert(into);
                    referenced.insert(from);
                }
                Op::Read { owner }
                | Op::Write { owner }
                | Op::Drop { owner }
                | Op::TaskCaptureMove { owner }
                | Op::ActorSendMove { owner } => {
                    referenced.insert(owner);
                }
                Op::Borrow { owner, loan, .. } => {
                    referenced.insert(owner);
                    if let Some(previous) = loan_owner.insert(loan, owner) {
                        if previous != owner {
                            return None;
                        }
                    }
                }
                Op::WriteThrough { owner, loan } => {
                    referenced.insert(owner);
                    if loan_owner.get(&loan).is_some_and(|o| *o != owner) {
                        return None;
                    }
                }
                Op::EndBorrow { .. } | Op::Suspend | Op::Return => {}
                _ => return None, // outside the lowered subset
            }
        }
    }
    // Destinations inherit the source's facts (V0 Move/Copy semantics).
    // Bounded: each pass either adds a destination or stops.
    for _ in 0..=traits.len() + introduced.len() {
        let mut changed = false;
        for block in &program.blocks {
            for op in &block.operations {
                if let Op::Move { from, into } | Op::Copy { from, into } = *op {
                    if let (Some(t), false) =
                        (traits.get(&from).copied(), traits.contains_key(&into))
                    {
                        traits.insert(into, t);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    // Owners never introduced (used without Init) are uninitialized roots too:
    // any use of them is a use of a never-owned value, as in V0.
    introduced.extend(referenced.iter().copied());

    let roots = introduced
        .iter()
        .map(|&id| {
            let t = traits.get(&id).copied().unwrap_or(crate::Traits {
                is_copy: false,
                is_send: false,
            });
            cyclic_v1::Root {
                id,
                is_copy: t.is_copy,
                is_transferable: t.is_send,
            }
        })
        .collect();

    let synthetic = program.blocks.iter().map(|b| b.id).max()?.checked_add(1)?;
    let mut blocks = Vec::with_capacity(program.blocks.len() + 1);
    let mut origins = BTreeMap::new();
    let mut original = BTreeMap::new();
    blocks.push(cyclic_v1::Block {
        id: synthetic,
        ops: introduced
            .iter()
            .map(|&o| cyclic_v1::Op::Move(place(o)))
            .collect(),
        successors: vec![program.entry],
    });
    origins.insert(
        synthetic,
        (synthetic, vec![Origin::Synthetic; introduced.len()]),
    );

    for block in &program.blocks {
        let mut ops = Vec::new();
        let mut from = Vec::new();
        for (index, op) in block.operations.iter().enumerate() {
            original.insert((block.id, index), op.clone());
            let mut push = |lowered: cyclic_v1::Op| {
                ops.push(lowered);
                from.push(Origin::Op(index));
            };
            match *op {
                Op::Init { owner, .. } => push(cyclic_v1::Op::Reinitialize(place(owner))),
                Op::Read { owner } => push(cyclic_v1::Op::Read(place(owner))),
                Op::Write { owner } => push(cyclic_v1::Op::Write(place(owner))),
                Op::Borrow { owner, loan, kind } => push(cyclic_v1::Op::Borrow {
                    loan,
                    place: place(owner),
                    kind: match kind {
                        BorrowKind::Shared => LoanKind::Shared,
                        BorrowKind::Mutable => LoanKind::Exclusive,
                    },
                }),
                Op::WriteThrough { loan, .. } => push(cyclic_v1::Op::WriteThrough(loan)),
                Op::EndBorrow { loan } => push(cyclic_v1::Op::EndLoan(loan)),
                Op::Move { from: src, into } => {
                    push(cyclic_v1::Op::Move(place(src)));
                    push(cyclic_v1::Op::Reinitialize(place(into)));
                }
                Op::Copy { from: src, into } => {
                    push(cyclic_v1::Op::Copy(place(src)));
                    push(cyclic_v1::Op::Reinitialize(place(into)));
                }
                Op::Drop { owner } => push(cyclic_v1::Op::Drop(place(owner))),
                Op::Suspend => push(cyclic_v1::Op::Suspend),
                Op::TaskCaptureMove { owner } | Op::ActorSendMove { owner } => {
                    push(cyclic_v1::Op::Transfer(place(owner)))
                }
                Op::Return => push(cyclic_v1::Op::Nop),
                _ => return None,
            }
        }
        origins.insert(block.id, (block.id, from));
        blocks.push(cyclic_v1::Block {
            id: block.id,
            ops,
            successors: block.successors.clone(),
        });
    }

    return Some(Ok(Lowered {
        program: cyclic_v1::Program {
            roots,
            blocks,
            entry: synthetic,
        },
        origins,
        original,
    }));
}

fn diag(code: &'static str, block: u32, operation: usize) -> Diagnostic {
    return Diagnostic {
        code,
        block,
        operation,
    };
}

fn map_error(lowered: &Lowered, error: &cyclic_v1::CheckError) -> Diagnostic {
    let (block, origin) = match lowered.origins.get(&error.block) {
        Some((block, ops)) => (*block, ops.get(error.operation).copied()),
        None => (error.block, None),
    };
    // An exit check reports operation == ops.len(): point past the last op.
    let operation = match origin {
        Some(Origin::Op(index)) => index,
        Some(Origin::Synthetic) => 0,
        None => lowered.original.keys().filter(|(b, _)| *b == block).count(),
    };
    let op = match origin {
        Some(Origin::Op(index)) => lowered.original.get(&(block, index)),
        _ => None,
    };
    let code = match error.code {
        Code::UseAfterMove => "E_USE_AFTER_MOVE_OR_DROP",
        // WriteThrough is cyclic_v1's only LoanConflict about loan *kind*.
        Code::LoanConflict => match op {
            Some(Op::WriteThrough { .. }) => "E_MUT_LOAN_REQUIRED",
            _ => "E_BORROW_CONFLICT",
        },
        Code::LoanNotLive => "E_UNKNOWN_LOAN",
        Code::LoanEscape => "E_LOAN_ESCAPE",
        Code::NotCopy => "E_COPY_PROOF_REQUIRED",
        Code::NotTransferable => match op {
            Some(Op::ActorSendMove { .. }) => "E_ACTOR_SEND_PROOF_REQUIRED",
            _ => "E_TASK_CAPTURE_PROOF",
        },
        Code::ReinitializeNotProven => "E_OWNER_DEF_REUSED",
        Code::UnsupportedSuspension => "E_SUSPEND_WITH_LIVE_LOAN",
        Code::ResourceLimit => "E_CFG_BUDGET",
        Code::InvalidIr => match error.message {
            "duplicate block id" => "E_CFG_DUPLICATE_BLOCK",
            "missing entry block" => "E_CFG_ENTRY",
            "duplicate LoanId definition" => "E_LOAN_DEF_REUSED",
            m if m.starts_with("unreachable") => "E_CFG_UNREACHABLE",
            _ => "E_CFG_EDGE",
        },
    };
    return diag(code, block, operation);
}
