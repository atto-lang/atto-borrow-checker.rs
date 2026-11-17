//! Sound common subset of the V0 cleanup oracle and cyclic field/loan
//! analysis. This gate *never* substitutes a cyclic-only success for V0.
//! In particular, owner minting, actor sends, pinned suspensions, deep copies,
//! projected-place aliases, and cyclic CFG cleanup stay explicitly unsupported.
use crate::cyclic_v1::{
    self, Block as CBlock, LoanKind as CLoanKind, Op as COp, Place, Program as CProgram,
    Root as CRoot,
};
use crate::master_evidence_v1::{verify_strict, EvidenceResolver, StrictError};
use crate::mir_v1::MirFunction;
use crate::ownership_bang_v1::BangManifest;
use crate::{BorrowKind, Op, Proof};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DualError {
    Unsupported {
        block: u32,
        operation: usize,
        code: &'static str,
    },
    Strict(StrictError),
    Cyclic(cyclic_v1::CheckError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualProof {
    /// The authoritative full cleanup plan, never synthesized from MAY/MUST.
    pub v0: Proof,
    /// An *additional* check of the same root-only acyclic ownership events.
    pub cyclic: cyclic_v1::Report,
}

/// Verify only an exactly representable common subset. The V0 engine checks
/// all original typed operations, including path-aware cleanup and MIR
/// inventory; cyclic_v1 independently enforces root loan/move constraints.
/// A successful combined result is a restricted model result only.
pub fn verify_dual_profile(
    function: &MirFunction,
    manifest: &BangManifest,
    resolver: &mut dyn EvidenceResolver,
) -> Result<DualProof, DualError> {
    let unsupported = |block, operation, code| DualError::Unsupported {
        block, operation, code,
    };

    let mut roots = Vec::new();
    let mut blocks = Vec::new();
    let mut seen_non_init = false;
    for block in &function.blocks {
        let mut ops = Vec::new();
        for (index, instruction) in block.instructions.iter().enumerate() {
            let converted = match &instruction.operation {
                Op::Init { owner, traits } => {
                    // cyclic_v1 starts with all declared roots initialized.
                    // Only an entry-block prelude can be translated faithfully.
                    if block.id != function.entry || seen_non_init {
                        return Err(unsupported(block.id, index, "E_DUAL_LATE_INIT"));
                    }
                    roots.push(CRoot {
                        id: *owner,
                        is_copy: traits.is_copy,
                        is_transferable: traits.is_send,
                    });
                    None
                }
                Op::Read { owner } => Some(COp::Read(Place::root(*owner))),
                Op::Write { owner } => Some(COp::Write(Place::root(*owner))),
                Op::Drop { owner } => Some(COp::Drop(Place::root(*owner))),
                Op::Borrow { owner, loan, kind } => Some(COp::Borrow {
                    loan: *loan,
                    place: Place::root(*owner),
                    kind: match kind {
                        BorrowKind::Shared => CLoanKind::Shared,
                        BorrowKind::Mutable => CLoanKind::Exclusive,
                    },
                }),
                Op::ReadThrough { loan, .. } => Some(COp::ReadThrough(*loan)),
                Op::WriteThrough { loan, .. } => Some(COp::WriteThrough(*loan)),
                Op::EndBorrow { loan } => Some(COp::EndLoan(*loan)),
                Op::Suspend => Some(COp::Suspend),
                Op::Return => Some(COp::Nop),
                // Never erase unsupported operations and claim the second
                // checker independently checked ownership effects.
                _ => return Err(unsupported(block.id, index, "E_DUAL_UNMODELED_OPERATION")),
            };
            if let Some(op) = converted {
                seen_non_init = true;
                ops.push(op);
            }
        }
        blocks.push(CBlock {
            id: block.id,
            ops,
            successors: block.successors.clone(),
        });
    }
    if roots.is_empty() {
        return Err(unsupported(function.entry, 0, "E_DUAL_MISSING_ROOTS"));
    }
    // This is an *additional* checker. Never turn either reject into PASS.
    let canonical = verify_strict(function, manifest, resolver).map_err(DualError::Strict)?;
    let cyclic = cyclic_v1::check(&CProgram {
        roots,
        blocks,
        entry: function.entry,
    })
    .map_err(DualError::Cyclic)?;
    Ok(DualProof {
        v0: canonical,
        cyclic,
    })
}
