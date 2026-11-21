//! Restricted joint preflight for lexical critical actor state and ref32.
//! Does not authenticate compiler metadata or acquire/hold physical RW locks.
//! Successful verification is NOT runtime authority to access native memory.
use std::collections::BTreeMap;

use crate::actor_ref32_v1::{
    check_access, AccessMode, ActorArena, Allocation, Loan, Ref32, Ref32Error,
};
use crate::{verify, ActorStateId, BlockId, CriticalScopeId, Diagnostic, Op, Program, Proof};

const MAX_SITES: usize = 100_000;

#[derive(Debug)]
pub struct CriticalRef32Site<'a> {
    pub block: BlockId,
    pub operation: usize,
    pub state: ActorStateId,
    pub scope: CriticalScopeId,
    /// Trusted compiler mapping of the state place to an allocation ID.
    pub state_allocation_id: u64,
    pub arena: &'a ActorArena,
    pub allocation: &'a Allocation,
    pub reference: &'a Ref32,
    pub loan: &'a Loan,
    pub access_bytes: u32,
    pub alignment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CriticalRef32Error {
    Lexical(Diagnostic),
    SiteBudget,
    DuplicateSite {
        block: BlockId,
        operation: usize,
    },
    MissingSite {
        block: BlockId,
        operation: usize,
    },
    UnexpectedSite {
        block: BlockId,
        operation: usize,
    },
    StateMismatch {
        block: BlockId,
        operation: usize,
    },
    AllocationBindingMismatch {
        block: BlockId,
        operation: usize,
    },
    /// A detached i64 snapshot must read all eight bytes, never a prefix.
    InvalidScalarWidth {
        block: BlockId,
        operation: usize,
        bytes: u32,
    },
    Ref32 {
        block: BlockId,
        operation: usize,
        reason: Ref32Error,
    },
}

/// Enforce a one-to-one inventory of all typed critical reads, writes and
/// scalar snapshots, then check trusted allocation and loan descriptors.
/// The runtime MUST independently validate capabilities and physical loans.
pub fn verify_critical_ref32_sites(
    program: &Program,
    sites: &[CriticalRef32Site<'_>],
) -> Result<Proof, CriticalRef32Error> {
    if sites.len() > MAX_SITES {
        return Err(CriticalRef32Error::SiteBudget);
    }
    let proof = verify(program).map_err(CriticalRef32Error::Lexical)?;
    let mut pending = BTreeMap::new();
    for site in sites {
        if pending.insert((site.block, site.operation), site).is_some() {
            return Err(CriticalRef32Error::DuplicateSite {
                block: site.block,
                operation: site.operation,
            });
        }
    }
    for block in &program.blocks {
        for (index, op) in block.operations.iter().enumerate() {
            let (state, scope, mode) = match op {
                Op::CriticalReadAccess { state, scope }
                | Op::CriticalCopyI64 { state, scope, .. } => (*state, *scope, AccessMode::Read),
                Op::CriticalWriteAccess { state, scope } => (*state, *scope, AccessMode::Write),
                _ => continue,
            };
            let site =
                pending
                    .remove(&(block.id, index))
                    .ok_or(CriticalRef32Error::MissingSite {
                        block: block.id,
                        operation: index,
                    })?;
            if site.state != state || site.scope != scope {
                return Err(CriticalRef32Error::StateMismatch {
                    block: block.id,
                    operation: index,
                });
            }
            if site.state_allocation_id == 0
                || site.state_allocation_id != site.allocation.allocation_id
            {
                return Err(CriticalRef32Error::AllocationBindingMismatch {
                    block: block.id,
                    operation: index,
                });
            }
            if matches!(op, Op::CriticalCopyI64 { .. }) && site.access_bytes != 8 {
                return Err(CriticalRef32Error::InvalidScalarWidth {
                    block: block.id,
                    operation: index,
                    bytes: site.access_bytes,
                });
            }
            check_access(
                site.arena,
                site.allocation,
                site.reference,
                site.loan,
                site.access_bytes,
                site.alignment,
                mode,
            )
            .map_err(|reason| CriticalRef32Error::Ref32 {
                block: block.id,
                operation: index,
                reason,
            })?;
        }
    }
    if let Some((&(block, operation), _)) = pending.iter().next() {
        return Err(CriticalRef32Error::UnexpectedSite { block, operation });
    }
    Ok(proof)
}
