//! Model-only consistency gate between static critical-state/ref32 preflight
//! and the separately minted, guarded logical runtime access model.
//!
//! This is NOT an authenticated compiler-to-runtime adapter or native memory
//! authorization. The caller must independently authenticate the emitted MIR,
//! runtime actor/arena/allocation provenance, physical guard and loan lifetime.
//! The returned value is only a checked guest u32 offset, never a pointer.
//! The two model namespaces have different allocation identities: matching
//! numeric offsets is necessary but NOT evidence of an authentic binding.
use crate::actor_arena_ref32_v1::Ref32 as RuntimeRef32;
use crate::actor_critical_ref32_v1::{
    verify_critical_ref32_sites, CriticalRef32Error, CriticalRef32Site,
};
use crate::actor_ref32_guarded_v1::{GuardedRef32Arena, GuardedRef32Error, Ref32Access};
use crate::actor_state_guard_v1::Permit;
use crate::{BlockId, Op, Program};

#[derive(Debug, PartialEq, Eq)]
pub enum JointModelError {
    Static(CriticalRef32Error),
    UnknownAccessOperation,
    MissingSelectedSite,
    DomainMismatch,
    ExtentMismatch,
    OffsetMismatch,
    Runtime(GuardedRef32Error),
}

/// Trusted caller must provide an independently inventoried typed-MIR program
/// and separately authentic runtime capability; this structure proves neither.
/// Only compare a specific operation after checking the COMPLETE static program.
pub struct JointModelRequest<'a, 'b> {
    pub program: &'a Program,
    pub sites: &'a [CriticalRef32Site<'b>],
    pub block: BlockId,
    pub operation: usize,
    pub runtime: &'a GuardedRef32Arena,
    pub runtime_ref: RuntimeRef32,
    pub permit: &'a Permit,
    /// Authenticated by the HOST before calling, not by this numeric input.
    pub trusted_holder: u64,
    pub displacement: u32,
    pub access_bytes: u32,
    pub alignment: u32,
}

/// Both preflight models must agree on this individual access. An 'Ok' means
/// model consistency only; it cannot be used as a native pointer capability.
/// In particular, an independent, trusted allocation-ID binding and a physical
/// reader/writer guard are still mandatory before actual machine load/store.
pub fn verify_joint_model_access(
    request: &JointModelRequest<'_, '_>,
) -> Result<u32, JointModelError> {
    verify_critical_ref32_sites(request.program, request.sites).map_err(JointModelError::Static)?;

    let op = request
        .program
        .blocks
        .iter()
        .find(|block| block.id == request.block)
        .and_then(|block| block.operations.get(request.operation))
        .ok_or(JointModelError::UnknownAccessOperation)?;

    let is_write = match op {
        Op::CriticalReadAccess { .. } | Op::CriticalCopyI64 { .. } => false,
        Op::CriticalWriteAccess { .. } => true,
        _ => return Err(JointModelError::UnknownAccessOperation),
    };

    let site = request
        .sites
        .iter()
        .find(|site| site.block == request.block && site.operation == request.operation)
        .ok_or(JointModelError::MissingSelectedSite)?;

    if site.arena.actor_id != request.runtime.owner_actor()
        || site.arena.generation != request.runtime.generation()
    {
        return Err(JointModelError::DomainMismatch);
    }
    if site.access_bytes != request.access_bytes || site.alignment != request.alignment {
        return Err(JointModelError::ExtentMismatch);
    }
    // Comparing checked addresses here is a CONSISTENCY check only. It does
    // not authenticate the static allocation ID, incarnation, or guest origin.
    let access = if is_write {
        Ref32Access::write(
            request.displacement,
            request.access_bytes,
            request.alignment,
        )
    } else {
        Ref32Access::read(
            request.displacement,
            request.access_bytes,
            request.alignment,
        )
    };
    // Check both the private ref and the LIVE permit before comparing offset.
    let checked = request
        .runtime
        .checked_offset(
            request.runtime_ref,
            request.permit,
            request.trusted_holder,
            access,
        )
        .map_err(JointModelError::Runtime)?;
    if checked != site.reference.offset {
        return Err(JointModelError::OffsetMismatch);
    }
    Ok(checked)
}
