//! Restricted V1 *preflight* for guest ref32 access against trusted MIR metadata.
//!
//! This checks actor/domain identity, generations, allocation extent, alignment,
//! and declared loan mode. It DOES NOT mint a capability, lock memory, authenticate
//! metadata, or authorize code generation without the compiler/runtime checks.
//! Shared regions require a separate explicit capability and runtime RW guard.
pub const MAX_ARENA_BYTES: u64 = u32::MAX as u64 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoanMode {
    SharedRead,
    ExclusiveWrite,
}

/// Trusted frontend/runtime inventory. An arbitrary guest cannot supply this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorArena {
    pub actor_id: u64,
    pub arena_id: u32,
    pub incarnation: u64,
    pub generation: u64,
    pub capacity_bytes: u64,
    pub retired: bool,
}

/// Represents one *live* allocation, not just the enclosing arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub actor_id: u64,
    pub arena_id: u32,
    pub incarnation: u64,
    pub generation: u64,
    pub allocation_id: u64,
    /// Nonzero slot-reuse epoch independent of actor incarnation.
    /// The runtime MUST advance on reuse and retire the slot before wrap.
    pub allocation_generation: u64,
    pub base: u32,
    pub bytes: u32,
    pub retired: bool,
}

/// 32-bit guest offset plus out-of-band authenticated domain provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ref32 {
    pub actor_id: u64,
    pub arena_id: u32,
    pub incarnation: u64,
    pub generation: u64,
    pub allocation_id: u64,
    pub allocation_generation: u64,
    pub offset: u32,
}

/// Metadata about a separately authenticated and physically held loan.
/// A compiler-generated value of this type is NEVER a physical lock proof.
#[derive(Debug, PartialEq, Eq)]
pub struct Loan {
    pub actor_id: u64,
    pub arena_id: u32,
    pub incarnation: u64,
    pub generation: u64,
    /// Allocation-bound proof context; not a physical or forge-resistant token.
    pub allocation_id: u64,
    pub allocation_generation: u64,
    pub mode: LoanMode,
    pub live: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedExtent {
    pub start: u32,
    pub end_exclusive: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ref32Error {
    InvalidArena,
    Retired,
    WrongDomain,
    StaleGeneration,
    WrongAllocation,
    StaleAllocation,
    NullReference,
    MissingLoan,
    WriteRequiresExclusive,
    InvalidAlignment,
    InvalidExtent,
    OutsideAllocation,
}

/// Rejects invalid typed-MIR ref32 access BEFORE emitting any unsafe IR.
/// An OK result is necessary but *not sufficient* for runtime access.
/// The runtime must independently validate and physically hold the loan.
pub fn check_access(
    arena: &ActorArena,
    allocation: &Allocation,
    reference: &Ref32,
    loan: &Loan,
    access_bytes: u32,
    alignment: u32,
    mode: AccessMode,
) -> Result<CheckedExtent, Ref32Error> {
    if arena.actor_id == 0
        || arena.arena_id == 0
        || arena.incarnation == 0
        || arena.generation == 0
        || arena.capacity_bytes == 0
        || arena.capacity_bytes > MAX_ARENA_BYTES
    {
        return Err(Ref32Error::InvalidArena);
    }
    if arena.retired || allocation.retired {
        return Err(Ref32Error::Retired);
    }
    if allocation.actor_id != arena.actor_id
        || reference.actor_id != arena.actor_id
        || loan.actor_id != arena.actor_id
        || allocation.arena_id != arena.arena_id
        || reference.arena_id != arena.arena_id
        || loan.arena_id != arena.arena_id
    {
        return Err(Ref32Error::WrongDomain);
    }
    if allocation.incarnation != arena.incarnation
        || reference.incarnation != arena.incarnation
        || loan.incarnation != arena.incarnation
        || allocation.generation != arena.generation
        || reference.generation != arena.generation
        || loan.generation != arena.generation
    {
        return Err(Ref32Error::StaleGeneration);
    }
    if allocation.allocation_id == 0
        || reference.allocation_id != allocation.allocation_id
        || loan.allocation_id != allocation.allocation_id
    {
        return Err(Ref32Error::WrongAllocation);
    }
    // A recycled slot within one actor incarnation must never revive a
    // stale reference or an old read/write loan.
    if allocation.allocation_generation == 0
        || reference.allocation_generation != allocation.allocation_generation
        || loan.allocation_generation != allocation.allocation_generation
    {
        return Err(Ref32Error::StaleAllocation);
    }
    // A null guest offset must never become valid by supplying metadata whose
    // allocation also starts at zero. The entire first byte is reserved.
    if reference.offset == 0 {
        return Err(Ref32Error::NullReference);
    }
    if !loan.live {
        return Err(Ref32Error::MissingLoan);
    }
    if mode == AccessMode::Write && loan.mode != LoanMode::ExclusiveWrite {
        return Err(Ref32Error::WriteRequiresExclusive);
    }
    if !alignment.is_power_of_two() || !reference.offset.is_multiple_of(alignment) {
        return Err(Ref32Error::InvalidAlignment);
    }
    // Dereferencing an empty span is never an authorization for one byte.
    if access_bytes == 0 || allocation.bytes == 0 || allocation.base == 0 {
        return Err(Ref32Error::InvalidExtent);
    }
    let allocation_end = u64::from(allocation.base) + u64::from(allocation.bytes);
    let access_end = u64::from(reference.offset) + u64::from(access_bytes);
    if allocation_end > arena.capacity_bytes || allocation_end > MAX_ARENA_BYTES {
        return Err(Ref32Error::InvalidExtent);
    }
    if reference.offset < allocation.base
        || access_end > allocation_end
        || access_end > MAX_ARENA_BYTES
    {
        return Err(Ref32Error::OutsideAllocation);
    }
    Ok(CheckedExtent {
        start: reference.offset,
        end_exclusive: access_end,
    })
}
