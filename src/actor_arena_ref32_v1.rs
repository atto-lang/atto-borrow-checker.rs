//! Canonical ref32 actor-arena access *model* for backend differential tests.
//!
//! No guest pointers or host memory are allocated here. Native runtimes must
//! independently enforce these checks at every load/store and prove physical
//! loan/continuation/I/O quiescence before freeing backing storage. This module
//! grants no shared-region permission: use guarded, generation-fenced runtime
//! loans before entering an explicitly authorized shared domain.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ARENA_ID: AtomicU64 = AtomicU64::new(1);

/// Zero is reserved as a null/invalid guest offset.
pub const MAX_REF32_CAPACITY: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ref32Error {
    InvalidIdentity,
    InvalidCapacity,
    InvalidSize,
    InvalidAlignment,
    ArenaIdExhausted,
    AllocationIdExhausted,
    Exhausted,
    WrongArena,
    WrongActor,
    StaleGeneration,
    StaleAllocation,
    OutOfBounds,
    Unaligned,
    Retired,
}

/// A checked guest offset plus trusted out-of-band domain/generation metadata.
/// Private fields prevent safe callers from forging an arbitrary arena token.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ref32 {
    offset: u32,
    arena_id: u64,
    actor_id: u64,
    arena_generation: u64,
    allocation_id: u64,
}

impl Ref32 {
    pub fn offset(self) -> u32 {
        self.offset
    }
}

#[derive(Clone, Copy, Debug)]
struct Allocation {
    size: u32,
    id: u64,
}

/// A bump-only, per-actor allocation metadata oracle; NOT a production heap.
/// An actor's guest memory must be independently allocated and physically
/// protected by its compiler/runtime. No offset recycling is supported here.
#[derive(Debug)]
pub struct ActorArenaRef32 {
    arena_id: u64,
    actor_id: u64,
    generation: u64,
    capacity: u64,
    next_offset: u64,
    next_allocation_id: u64,
    allocations: BTreeMap<u32, Allocation>,
    retired: bool,
}

impl ActorArenaRef32 {
    pub fn new(actor_id: u64, generation: u64, capacity: u64) -> Result<Self, Ref32Error> {
        if actor_id == 0 || generation == 0 {
            return Err(Ref32Error::InvalidIdentity);
        }
        if capacity == 0 || capacity > MAX_REF32_CAPACITY {
            return Err(Ref32Error::InvalidCapacity);
        }
        // Preserve unique identity even if generations/offsets match across
        // distinct actor arenas. Do not wrap or reuse a trusted namespace ID.
        let arena_id = NEXT_ARENA_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Ref32Error::ArenaIdExhausted)?;
        Ok(Self {
            arena_id,
            actor_id,
            generation,
            capacity,
            next_offset: 1,
            next_allocation_id: 1,
            allocations: BTreeMap::new(),
            retired: false,
        })
    }

    pub fn actor_id(&self) -> u64 {
        self.actor_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Return a unique, nonzero ref32; allocation is atomic on error.
    /// Each allocation has its own extent; access cannot spill into a
    /// neighboring allocation merely because it fits inside the arena.
    pub fn allocate(&mut self, size: u32, alignment: u32) -> Result<Ref32, Ref32Error> {
        if self.retired {
            return Err(Ref32Error::Retired);
        }
        if size == 0 {
            return Err(Ref32Error::InvalidSize);
        }
        check_alignment(alignment)?;
        let align = u64::from(alignment);
        let pad = (align - self.next_offset % align) % align;
        let start = self.next_offset.checked_add(pad).ok_or(Ref32Error::Exhausted)?;
        let end = start
            .checked_add(u64::from(size))
            .ok_or(Ref32Error::Exhausted)?;
        // Exclusive end may equal MAX_REF32_CAPACITY+1; the largest *address*
        // is still a u32. Do not truncate or wrap a host-sized pointer.
        if start > MAX_REF32_CAPACITY || end > self.capacity + 1 {
            return Err(Ref32Error::Exhausted);
        }
        let next_id = self
            .next_allocation_id
            .checked_add(1)
            .ok_or(Ref32Error::AllocationIdExhausted)?;
        let offset = u32::try_from(start).map_err(|_| Ref32Error::Exhausted)?;
        let allocation_id = self.next_allocation_id;
        self.allocations.insert(offset, Allocation { size, id: allocation_id });
        self.next_offset = end;
        self.next_allocation_id = next_id;
        Ok(Ref32 {
            offset,
            arena_id: self.arena_id,
            actor_id: self.actor_id,
            arena_generation: self.generation,
            allocation_id,
        })
    }

    /// Resolve only within the original allocation and exact actor incarnation.
    /// Returns a checked 32-bit offset, never a host address or reference.
    /// The trusted runtime must still validate the physical memory operation.
    pub fn checked_offset(
        &self,
        reference: Ref32,
        requesting_actor: u64,
        expected_generation: u64,
        displacement: u32,
        size: u32,
        alignment: u32,
    ) -> Result<u32, Ref32Error> {
        if self.retired {
            return Err(Ref32Error::Retired);
        }
        if requesting_actor == 0 || expected_generation == 0 {
            return Err(Ref32Error::InvalidIdentity);
        }
        if requesting_actor != self.actor_id || reference.actor_id != self.actor_id {
            return Err(Ref32Error::WrongActor);
        }
        if expected_generation != self.generation
            || reference.arena_generation != self.generation
        {
            return Err(Ref32Error::StaleGeneration);
        }
        if reference.arena_id != self.arena_id {
            return Err(Ref32Error::WrongArena);
        }
        if size == 0 {
            return Err(Ref32Error::InvalidSize);
        }
        check_alignment(alignment)?;
        let allocation = self
            .allocations
            .get(&reference.offset)
            .ok_or(Ref32Error::StaleAllocation)?;
        if allocation.id != reference.allocation_id {
            return Err(Ref32Error::StaleAllocation);
        }
        let relative_end = u64::from(displacement)
            .checked_add(u64::from(size))
            .ok_or(Ref32Error::OutOfBounds)?;
        if relative_end > u64::from(allocation.size) {
            return Err(Ref32Error::OutOfBounds);
        }
        let absolute = u64::from(reference.offset)
            .checked_add(u64::from(displacement))
            .ok_or(Ref32Error::OutOfBounds)?;
        if absolute % u64::from(alignment) != 0 {
            return Err(Ref32Error::Unaligned);
        }
        u32::try_from(absolute).map_err(|_| Ref32Error::OutOfBounds)
    }

    /// Permanently fence this metadata domain. A new incarnation must mint
    /// a NEW arena; this method does not reclaim physical memory or quiesce
    /// in-flight native/FFI accesses.
    pub fn retire(&mut self, next_generation: u64) -> Result<(), Ref32Error> {
        if self.retired {
            return Err(Ref32Error::Retired);
        }
        if next_generation <= self.generation {
            return Err(Ref32Error::StaleGeneration);
        }
        self.retired = true;
        self.generation = next_generation;
        Ok(())
    }
}

fn check_alignment(alignment: u32) -> Result<(), Ref32Error> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(Ref32Error::InvalidAlignment);
    }
    Ok(())
}
