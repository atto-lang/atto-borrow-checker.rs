//! Conservative *logical* integration of the canonical 32-bit actor arena
//! and generation-fenced reader/writer admission models.
//!
//! This exposes only checked offsets, NEVER native addresses. It does not
//! authenticate caller identities, hold a physical lock, own actual memory,
//! or authorize code generation. The trusted runtime must retain physical
//! guards across the entire native load/store and prove I/O/stack/loan
//! quiescence before freeing actor backing storage.
use crate::actor_arena_ref32_v1::{ActorArenaRef32, Ref32, Ref32Error};
use crate::actor_state_guard_v1::{GuardError, GuardQueue, Mode, Permit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedRef32Error {
    Arena(Ref32Error),
    Guard(GuardError),
    Unsealed,
    Sealed,
}

impl From<Ref32Error> for GuardedRef32Error {
    fn from(error: Ref32Error) -> Self {
        Self::Arena(error)
    }
}

impl From<GuardError> for GuardedRef32Error {
    fn from(error: GuardError) -> Self {
        Self::Guard(error)
    }
}

/// A single checked guest-memory operation. Keeping extent and mode together
/// prevents callers from accidentally swapping independently typed scalar
/// arguments while preserving fail-closed admission of explicit writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref32Access {
    displacement: u32,
    bytes: u32,
    alignment: u32,
    write: bool,
}

impl Ref32Access {
    pub const fn read(displacement: u32, bytes: u32, alignment: u32) -> Self {
        Self {
            displacement,
            bytes,
            alignment,
            write: false,
        }
    }

    pub const fn write(displacement: u32, bytes: u32, alignment: u32) -> Self {
        Self {
            displacement,
            bytes,
            alignment,
            write: true,
        }
    }
}

/// Source-free model: one owner for a sealed set of ref32 allocations, plus
/// one reader/writer permit queue covering the *whole* arena. Whole-arena
/// scopes conservatively avoid disjoint-allocation aliasing assumptions.
///
/// Callers of this type must be trusted. Numeric actor IDs supplied by a
/// guest are not admission authority. Per-allocation loans, actual heap
/// access, process/tenant boundaries and physical retirement are separate.
#[derive(Debug)]
pub struct GuardedRef32Arena {
    arena: ActorArenaRef32,
    queue: GuardQueue,
    sealed: bool,
}

impl GuardedRef32Arena {
    pub fn new(
        owner_actor: u64,
        generation: u64,
        capacity: u64,
    ) -> Result<Self, GuardedRef32Error> {
        // Construct the arena before the guard, and never expose either
        // independently; their initial generation is always identical.
        let arena = ActorArenaRef32::new(owner_actor, generation, capacity)?;
        let queue = GuardQueue::new(generation)?;
        Ok(Self {
            arena,
            queue,
            sealed: false,
        })
    }

    pub fn owner_actor(&self) -> u64 {
        self.arena.actor_id()
    }

    pub fn generation(&self) -> u64 {
        self.arena.generation()
    }

    /// Allocations can only be made before publication in this restricted
    /// model. A production runtime needs an independently proved dynamic
    /// allocation/borrow protocol; sealing is not an actor memory allocator.
    pub fn allocate_before_seal(
        &mut self,
        size: u32,
        alignment: u32,
    ) -> Result<Ref32, GuardedRef32Error> {
        if self.sealed {
            return Err(GuardedRef32Error::Sealed);
        }
        self.arena
            .allocate(size, alignment)
            .map_err(GuardedRef32Error::from)
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// The caller must authenticate the actor and region capability *before*
    /// requesting. A numeric actor ID alone grants no authorization.
    pub fn request(
        &mut self,
        trusted_holder: u64,
        generation: u64,
        mode: Mode,
    ) -> Result<u64, GuardedRef32Error> {
        if !self.sealed {
            return Err(GuardedRef32Error::Unsealed);
        }
        self.queue
            .request(trusted_holder, generation, mode)
            .map_err(GuardedRef32Error::from)
    }

    pub fn admit_ready(&mut self) -> Result<Vec<Permit>, GuardedRef32Error> {
        if !self.sealed {
            return Err(GuardedRef32Error::Unsealed);
        }
        Ok(self.queue.admit_ready())
    }

    /// Cancel a queued admission without blocking a carrier. An already
    /// admitted loan must instead be physically exited and released; a
    /// queued cancellation cannot revoke a live permit or bypass FIFO.
    /// The runtime must authenticate the holder before calling this method.
    pub fn cancel_pending(
        &mut self,
        ticket: u64,
        trusted_holder: u64,
        generation: u64,
    ) -> Result<(), GuardedRef32Error> {
        if !self.sealed {
            return Err(GuardedRef32Error::Unsealed);
        }
        self.queue
            .cancel_pending(ticket, trusted_holder, generation)
            .map_err(GuardedRef32Error::from)
    }

    /// A successful result is strictly a *logical preflight*: the authenticated
    /// permit must be checked against THIS arena's guard namespace and the
    /// ref32 against THIS arena's allocation table. Runtime physical locks
    /// and caller/tenant capability validation remain mandatory.
    pub fn checked_offset(
        &self,
        reference: Ref32,
        permit: &Permit,
        trusted_holder: u64,
        access: Ref32Access,
    ) -> Result<u32, GuardedRef32Error> {
        if !self.sealed {
            return Err(GuardedRef32Error::Unsealed);
        }
        self.queue.access(permit, trusted_holder, access.write)?;
        self.arena
            .checked_offset(
                reference,
                self.arena.actor_id(),
                self.arena.generation(),
                access.displacement,
                access.bytes,
                access.alignment,
            )
            .map_err(GuardedRef32Error::from)
    }

    pub fn release(
        &mut self,
        permit: &Permit,
        trusted_holder: u64,
    ) -> Result<(), GuardedRef32Error> {
        self.queue
            .release(permit, trusted_holder)
            .map_err(GuardedRef32Error::from)
    }

    /// Fences old permits and ref32 metadata in the same logical transition.
    /// Actual physical backing storage must not be reclaimed at this point.
    pub fn retire(&mut self, next_generation: u64) -> Result<(), GuardedRef32Error> {
        if next_generation <= self.arena.generation() {
            return Err(GuardError::StaleGeneration.into());
        }
        // Invariant: queue and arena have identical generations, are never
        // separately exposed, and may each retire only through this method.
        // Queue retirement first ensures no new permits can become live.
        self.queue.retire(next_generation)?;
        self.arena.retire(next_generation)?;
        Ok(())
    }

    /// TRUSTED RUNTIME ONLY, after independently establishing that the
    /// physical scope and ALL associated native accesses have exited.
    pub fn complete_physical_quiescence(
        &mut self,
        permit: &Permit,
        trusted_holder: u64,
    ) -> Result<(), GuardedRef32Error> {
        self.queue
            .complete_physical_quiescence(permit, trusted_holder)
            .map_err(GuardedRef32Error::from)
    }

    /// Necessary logical state, NOT independent proof of physical reclamation.
    pub fn may_reclaim(&self) -> bool {
        self.queue.may_reclaim()
    }
}
