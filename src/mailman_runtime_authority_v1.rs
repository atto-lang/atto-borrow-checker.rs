//! Runtime-local, safe-Rust Mailman transfer authority (experimental V1).
//!
//! The authority is shared across Mailmen and all handles to one domain while
//! alive. Only the trusted allocator adapter may register or retire allocations;
//! the caller's compiler proof NEVER creates a live allocation by itself.
//! A pending permit is linear (not Clone), aborts on drop, and cannot commit
//! twice. A committed envelope must be explicitly accepted by its recipient;
//! abandoned committed envelopes remain quarantined until a later, separately
//! verified destructor/recovery path exists.
//!
//! This does NOT move physical heaps, authenticate compiler codegen, mint
//! unforgeable cross-process tokens, or safely expose arbitrary shared memory.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use crate::mailman_compiler_bound_v1::{
    CompilerBoundTransfer, Error as BrokerError, SharedTransferBroker,
};
use crate::mailman_delivery_v1::AllocationId;
use crate::OwnerId;

const MAX_ALLOCATIONS: usize = 65_536;
const MAX_GRANTS: usize = 4096;
const MAX_DOMAINS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActorIdentity {
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationStamp {
    pub id: AllocationId,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAuthority,
    AuthorityConflict,
    InvalidActor,
    InvalidAllocation,
    AllocationBudget,
    DuplicateAllocation,
    StaleAllocation,
    OwnerMismatch,
    AllocationBusy,
    IncompleteGraph,
    WrongDomain,
    WrongActorGeneration,
    GrantBudget,
    GrantMissing,
    GrantState,
    InvalidOwner,
    Poisoned,
    Broker(BrokerError),
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "E_MAIL_RUNTIME_AUTHORITY",
            Self::AuthorityConflict => "E_MAIL_RUNTIME_DOMAIN_CONFLICT",
            Self::InvalidActor => "E_MAIL_RUNTIME_ACTOR",
            Self::InvalidAllocation => "E_MAIL_RUNTIME_ALLOCATION",
            Self::AllocationBudget => "E_MAIL_RUNTIME_ALLOCATION_BUDGET",
            Self::DuplicateAllocation => "E_MAIL_RUNTIME_DUPLICATE_ALLOCATION",
            Self::StaleAllocation => "E_MAIL_RUNTIME_ALLOCATION_EPOCH",
            Self::OwnerMismatch => "E_MAIL_RUNTIME_OWNER",
            Self::AllocationBusy => "E_MAIL_RUNTIME_RESERVED",
            Self::IncompleteGraph => "E_MAIL_RUNTIME_GRAPH_MISMATCH",
            Self::WrongDomain => "E_MAIL_RUNTIME_DOMAIN",
            Self::WrongActorGeneration => "E_MAIL_RUNTIME_ACTOR_EPOCH",
            Self::GrantBudget => "E_MAIL_RUNTIME_GRANT_BUDGET",
            Self::GrantMissing => "E_MAIL_RUNTIME_UNKNOWN_GRANT",
            Self::GrantState => "E_MAIL_RUNTIME_GRANT_STATE",
            Self::InvalidOwner => "E_MAIL_RUNTIME_OWNER_SLOT",
            Self::Poisoned => "E_MAIL_RUNTIME_POISON",
            Self::Broker(error) => error.code(),
        }
    }
}

impl From<BrokerError> for Error {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    actor: ActorIdentity,
    slot: OwnerId,
}

#[derive(Clone, Copy, Debug)]
struct Live {
    epoch: u64,
    owner: Option<Owner>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending,
    Committed,
}

#[derive(Debug)]
struct Grant {
    phase: Phase,
    mailman: u32,
    ticket: u64,
    ticket_generation: u64,
    source: ActorIdentity,
    destination: ActorIdentity,
    allocations: Vec<AllocationStamp>,
}

#[derive(Debug)]
struct State {
    domain: u64,
    destination: ActorIdentity,
    capacity: usize,
    quotas: Vec<(u32, usize)>,
    broker: SharedTransferBroker,
    live: BTreeMap<AllocationId, Live>,
    reserved: BTreeSet<AllocationId>,
    grants: BTreeMap<u64, Grant>,
    next_grant: u64,
}

type Shared = Arc<Mutex<State>>;
// Retain each authority for the process lifetime. A weak directory would
// silently forget quarantined handoffs when the last application handle drops.
type Directory = BTreeMap<u64, Shared>;

fn directory() -> &'static Mutex<Directory> {
    static DIRECTORY: OnceLock<Mutex<Directory>> = OnceLock::new();
    DIRECTORY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Cloneable *handle* to one shared domain authority. The permit and receiver
/// envelope are NOT cloneable. The global weak directory prevents the same
/// process from accidentally opening competing authorities for a live domain.
#[derive(Clone, Debug)]
pub struct DomainAuthority {
    shared: Shared,
}

impl DomainAuthority {
    pub fn open(
        domain: u64,
        destination: ActorIdentity,
        capacity: usize,
        mailmen: &[(u32, usize)],
    ) -> Result<Self, Error> {
        if domain == 0 || destination.id == 0 || destination.generation == 0 {
            return Err(Error::InvalidAuthority);
        }
        let mut quotas = mailmen.to_vec();
        quotas.sort_unstable();
        let mut map = directory().lock().map_err(|_| Error::Poisoned)?;
        // Never discard a domain's consumed/escrow history before process
        // shutdown, even when all ordinary application handles have dropped.
        if let Some(existing) = map.get(&domain).cloned() {
            let state = existing.lock().map_err(|_| Error::Poisoned)?;
            if state.destination != destination
                || state.capacity != capacity
                || state.quotas != quotas
            {
                return Err(Error::AuthorityConflict);
            }
            drop(state);
            return Ok(Self { shared: existing });
        }
        if map.len() >= MAX_DOMAINS {
            return Err(Error::AllocationBudget);
        }
        let broker = SharedTransferBroker::new(domain, destination.generation, capacity, &quotas)?;
        let shared = Arc::new(Mutex::new(State {
            domain,
            destination,
            capacity,
            quotas,
            broker,
            live: BTreeMap::new(),
            reserved: BTreeSet::new(),
            grants: BTreeMap::new(),
            next_grant: 1,
        }));
        map.insert(domain, Arc::clone(&shared));
        Ok(Self { shared })
    }

    /// PRIVILEGED HOST ADAPTER. Only an allocator may invoke this on actual
    /// freshly allocated live objects. It is NOT an AttoLang source API.
    /// Batch preflight is atomic: a failed registration changes no ownership.
    pub fn register_allocator_owned(
        &self,
        actor: ActorIdentity,
        owner_slot: OwnerId,
        stamps: &[AllocationStamp],
    ) -> Result<(), Error> {
        if actor.id == 0 || actor.generation == 0 {
            return Err(Error::InvalidActor);
        }
        if owner_slot == 0 {
            return Err(Error::InvalidOwner);
        }
        if stamps.is_empty() || stamps.len() > MAX_ALLOCATIONS {
            return Err(Error::InvalidAllocation);
        }
        let mut guard = self.shared.lock().map_err(|_| Error::Poisoned)?;
        if guard.live.len().saturating_add(stamps.len()) > MAX_ALLOCATIONS {
            return Err(Error::AllocationBudget);
        }
        let mut seen = BTreeSet::new();
        for stamp in stamps {
            if stamp.id == 0 || stamp.generation == 0 {
                return Err(Error::InvalidAllocation);
            }
            if !seen.insert(stamp.id) {
                return Err(Error::DuplicateAllocation);
            }
            if guard.reserved.contains(&stamp.id) {
                return Err(Error::AllocationBusy);
            }
            if let Some(previous) = guard.live.get(&stamp.id) {
                if previous.owner.is_some() {
                    return Err(Error::DuplicateAllocation);
                }
                if stamp.generation <= previous.epoch {
                    return Err(Error::StaleAllocation);
                }
            }
        }
        for stamp in stamps {
            guard.live.insert(
                stamp.id,
                Live {
                    epoch: stamp.generation,
                    owner: Some(Owner {
                        actor,
                        slot: owner_slot,
                    }),
                },
            );
        }
        Ok(())
    }

    /// PRIVILEGED HOST ADAPTER. The allocator MUST have performed actual
    /// object destruction before retiring these registered allocations.
    pub fn retire_destroyed(
        &self,
        actor: ActorIdentity,
        owner_slot: OwnerId,
        stamps: &[AllocationStamp],
    ) -> Result<(), Error> {
        if stamps.is_empty() || owner_slot == 0 {
            return Err(Error::InvalidAllocation);
        }
        let mut guard = self.shared.lock().map_err(|_| Error::Poisoned)?;
        let mut seen = BTreeSet::new();
        for stamp in stamps {
            if !seen.insert(stamp.id) {
                return Err(Error::DuplicateAllocation);
            }
            if guard.reserved.contains(&stamp.id) {
                return Err(Error::AllocationBusy);
            }
            let Some(entry) = guard.live.get(&stamp.id) else {
                return Err(Error::InvalidAllocation);
            };
            if entry.epoch != stamp.generation {
                return Err(Error::StaleAllocation);
            }
            if entry.owner
                != Some(Owner {
                    actor,
                    slot: owner_slot,
                })
            {
                return Err(Error::OwnerMismatch);
            }
        }
        for stamp in stamps {
            if let Some(entry) = guard.live.get_mut(&stamp.id) {
                entry.owner = None;
            }
        }
        Ok(())
    }

    /// The runtime gets an opaque, linear capability only after every graph
    /// node matches trusted allocator registration AND the compiler proof.
    /// There is no sender invalidation until successful commit.
    pub fn prepare(
        &self,
        mailman: u32,
        source: ActorIdentity,
        proof: &CompilerBoundTransfer,
    ) -> Result<PendingTransfer, Error> {
        if source.id == 0 || source.generation == 0 {
            return Err(Error::InvalidActor);
        }
        let mut state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        let delivery = proof.delivery();
        if delivery.source_actor_generation() != source.generation
            || delivery.destination_actor_generation() != state.destination.generation
        {
            return Err(Error::WrongActorGeneration);
        }
        if state.grants.len() >= MAX_GRANTS || state.next_grant == u64::MAX {
            return Err(Error::GrantBudget);
        }
        let keys = delivery.allocation_keys();
        if keys.is_empty() || keys.len() > MAX_ALLOCATIONS {
            return Err(Error::IncompleteGraph);
        }
        let mut stamps = Vec::with_capacity(keys.len());
        for key in keys {
            if key.domain() != state.domain {
                return Err(Error::WrongDomain);
            }
            let Some(allocated) = state.live.get(&key.id()) else {
                return Err(Error::IncompleteGraph);
            };
            if allocated.epoch != key.generation() {
                return Err(Error::StaleAllocation);
            }
            if allocated.owner
                != Some(Owner {
                    actor: source,
                    slot: proof.owner(),
                })
            {
                return Err(Error::OwnerMismatch);
            }
            if state.reserved.contains(&key.id()) {
                return Err(Error::AllocationBusy);
            }
            stamps.push(AllocationStamp {
                id: key.id(),
                generation: key.generation(),
            });
        }

        // All preceding preflights are read-only. The broker reservation is
        // the first mutation, under the SAME domain-state mutex.
        state.broker.prepare(mailman, proof)?;
        let grant_id = state.next_grant;
        state.next_grant += 1;
        for stamp in &stamps {
            state.reserved.insert(stamp.id);
        }
        let ticket = delivery.ticket();
        let ticket_generation = delivery.ticket_generation();
        let destination = state.destination;
        state.grants.insert(
            grant_id,
            Grant {
                phase: Phase::Pending,
                mailman,
                ticket,
                ticket_generation,
                source,
                destination,
                allocations: stamps,
            },
        );
        Ok(PendingTransfer {
            shared: Arc::clone(&self.shared),
            id: grant_id,
            armed: true,
        })
    }

    /// Inspection only; it never conveys ownership or access to an object.
    pub fn owner_of(
        &self,
        stamp: AllocationStamp,
    ) -> Result<Option<(ActorIdentity, OwnerId)>, Error> {
        let state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        let Some(entry) = state.live.get(&stamp.id) else {
            return Ok(None);
        };
        if entry.epoch != stamp.generation {
            return Err(Error::StaleAllocation);
        }
        Ok(entry.owner.map(|owner| (owner.actor, owner.slot)))
    }

    pub fn pending_count(&self) -> Result<usize, Error> {
        let state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        Ok(state.grants.len())
    }
}

impl State {
    fn abort(&mut self, id: u64) -> Result<(), Error> {
        let grant = self.grants.get(&id).ok_or(Error::GrantMissing)?;
        if grant.phase != Phase::Pending {
            return Err(Error::GrantState);
        }
        self.broker
            .abort(grant.mailman, grant.ticket, grant.ticket_generation)?;
        for stamp in &grant.allocations {
            self.reserved.remove(&stamp.id);
        }
        self.grants.remove(&id);
        Ok(())
    }

    fn commit(&mut self, id: u64) -> Result<(), Error> {
        let grant = self.grants.get(&id).ok_or(Error::GrantMissing)?;
        if grant.phase != Phase::Pending {
            return Err(Error::GrantState);
        }
        let source = grant.source;
        for stamp in &grant.allocations {
            let Some(entry) = self.live.get(&stamp.id) else {
                return Err(Error::IncompleteGraph);
            };
            if entry.epoch != stamp.generation {
                return Err(Error::StaleAllocation);
            }
            if entry.owner.is_none_or(|owner| owner.actor != source) {
                return Err(Error::OwnerMismatch);
            }
        }
        // Broker commit consumes sender ownership in its graph ledger first;
        // registry then places nodes in-flight and inaccessible to both actors.
        self.broker
            .commit(grant.mailman, grant.ticket, grant.ticket_generation)?;
        for stamp in &grant.allocations {
            if let Some(entry) = self.live.get_mut(&stamp.id) {
                entry.owner = None;
            }
        }
        if let Some(grant) = self.grants.get_mut(&id) {
            grant.phase = Phase::Committed;
        }
        Ok(())
    }

    fn accept(&mut self, id: u64, owner_slot: OwnerId) -> Result<(), Error> {
        if owner_slot == 0 {
            return Err(Error::InvalidOwner);
        }
        let grant = self.grants.get(&id).ok_or(Error::GrantMissing)?;
        if grant.phase != Phase::Committed {
            return Err(Error::GrantState);
        }
        for stamp in &grant.allocations {
            let Some(entry) = self.live.get(&stamp.id) else {
                return Err(Error::IncompleteGraph);
            };
            if entry.epoch != stamp.generation || entry.owner.is_some() {
                return Err(Error::GrantState);
            }
        }
        self.broker
            .finish(grant.mailman, grant.ticket, grant.ticket_generation)?;
        let destination = grant.destination;
        for stamp in &grant.allocations {
            if let Some(entry) = self.live.get_mut(&stamp.id) {
                entry.owner = Some(Owner {
                    actor: destination,
                    slot: owner_slot,
                });
            }
            self.reserved.remove(&stamp.id);
        }
        self.grants.remove(&id);
        Ok(())
    }
}

/// Non-cloneable, non-user-mintable provisional permit. Dropping an
/// uncommitted permit rolls back escrow (or retains it if the mutex poisoned).
#[derive(Debug)]
pub struct PendingTransfer {
    shared: Shared,
    id: u64,
    armed: bool,
}

impl PendingTransfer {
    pub fn commit(&mut self) -> Result<ReceivedTransfer, Error> {
        if !self.armed {
            return Err(Error::GrantState);
        }
        let mut state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        state.commit(self.id)?;
        self.armed = false;
        Ok(ReceivedTransfer {
            shared: Arc::clone(&self.shared),
            id: self.id,
            accepted: false,
        })
    }

    pub fn abort(&mut self) -> Result<(), Error> {
        if !self.armed {
            return Err(Error::GrantState);
        }
        let mut state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        state.abort(self.id)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for PendingTransfer {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut state) = self.shared.lock() {
                if state.abort(self.id).is_ok() {
                    self.armed = false;
                }
            }
        }
    }
}

/// Non-cloneable committed handoff. An unaccepted envelope is quarantined
/// rather than silently restoring sender ownership or freeing live memory.
/// Supervisor recovery must supply a separately proven destruction path.
#[derive(Debug)]
pub struct ReceivedTransfer {
    shared: Shared,
    id: u64,
    accepted: bool,
}

impl ReceivedTransfer {
    pub fn accept(&mut self, destination_owner_slot: OwnerId) -> Result<(), Error> {
        if self.accepted {
            return Err(Error::GrantState);
        }
        let mut state = self.shared.lock().map_err(|_| Error::Poisoned)?;
        state.accept(self.id, destination_owner_slot)?;
        self.accepted = true;
        Ok(())
    }
}
