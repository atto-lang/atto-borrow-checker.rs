//! Restricted, model-only Mailman graph/lease delivery oracle.
//!
//! This module validates the *shape* of a compiler-submitted whole-graph
//! ownership inventory. It cannot authenticate that the compiler supplied
//! every pointer/alias, or that a production runtime minted its envelopes.
//! It is NOT physical memory isolation, a runtime Mailman or guest execution.
use std::collections::{BTreeMap, BTreeSet};

pub type AllocationId = u32;
const MAX_NODES: usize = 4096;
const MAX_EDGES: usize = 16384;
const MAX_TICKETS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
    Transfer,
    DeepCopy,
    ReadLease,
    WriteLease,
    FrozenShare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedDelivery {
    Transfer,
    DeepCopy,
    ElidedDeepCopy,
    ReadLease,
    WriteLease,
    FrozenShare,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allocation {
    pub id: AllocationId,
    pub owner_domain: u64,
    pub mutable: bool,
    pub sendable: bool,
    pub deep_copyable: bool,
    pub frozen: bool,
    pub sync: bool,
    /// Every reachable pointer edge, including interior/back references.
    pub references: Vec<AllocationId>,
    /// Known aliases outside the authoritative graph (not tracked leases).
    pub escaped_aliases: u32,
    pub active_readers: u32,
    pub active_writer: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphInventory {
    pub root: AllocationId,
    pub nodes: Vec<Allocation>,
    /// Independently enumerated by a compiler pass, not inferred here.
    /// The oracle tests *submitted* completeness, not census authenticity.
    pub expected_reachable: Vec<AllocationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRequest {
    pub mode: DeliveryMode,
    pub source_domain: u64,
    pub destination_domain: u64,
    pub source_actor_generation: u64,
    pub destination_actor_generation: u64,
    pub ticket: u64,
    pub ticket_generation: u64,
    /// An asynchronously retained lease requires separately proven pinned
    /// frame, borrow extent, receiver quiescence and cleanup paths.
    pub lease_may_suspend: bool,
    pub pinned_lease_proven: bool,
    pub scoped_lease_proven: bool,
    /// Copy-elision requests are a backend optimization, not a change to
    /// source-level copy!! semantics.
    pub allow_elision: bool,
    pub source_observable_after_send: bool,
    pub copy_identity_or_hooks_observable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidInventory,
    InventoryBudget,
    StaleGeneration,
    InvalidTicket,
    NotSendable,
    OwnershipNotExclusive,
    OutstandingLoan,
    CopyWitnessRequired,
    FrozenSyncRequired,
    CrossDomainZeroCopy,
    LeaseScopeRequired,
    LeaseSuspendUnproven,
    LeaseConflict,
    MailboxFull,
    DuplicateTicket,
    UnknownTicket,
    LeaseStillActive,
    TicketLimit,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInventory => "E_MAIL_GRAPH_INVENTORY",
            Self::InventoryBudget => "E_MAIL_GRAPH_BUDGET",
            Self::StaleGeneration => "E_MAIL_ACTOR_GENERATION",
            Self::InvalidTicket => "E_MAIL_TICKET_ID",
            Self::NotSendable => "E_MAIL_SENDABLE",
            Self::OwnershipNotExclusive => "E_MAIL_GRAPH_NOT_UNIQUE",
            Self::OutstandingLoan => "E_MAIL_LOAN_OUTSTANDING",
            Self::CopyWitnessRequired => "E_MAIL_DEEP_COPY_WITNESS",
            Self::FrozenSyncRequired => "E_MAIL_FROZEN_SYNC",
            Self::CrossDomainZeroCopy => "E_MAIL_DOMAIN",
            Self::LeaseScopeRequired => "E_MAIL_LEASE_SCOPE",
            Self::LeaseSuspendUnproven => "E_MAIL_LEASE_SUSPEND",
            Self::LeaseConflict => "E_MAIL_LEASE_CONFLICT",
            Self::MailboxFull => "E_MAILBOX_FULL",
            Self::DuplicateTicket => "E_MAIL_DUPLICATE_TICKET",
            Self::UnknownTicket => "E_MAIL_UNKNOWN_TICKET",
            Self::LeaseStillActive => "E_MAIL_LEASE_ACTIVE",
            Self::TicketLimit => "E_MAIL_TICKET_BUDGET",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDelivery {
    pub selected: SelectedDelivery,
    pub reachable: Vec<AllocationId>,
    pub ticket: u64,
    pub ticket_generation: u64,
    pub source_actor_generation: u64,
    pub destination_actor_generation: u64,
}

fn verify_inventory(inventory: &GraphInventory) -> Result<Vec<AllocationId>, Error> {
    if inventory.root == 0
        || inventory.nodes.is_empty()
        || inventory.nodes.len() > MAX_NODES
        || inventory.expected_reachable.len() != inventory.nodes.len()
    {
        return Err(Error::InventoryBudget);
    }
    let mut indexed = BTreeMap::new();
    let mut edges = 0usize;
    for node in &inventory.nodes {
        if node.id == 0 || indexed.insert(node.id, node).is_some() {
            return Err(Error::InvalidInventory);
        }
        edges = edges.saturating_add(node.references.len());
        if edges > MAX_EDGES || node.active_readers == u32::MAX {
            return Err(Error::InventoryBudget);
        }
        // Immutable sharing may retain external references only if frozen.
        if !node.mutable && node.active_writer {
            return Err(Error::InvalidInventory);
        }
    }
    let expected: BTreeSet<_> = inventory.expected_reachable.iter().copied().collect();
    if expected.len() != inventory.expected_reachable.len()
        || expected.len() != indexed.len()
        || !expected.contains(&inventory.root)
    {
        return Err(Error::InvalidInventory);
    }
    let mut discovered = BTreeSet::new();
    let mut worklist = vec![inventory.root];
    while let Some(id) = worklist.pop() {
        let Some(node) = indexed.get(&id) else {
            return Err(Error::InvalidInventory);
        };
        if discovered.insert(id) {
            for child in &node.references {
                if !indexed.contains_key(child) {
                    return Err(Error::InvalidInventory);
                }
                worklist.push(*child);
            }
        }
    }
    if discovered != expected {
        return Err(Error::InvalidInventory);
    }
    Ok(discovered.into_iter().collect())
}

pub fn verify_delivery(
    inventory: &GraphInventory,
    request: &DeliveryRequest,
) -> Result<VerifiedDelivery, Error> {
    if request.source_actor_generation == 0 || request.destination_actor_generation == 0 {
        return Err(Error::StaleGeneration);
    }
    if request.ticket == 0 || request.ticket_generation == 0 {
        return Err(Error::InvalidTicket);
    }
    let reachable = verify_inventory(inventory)?;
    if inventory.nodes.iter().any(|node| !node.sendable) {
        return Err(Error::NotSendable);
    }
    let same_domain = request.source_domain == request.destination_domain;
    let unique = inventory.nodes.iter().all(|node| {
        if node.frozen && node.sync && !node.mutable {
            true
        } else {
            node.owner_domain == request.source_domain
                && node.escaped_aliases == 0
                && node.active_readers == 0
                && !node.active_writer
        }
    });
    let no_outstanding_loans = inventory
        .nodes
        .iter()
        .all(|node| node.active_readers == 0 && !node.active_writer);
    let selected = match request.mode {
        DeliveryMode::Transfer => {
            if !same_domain {
                return Err(Error::CrossDomainZeroCopy);
            }
            if !no_outstanding_loans {
                return Err(Error::OutstandingLoan);
            }
            if !unique {
                return Err(Error::OwnershipNotExclusive);
            }
            SelectedDelivery::Transfer
        }
        DeliveryMode::DeepCopy => {
            if inventory.nodes.iter().any(|node| node.active_writer) {
                return Err(Error::LeaseConflict);
            }
            if inventory.nodes.iter().any(|node| {
                node.mutable
                    && (node.owner_domain != request.source_domain || node.escaped_aliases != 0)
            }) && !request.scoped_lease_proven
            {
                return Err(Error::LeaseScopeRequired);
            }
            if inventory
                .nodes
                .iter()
                .any(|node| node.mutable && !node.deep_copyable)
            {
                return Err(Error::CopyWitnessRequired);
            }
            if request.allow_elision
                && !request.source_observable_after_send
                && !request.copy_identity_or_hooks_observable
                && same_domain
                && unique
            {
                SelectedDelivery::ElidedDeepCopy
            } else {
                SelectedDelivery::DeepCopy
            }
        }
        DeliveryMode::FrozenShare => {
            if inventory
                .nodes
                .iter()
                .any(|node| node.mutable || !node.frozen || !node.sync)
            {
                return Err(Error::FrozenSyncRequired);
            }
            if !same_domain {
                return Err(Error::CrossDomainZeroCopy);
            }
            SelectedDelivery::FrozenShare
        }
        DeliveryMode::ReadLease | DeliveryMode::WriteLease => {
            if !same_domain {
                return Err(Error::CrossDomainZeroCopy);
            }
            if !request.scoped_lease_proven {
                return Err(Error::LeaseScopeRequired);
            }
            if request.lease_may_suspend && !request.pinned_lease_proven {
                return Err(Error::LeaseSuspendUnproven);
            }
            if inventory.nodes.iter().any(|node| {
                (node.mutable
                    && (node.owner_domain != request.source_domain || node.escaped_aliases != 0))
                    || (node.owner_domain != request.source_domain && (!node.frozen || !node.sync))
            }) {
                return Err(Error::OwnershipNotExclusive);
            }
            match request.mode {
                DeliveryMode::ReadLease => {
                    if inventory.nodes.iter().any(|node| node.active_writer) {
                        return Err(Error::LeaseConflict);
                    }
                    SelectedDelivery::ReadLease
                }
                DeliveryMode::WriteLease => {
                    if !no_outstanding_loans {
                        return Err(Error::LeaseConflict);
                    }
                    SelectedDelivery::WriteLease
                }
                _ => unreachable!(),
            }
        }
    };
    Ok(VerifiedDelivery {
        selected,
        reachable,
        ticket: request.ticket,
        ticket_generation: request.ticket_generation,
        source_actor_generation: request.source_actor_generation,
        destination_actor_generation: request.destination_actor_generation,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ticket {
    selected: SelectedDelivery,
    reachable: Vec<AllocationId>,
    active_users: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RegionGuard {
    readers: usize,
    writer: bool,
}

fn is_writer(mode: SelectedDelivery) -> bool {
    matches!(
        mode,
        SelectedDelivery::Transfer
            | SelectedDelivery::ElidedDeepCopy
            | SelectedDelivery::WriteLease
    )
}

fn is_reader(mode: SelectedDelivery) -> bool {
    matches!(
        mode,
        SelectedDelivery::DeepCopy | SelectedDelivery::ReadLease
    )
}

fn retains_guard_after_commit(mode: SelectedDelivery) -> bool {
    !matches!(
        mode,
        SelectedDelivery::DeepCopy | SelectedDelivery::FrozenShare
    )
}

/// Bounded *host model* for Mailman escrow/admission, not a physical mailbox.
/// Tickets cannot be reused after commit/abort/finish during this ledger's life.
#[derive(Debug)]
pub struct DeliveryLedger {
    capacity: usize,
    reserved: usize,
    committed: usize,
    pending: BTreeMap<(u64, u64), Ticket>,
    delivered: BTreeMap<(u64, u64), Ticket>,
    seen: BTreeSet<(u64, u64)>,
    latest_ticket_generation: BTreeMap<u64, u64>,
    guards: BTreeMap<AllocationId, RegionGuard>,
    consumed: BTreeSet<AllocationId>,
}

impl DeliveryLedger {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            reserved: 0,
            committed: 0,
            pending: BTreeMap::new(),
            delivered: BTreeMap::new(),
            seen: BTreeSet::new(),
            latest_ticket_generation: BTreeMap::new(),
            guards: BTreeMap::new(),
            consumed: BTreeSet::new(),
        }
    }

    pub fn prepare(&mut self, proof: &VerifiedDelivery) -> Result<(), Error> {
        let id = (proof.ticket, proof.ticket_generation);
        if self.seen.contains(&id)
            || self
                .latest_ticket_generation
                .get(&proof.ticket)
                .is_some_and(|epoch| *epoch >= proof.ticket_generation)
        {
            return Err(Error::DuplicateTicket);
        }
        if self.seen.len() >= MAX_TICKETS {
            return Err(Error::TicketLimit);
        }
        if self.reserved.saturating_add(self.committed) >= self.capacity {
            return Err(Error::MailboxFull);
        }
        for node in &proof.reachable {
            if self.consumed.contains(node) {
                return Err(Error::OwnershipNotExclusive);
            }
            let guard = self.guards.get(node).copied().unwrap_or_default();
            if (is_writer(proof.selected) && (guard.writer || guard.readers != 0))
                || (is_reader(proof.selected) && guard.writer)
                || (proof.selected == SelectedDelivery::FrozenShare
                    && (guard.writer || guard.readers != 0))
            {
                return Err(Error::LeaseConflict);
            }
        }
        self.acquire_guards(proof.selected, &proof.reachable);
        self.seen.insert(id);
        self.latest_ticket_generation
            .insert(proof.ticket, proof.ticket_generation);
        self.pending.insert(
            id,
            Ticket {
                selected: proof.selected,
                reachable: proof.reachable.clone(),
                active_users: 0,
            },
        );
        self.reserved += 1;
        Ok(())
    }

    fn acquire_guards(&mut self, mode: SelectedDelivery, nodes: &[AllocationId]) {
        for id in nodes {
            let guard = self.guards.entry(*id).or_default();
            if is_reader(mode) {
                guard.readers += 1;
            } else if is_writer(mode) {
                guard.writer = true;
            }
        }
    }

    fn release_guards(&mut self, mode: SelectedDelivery, nodes: &[AllocationId]) {
        for id in nodes {
            if let Some(guard) = self.guards.get_mut(id) {
                if is_reader(mode) {
                    guard.readers -= 1;
                } else if is_writer(mode) {
                    guard.writer = false;
                }
                if guard.readers == 0 && !guard.writer {
                    self.guards.remove(id);
                }
            }
        }
    }

    pub fn commit(&mut self, ticket: u64, generation: u64) -> Result<bool, Error> {
        let id = (ticket, generation);
        let value = self.pending.remove(&id).ok_or(Error::UnknownTicket)?;
        self.reserved -= 1;
        self.committed += 1;
        if !retains_guard_after_commit(value.selected) {
            self.release_guards(value.selected, &value.reachable);
        }
        let consumed = matches!(
            value.selected,
            SelectedDelivery::Transfer | SelectedDelivery::ElidedDeepCopy
        );
        if consumed {
            self.consumed.extend(value.reachable.iter().copied());
        }
        self.delivered.insert(id, value);
        Ok(consumed)
    }

    pub fn abort(&mut self, ticket: u64, generation: u64) -> Result<(), Error> {
        let value = self
            .pending
            .remove(&(ticket, generation))
            .ok_or(Error::UnknownTicket)?;
        self.release_guards(value.selected, &value.reachable);
        self.reserved -= 1;
        Ok(())
    }

    pub fn enter_lease_user(&mut self, ticket: u64, generation: u64) -> Result<(), Error> {
        let value = self
            .delivered
            .get_mut(&(ticket, generation))
            .ok_or(Error::UnknownTicket)?;
        if !matches!(
            value.selected,
            SelectedDelivery::ReadLease | SelectedDelivery::WriteLease
        ) {
            return Err(Error::LeaseScopeRequired);
        }
        value.active_users = value
            .active_users
            .checked_add(1)
            .ok_or(Error::TicketLimit)?;
        Ok(())
    }

    pub fn exit_lease_user(&mut self, ticket: u64, generation: u64) -> Result<(), Error> {
        let value = self
            .delivered
            .get_mut(&(ticket, generation))
            .ok_or(Error::UnknownTicket)?;
        if value.active_users == 0 {
            return Err(Error::UnknownTicket);
        }
        value.active_users -= 1;
        Ok(())
    }

    pub fn finish(&mut self, ticket: u64, generation: u64) -> Result<(), Error> {
        let id = (ticket, generation);
        let value = self.delivered.get(&id).ok_or(Error::UnknownTicket)?;
        if value.active_users != 0 {
            return Err(Error::LeaseStillActive);
        }
        let value = self.delivered.remove(&id).ok_or(Error::UnknownTicket)?;
        if retains_guard_after_commit(value.selected) {
            self.release_guards(value.selected, &value.reachable);
        }
        self.committed -= 1;
        Ok(())
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.reserved, self.committed)
    }
}
