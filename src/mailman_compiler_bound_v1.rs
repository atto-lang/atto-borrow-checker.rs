//! Model-only typed-MIR / source census gate and shared Mailman transfer broker.
//! Does NOT authenticate a compiler producer, physical allocation or actor runtime.
//! The native compiler must independently attest source-site and graph inventories.
//! V1 intentionally allows transfer only: other modes need distinct typed MIR proofs.
use std::collections::{BTreeMap, BTreeSet};

use crate::mailman_delivery_v1::{
    verify_delivery, DeliveryLedger, DeliveryMode, DeliveryRequest, Error as DeliveryError,
    GraphInventory, SelectedDelivery, VerifiedDelivery,
};
use crate::mir_v1::{verify_mir, Effect, MirError, MirFunction, Producer};
use crate::{Op, OwnerId, SendTicketId};

pub const CONTRACT_VERSION: &str = "atto-mailman-compiler-transfer-v1";
const MAX_SITES: usize = 4096;
const MAX_MAILMEN: usize = 64;
const MAX_CAPACITY: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceTransferSite {
    pub instruction_id: u64,
    pub source_node_id: u64,
    pub owner: OwnerId,
    pub ticket: SendTicketId,
}

/// Independently derived native type/CFG census; submitted values are not
/// cryptographic attestations, and must never come from untrusted Atto source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerSendCensus {
    pub version: String,
    pub producer: Producer,
    pub source_transfer_sites: Vec<SourceTransferSite>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CensusVersion,
    ProducerMismatch,
    InvalidSite,
    DuplicateSite,
    IncompleteCensus,
    SendSiteMismatch,
    UnsupportedDeliveryMode,
    UnsupportedActorEffect,
    MissingCommitOrRollback,
    WrongDomain,
    InvalidMailman,
    MailmanFull,
    UnknownTicket,
    WrongMailman,
    InvalidBroker,
    MirInvalid(&'static str),
    MirUnsafe(&'static str),
    Delivery(DeliveryError),
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::CensusVersion => "E_MAIL_BIND_CENSUS_VERSION",
            Self::ProducerMismatch => "E_MAIL_BIND_PRODUCER",
            Self::InvalidSite => "E_MAIL_BIND_SITE",
            Self::DuplicateSite => "E_MAIL_BIND_DUPLICATE_SITE",
            Self::IncompleteCensus => "E_MAIL_BIND_INCOMPLETE_CENSUS",
            Self::SendSiteMismatch => "E_MAIL_BIND_SOURCE_MIR_MISMATCH",
            Self::UnsupportedDeliveryMode => "E_MAIL_BIND_UNSUPPORTED_MODE",
            Self::UnsupportedActorEffect => "E_MAIL_BIND_UNMODELED_ACTOR_EFFECT",
            Self::MissingCommitOrRollback => "E_MAIL_BIND_UNRESOLVED_SEND",
            Self::WrongDomain => "E_MAIL_BIND_DOMAIN",
            Self::InvalidMailman => "E_MAIL_BIND_MAILMAN",
            Self::MailmanFull => "E_MAIL_BIND_LOCAL_MAILBOX_FULL",
            Self::UnknownTicket => "E_MAIL_BIND_UNKNOWN_TICKET",
            Self::WrongMailman => "E_MAIL_BIND_WRONG_MAILMAN",
            Self::InvalidBroker => "E_MAIL_BIND_INVALID_BROKER",
            Self::MirInvalid(_) => "E_MAIL_BIND_MIR_INVALID",
            Self::MirUnsafe(_) => "E_MAIL_BIND_MIR_UNSAFE",
            Self::Delivery(error) => error.code(),
        }
    }
}

impl From<MirError> for Error {
    fn from(error: MirError) -> Self {
        match error {
            MirError::Invalid(code) => Self::MirInvalid(code),
            MirError::Unsafe(diagnostic) => Self::MirUnsafe(diagnostic.code),
        }
    }
}

impl From<DeliveryError> for Error {
    fn from(error: DeliveryError) -> Self {
        Self::Delivery(error)
    }
}

/// Opaque model proof, constructible only after complete submitted MIR and
/// whole-graph checks. It is NOT a runtime-granted capability.
#[derive(Debug)]
pub struct CompilerBoundTransfer {
    delivery: VerifiedDelivery,
    compiler_git_sha: String,
    source_sha256: String,
    source_node_id: u64,
    owner: OwnerId,
    source_domain: u64,
    destination_domain: u64,
}

impl CompilerBoundTransfer {
    pub fn source_node_id(&self) -> u64 { self.source_node_id }
    pub fn owner(&self) -> OwnerId { self.owner }
    pub fn compiler_git_sha(&self) -> &str { &self.compiler_git_sha }
    pub fn source_sha256(&self) -> &str { &self.source_sha256 }
}

pub fn verify_compiler_transfer(
    function: &MirFunction,
    census: &CompilerSendCensus,
    graph: &GraphInventory,
    request: &DeliveryRequest,
) -> Result<CompilerBoundTransfer, Error> {
    if request.mode != DeliveryMode::Transfer {
        return Err(Error::UnsupportedDeliveryMode);
    }
    if census.version != CONTRACT_VERSION {
        return Err(Error::CensusVersion);
    }
    if census.producer != function.producer {
        return Err(Error::ProducerMismatch);
    }
    if census.source_transfer_sites.is_empty() || census.source_transfer_sites.len() > MAX_SITES {
        return Err(Error::InvalidSite);
    }
    // Validate complete typed MIR, all effects, CFG and independently
    // enumerated instruction IDs before binding any individual source send.
    verify_mir(function)?;
    let mut sites = BTreeMap::new();
    let mut census_tickets = BTreeSet::new();
    for site in &census.source_transfer_sites {
        if site.instruction_id == 0 || site.source_node_id == 0
            || site.owner == 0 || site.ticket == 0 {
            return Err(Error::InvalidSite);
        }
        if sites.insert(site.instruction_id, site).is_some()
            || !census_tickets.insert(site.ticket) {
            return Err(Error::DuplicateSite);
        }
    }

    let mut observed = BTreeSet::new();
    let mut commits = BTreeSet::new();
    let mut aborts = BTreeSet::new();
    for block in &function.blocks {
        for instruction in &block.instructions {
            match &instruction.operation {
                Op::ActorSendPrepare { owner, ticket } => {
                    if instruction.effect != Effect::ActorBoundary {
                        return Err(Error::SendSiteMismatch);
                    }
                    let Some(site) = sites.get(&instruction.instruction_id) else {
                        return Err(Error::IncompleteCensus);
                    };
                    if site.source_node_id != instruction.source_node_id
                        || site.owner != *owner || site.ticket != *ticket {
                        return Err(Error::SendSiteMismatch);
                    }
                    observed.insert(instruction.instruction_id);
                }
                Op::ActorSendCommit { ticket } => { commits.insert(*ticket); }
                Op::ActorSendAbort { ticket } => { aborts.insert(*ticket); }
                Op::ActorSendMove { .. } | Op::ActorSendCopy { .. }
                | Op::ActorHopBorrow { .. } | Op::PublishFrozen { .. }
                | Op::PromoteGuarded { .. } => {
                    return Err(Error::UnsupportedActorEffect);
                }
                _ => {}
            }
        }
    }
    if observed.len() != sites.len() {
        return Err(Error::IncompleteCensus);
    }
    if census_tickets.iter().any(|id| !commits.contains(id) || !aborts.contains(id)) {
        return Err(Error::MissingCommitOrRollback);
    }
    let Ok(ticket) = SendTicketId::try_from(request.ticket) else {
        return Err(Error::InvalidSite);
    };
    let Some(site) = census.source_transfer_sites.iter().find(|s| s.ticket == ticket) else {
        return Err(Error::SendSiteMismatch);
    };
    if request.source_domain == 0 || request.destination_domain == 0
        || request.source_domain != request.destination_domain {
        return Err(Error::WrongDomain);
    }
    let delivery = verify_delivery(graph, request)?;
    if delivery.selected() != SelectedDelivery::Transfer {
        return Err(Error::UnsupportedDeliveryMode);
    }
    Ok(CompilerBoundTransfer {
        delivery,
        compiler_git_sha: function.producer.compiler_git_sha.clone(),
        source_sha256: function.producer.source_sha256.clone(),
        source_node_id: site.source_node_id,
        owner: site.owner,
        source_domain: request.source_domain,
        destination_domain: request.destination_domain,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State { Pending, Committed }

#[derive(Clone, Copy, Debug)]
struct OwnedTicket { mailman: u32, state: State }

#[derive(Clone, Copy, Debug)]
struct Quota { capacity: usize, reserved: usize, committed: usize }

/// One broker is shared by *all* Mailmen within the same actor/heap domain.
/// Its exclusive mutable borrow serializes model decisions. Production needs
/// a runtime-global registry with atomic synchronization and ABA-safe grants.
#[derive(Debug)]
pub struct SharedTransferBroker {
    domain: u64,
    destination_generation: u64,
    ledger: DeliveryLedger,
    mailmen: BTreeMap<u32, Quota>,
    tickets: BTreeMap<(u64, u64), OwnedTicket>,
}

impl SharedTransferBroker {
    pub fn new(
        domain: u64,
        destination_generation: u64,
        global_capacity: usize,
        mailman_capacities: &[(u32, usize)],
    ) -> Result<Self, Error> {
        if domain == 0 || destination_generation == 0
            || global_capacity == 0 || global_capacity > MAX_CAPACITY
            || mailman_capacities.is_empty() || mailman_capacities.len() > MAX_MAILMEN {
            return Err(Error::InvalidBroker);
        }
        let mut mailmen = BTreeMap::new();
        for (id, cap) in mailman_capacities {
            if *id == 0 || *cap == 0 || *cap > MAX_CAPACITY
                || mailmen.insert(*id, Quota {
                    capacity: *cap, reserved: 0, committed: 0
                }).is_some() {
                return Err(Error::InvalidBroker);
            }
        }
        Ok(Self {
            domain,
            destination_generation,
            ledger: DeliveryLedger::new(global_capacity, destination_generation),
            mailmen,
            tickets: BTreeMap::new(),
        })
    }

    pub fn prepare(&mut self, mailman: u32, proof: &CompilerBoundTransfer) -> Result<(), Error> {
        if proof.source_domain != self.domain || proof.destination_domain != self.domain {
            return Err(Error::WrongDomain);
        }
        if proof.delivery.destination_actor_generation() != self.destination_generation {
            return Err(Error::Delivery(DeliveryError::StaleGeneration));
        }
        let Some(quota) = self.mailmen.get(&mailman) else {
            return Err(Error::InvalidMailman);
        };
        if quota.reserved.saturating_add(quota.committed) >= quota.capacity {
            return Err(Error::MailmanFull);
        }
        // The authoritative ledger gates graph conflicts, replay, ticket and
        // allocation epochs. Failed admission changes neither local quota.
        self.ledger.prepare(&proof.delivery)?;
        let key = (proof.delivery.ticket(), proof.delivery.ticket_generation());
        self.tickets.insert(key, OwnedTicket { mailman, state: State::Pending });
        let quota = self.mailmen.get_mut(&mailman).ok_or(Error::InvalidMailman)?;
        quota.reserved += 1;
        Ok(())
    }

    fn check_ticket(&self, mailman: u32, ticket: u64, generation: u64, expected: State)
        -> Result<(), Error> {
        let Some(record) = self.tickets.get(&(ticket, generation)) else {
            return Err(Error::UnknownTicket);
        };
        if record.mailman != mailman {
            return Err(Error::WrongMailman);
        }
        if record.state != expected {
            return Err(Error::UnknownTicket);
        }
        Ok(())
    }

    pub fn commit(&mut self, mailman: u32, ticket: u64, generation: u64) -> Result<(), Error> {
        self.check_ticket(mailman, ticket, generation, State::Pending)?;
        if !self.ledger.commit(ticket, generation)? {
            return Err(Error::UnsupportedDeliveryMode);
        }
        let quota = self.mailmen.get_mut(&mailman).ok_or(Error::InvalidMailman)?;
        quota.reserved -= 1;
        quota.committed += 1;
        if let Some(record) = self.tickets.get_mut(&(ticket, generation)) {
            record.state = State::Committed;
        }
        Ok(())
    }

    pub fn abort(&mut self, mailman: u32, ticket: u64, generation: u64) -> Result<(), Error> {
        self.check_ticket(mailman, ticket, generation, State::Pending)?;
        self.ledger.abort(ticket, generation)?;
        let quota = self.mailmen.get_mut(&mailman).ok_or(Error::InvalidMailman)?;
        quota.reserved -= 1;
        self.tickets.remove(&(ticket, generation));
        Ok(())
    }

    pub fn finish(&mut self, mailman: u32, ticket: u64, generation: u64) -> Result<(), Error> {
        self.check_ticket(mailman, ticket, generation, State::Committed)?;
        self.ledger.finish(ticket, generation)?;
        let quota = self.mailmen.get_mut(&mailman).ok_or(Error::InvalidMailman)?;
        quota.committed -= 1;
        self.tickets.remove(&(ticket, generation));
        Ok(())
    }

    pub fn counts(&self, mailman: u32) -> Option<(usize, usize)> {
        self.mailmen.get(&mailman).map(|q| (q.reserved, q.committed))
    }
}
