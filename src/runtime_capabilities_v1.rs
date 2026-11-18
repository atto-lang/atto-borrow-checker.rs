//! Host-side reference implementation for frozen graphs, weak upgrades and
//! pinned buffers. This module uses real Rust allocation/locking primitives,
//! not guest pointers or self-attested "proof" booleans.
//!
//! Boundaries: it is not an AttoLang frontend, allocator, cross-tenant broker,
//! guest ABI, or native backend implementation. A trusted adapter must create
//! the graph from verified ownership/provenance and mint domain permissions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, TryLockError, Weak};

static NEXT_REGION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    InvalidDomain,
    InvalidNode,
    DuplicateNode,
    UnknownEdge,
    DisconnectedGraph,
    UnfreezableEdge,
    BudgetExceeded,
    IdentityExhausted,
    WrongDomain,
    Retired,
    Busy,
    Poisoned,
}

/// A non-plain edge cannot be waved away by freezing only the root object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Plain,
    ExternalMutableAlias,
    InteriorMutable,
    ForeignPointer,
    UnverifiedDynamic,
}

#[derive(Debug)]
pub struct GraphNode {
    pub id: u32,
    pub kind: NodeKind,
    pub payload: Vec<u8>,
    pub children: Vec<u32>,
}

/// Resource budgets are charged *before* traversing a potentially cyclic graph.
/// Actual compiler/runtime implementations also bound parser and allocation work.
#[derive(Clone, Copy, Debug)]
pub struct FreezeLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_bytes: usize,
}

impl Default for FreezeLimits {
    fn default() -> Self {
        Self { max_nodes: 1024, max_edges: 4096, max_bytes: 1024 * 1024 }
    }
}

/// Exclusive graph ownership. Not Clone: caller must pass the whole value to
/// freeze. Its members are owned byte vectors, never host/raw guest pointers.
/// A backend still MUST prove that its source graph matches this representation.
#[derive(Debug)]
pub struct UniqueGraph {
    domain: u64,
    root: u32,
    nodes: Vec<GraphNode>,
}

impl UniqueGraph {
    /// Construction is a *model* input. It does not authenticate a tenant or
    /// prove that arbitrary AttoLang objects lack outside mutable aliases.
    pub fn new(domain: u64, root: u32, nodes: Vec<GraphNode>) -> Result<Self, CapabilityError> {
        if domain == 0 {
            return Err(CapabilityError::InvalidDomain);
        }
        Ok(Self { domain, root, nodes })
    }

    fn validate(&self, limits: FreezeLimits) -> Result<(), CapabilityError> {
        if self.root == 0 || self.nodes.is_empty()
            || self.nodes.len() > limits.max_nodes
        {
            return Err(CapabilityError::BudgetExceeded);
        }
        let mut indices = BTreeMap::new();
        let (mut edges, mut bytes) = (0usize, 0usize);
        for (index, node) in self.nodes.iter().enumerate() {
            if node.id == 0 {
                return Err(CapabilityError::InvalidNode);
            }
            if indices.insert(node.id, index).is_some() {
                return Err(CapabilityError::DuplicateNode);
            }
            if node.kind != NodeKind::Plain {
                return Err(CapabilityError::UnfreezableEdge);
            }
            edges = edges.checked_add(node.children.len())
                .ok_or(CapabilityError::BudgetExceeded)?;
            bytes = bytes.checked_add(node.payload.len())
                .ok_or(CapabilityError::BudgetExceeded)?;
            if edges > limits.max_edges || bytes > limits.max_bytes {
                return Err(CapabilityError::BudgetExceeded);
            }
        }
        if !indices.contains_key(&self.root) {
            return Err(CapabilityError::UnknownEdge);
        }
        // Iterative traversal bounds stack use and correctly accepts cycles.
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from([self.root]);
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            let index = indices.get(&id).ok_or(CapabilityError::UnknownEdge)?;
            for &child in &self.nodes[*index].children {
                if !indices.contains_key(&child) {
                    return Err(CapabilityError::UnknownEdge);
                }
                queue.push_back(child);
            }
        }
        // A partially validated graph cannot hide unvisited mutable storage.
        if visited.len() != self.nodes.len() {
            return Err(CapabilityError::DisconnectedGraph);
        }
        Ok(())
    }

    /// On failure the unique owner is returned, not silently destroyed.
    /// On success no mutable graph alias survives through this Rust API.
    pub fn freeze(self, limits: FreezeLimits) -> Result<FrozenOwner, (CapabilityError, Self)> {
        if let Err(error) = self.validate(limits) {
            return Err((error, self));
        }
        let id = match NEXT_REGION_ID.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1),
        ) {
            Ok(id) => id,
            Err(_) => return Err((CapabilityError::IdentityExhausted, self)),
        };
        let mut map = BTreeMap::new();
        for node in self.nodes {
            map.insert(node.id, FrozenNode {
                payload: node.payload, children: node.children,
            });
        }
        Ok(FrozenOwner {
            region: Arc::new(FrozenRegion {
                id, domain: self.domain,
                retired: AtomicBool::new(false),
                // Physical read scopes and retirement admission use a lock.
                // The atomic retirement bit allows nonblocking owner Drop.
                leases: RwLock::new(()),
                graph: FrozenGraph { root: self.root, nodes: map },
            }),
        })
    }
}

#[derive(Debug)]
pub struct FrozenNode {
    payload: Vec<u8>,
    children: Vec<u32>,
}
impl FrozenNode {
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub fn children(&self) -> &[u32] { &self.children }
}

/// Immutable graph view; no guest-visible interior mutation is exposed.
#[derive(Debug)]
pub struct FrozenGraph {
    root: u32,
    nodes: BTreeMap<u32, FrozenNode>,
}
impl FrozenGraph {
    pub fn root(&self) -> u32 { self.root }
    pub fn node(&self, id: u32) -> Option<&FrozenNode> { self.nodes.get(&id) }
    pub fn node_count(&self) -> usize { self.nodes.len() }
}

#[derive(Debug)]
struct FrozenRegion {
    id: u64,
    domain: u64,
    // Retirement is logically immediate even when a physical read is active.
    // A reader may finish if it acquired a lease before retirement; callers
    // cannot start new reads after the atomic retirement linearization point.
    retired: AtomicBool,
    leases: RwLock<()>,
    graph: FrozenGraph,
}

/// A trusted host must mint this from independently authenticated caller
/// context; it is deliberately impossible to construct from another crate.
#[derive(Clone, Copy, Debug)]
pub struct HostDomainPermit {
    domain: u64,
}
impl HostDomainPermit {
    pub(crate) fn trusted(domain: u64) -> Result<Self, CapabilityError> {
        if domain == 0 { return Err(CapabilityError::InvalidDomain); }
        Ok(Self { domain })
    }
}

/// The sole authority for retiring a frozen region. Clone is intentionally
/// absent: share() clones *read* rights but not the retirement authority.
#[derive(Debug)]
pub struct FrozenOwner {
    region: Arc<FrozenRegion>,
}
impl FrozenOwner {
    pub fn share(&self) -> FrozenShared {
        FrozenShared { region: Arc::clone(&self.region) }
    }
    pub fn downgrade(&self) -> FrozenWeak {
        self.share().downgrade()
    }
    pub fn retire(&self) -> Result<(), CapabilityError> {
        // No scheduler-thread parking: retirement takes effect before trying
        // to establish physical quiescence. If a callback is in flight, the
        // caller gets Busy and can retry after that callback exits.
        self.region.retired.store(true, Ordering::SeqCst);
        match self.region.leases.try_write() {
            Ok(_lease) => Ok(()),
            Err(TryLockError::WouldBlock) => Err(CapabilityError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(CapabilityError::Poisoned),
        }
    }
}
impl Drop for FrozenOwner {
    fn drop(&mut self) {
        // Drop must never wait on a read callback (including a callback
        // that itself drops the owner). Arc keeps physical storage alive.
        self.region.retired.store(true, Ordering::SeqCst);
    }
}

/// Arc keeps physical memory alive, but does not bypass logical retirement.
/// Reads require a host domain permit and never return an unguarded &T.
#[derive(Clone, Debug)]
pub struct FrozenShared {
    region: Arc<FrozenRegion>,
}
impl FrozenShared {
    pub fn downgrade(&self) -> FrozenWeak {
        FrozenWeak {
            region: Arc::downgrade(&self.region),
            region_id: self.region.id,
            domain: self.region.domain,
        }
    }
    pub fn read<R>(
        &self,
        permit: &HostDomainPermit,
        access: impl FnOnce(&FrozenGraph) -> R,
    ) -> Result<R, CapabilityError> {
        if self.region.domain != permit.domain {
            return Err(CapabilityError::WrongDomain);
        }
        let _lease = self.region.leases.read().map_err(|_| CapabilityError::Poisoned)?;
        if self.region.retired.load(Ordering::SeqCst) {
            return Err(CapabilityError::Retired);
        }
        // Hold a physical read lease for the entire callback. No raw pointer
        // escapes; a concurrent retire waits for this operation to finish.
        Ok(access(&self.region.graph))
    }
}

/// Weak ownership is neither a raw pointer nor a permanent right to access.
/// Locking + Arc::upgrade prevent use-after-free and generation reuse/ABA.
#[derive(Clone, Debug)]
pub struct FrozenWeak {
    region: Weak<FrozenRegion>,
    region_id: u64,
    domain: u64,
}
impl FrozenWeak {
    pub fn upgrade(&self, permit: &HostDomainPermit) -> Option<FrozenShared> {
        if self.domain != permit.domain {
            return None;
        }
        let strong = self.region.upgrade()?;
        if strong.id != self.region_id || strong.domain != permit.domain {
            return None;
        }
        let _lease = strong.leases.read().ok()?;
        if strong.retired.load(Ordering::SeqCst) { return None; }
        drop(_lease);
        // A concurrent retire AFTER this point is valid: it must block or
        // invalidate later read() calls. Success never grants mutable access.
        Some(FrozenShared { region: strong })
    }
}

/// Stable address of the pointee even if this *handle* changes stack slots.
/// We expose only Pin<&T>, not &mut T or an unsafe pointee extraction API.
/// In particular, callers cannot move an Unpin pointee out through &mut T.
#[derive(Debug)]
pub struct StablePinned<T> {
    allocation: Pin<Box<T>>,
}
impl<T> StablePinned<T> {
    pub fn new(value: T) -> Self {
        Self { allocation: Box::pin(value) }
    }
    pub fn view(&self) -> Pin<&T> {
        self.allocation.as_ref()
    }
}
