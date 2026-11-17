//! Strict, compiler-attested canonical ownership verification.
//!
//! A Rust host must implement EvidenceResolver using a *separate* trusted
//! typed-source and type/layout/effect inventory. Calling this API with an
//! allow-all resolver is NOT a proof of language or guest correctness.
//! Every accepted profile still uses the same V0/MIR ownership engine.
use std::collections::BTreeSet;

use crate::mir_v1::{MirFunction, Producer};
use crate::ownership_bang_v1::{
    verify_bang_mir, BangError, BangManifest, SourceAuthority, Verb,
};
use crate::{Op, OwnerId, Proof};

pub const CONTRACT_VERSION: &str = "atto-master-evidence-v1";
const MAX_REQUIREMENTS: usize = 300_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProofKind {
    OwnedAuthority,
    BorrowedLoanRoot,
    CopyTrait,
    SendTrait,
    MutablePlace,
    FrozenSync,
    DetachedOwnedCopy,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EvidenceRequest {
    pub instruction_id: u64,
    pub source_node_id: u64,
    pub owner: OwnerId,
    pub kind: ProofKind,
}

/// This must query the *independent native compiler provenance/type resolver*.
/// A caller-supplied bool, unchecked hash or self-confirming MIR event list
/// does not constitute independent evidence. The implementation must fail
/// closed when the source and type witness cannot be authenticated.
pub trait EvidenceResolver {
    fn prove(&mut self, producer: &Producer, request: &EvidenceRequest) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictError {
    Canonical(BangError),
    Invalid(&'static str),
    EvidenceDenied(EvidenceRequest),
}

fn insert(
    requirements: &mut BTreeSet<EvidenceRequest>,
    id: u64,
    node: u64,
    owner: OwnerId,
    kind: ProofKind,
) -> Result<(), StrictError> {
    if id == 0 || node == 0 || owner == 0 {
        return Err(StrictError::Invalid("E_EVIDENCE_ID_ZERO"));
    }
    if requirements.len() >= MAX_REQUIREMENTS {
        return Err(StrictError::Invalid("E_EVIDENCE_BUDGET"));
    }
    requirements.insert(EvidenceRequest {
        instruction_id: id,
        source_node_id: node,
        owner,
        kind,
    });
    Ok(())
}

/// Validate the full ownership and typed-MIR inventory before asking an
/// external resolver to authenticate any independent source/type facts.
/// On a bad MIR or site manifest, the resolver receives **zero** callbacks.
pub fn verify_strict(
    function: &MirFunction,
    manifest: &BangManifest,
    resolver: &mut dyn EvidenceResolver,
) -> Result<Proof, StrictError> {
    let result = verify_bang_mir(function, manifest).map_err(StrictError::Canonical)?;
    let mut requirements = BTreeSet::new();
    for block in &function.blocks {
        for instruction in &block.instructions {
            let id = instruction.instruction_id;
            let node = instruction.source_node_id;
            match &instruction.operation {
                Op::Init { owner, traits } => {
                    if traits.is_copy {
                        insert(&mut requirements, id, node, *owner, ProofKind::CopyTrait)?;
                    }
                    if traits.is_send {
                        insert(&mut requirements, id, node, *owner, ProofKind::SendTrait)?;
                    }
                }
                Op::Borrow { owner, kind: crate::BorrowKind::Mutable, .. } => {
                    insert(&mut requirements, id, node, *owner, ProofKind::MutablePlace)?;
                }
                Op::CopyThrough { owner, detached_proven: true, .. } => {
                    insert(&mut requirements, id, node, *owner, ProofKind::DetachedOwnedCopy)?;
                }
                Op::PublishFrozen { owner, sync_proven: true, .. } => {
                    insert(&mut requirements, id, node, *owner, ProofKind::FrozenSync)?;
                }
                _ => {}
            }
        }
    }
    for site in &manifest.sites {
        let kind = match site.source_authority {
            SourceAuthority::Owned => ProofKind::OwnedAuthority,
            SourceAuthority::BorrowedLoan => ProofKind::BorrowedLoanRoot,
            SourceAuthority::ActorState | SourceAuthority::Unknown => {
                // The inner checker rejects these profiles; this is defensive.
                return Err(StrictError::Invalid("E_EVIDENCE_UNPROVEN_AUTHORITY"));
            }
        };
        insert(
            &mut requirements,
            site.instruction_id,
            site.source_node_id,
            site.from,
            kind,
        )?;
        if site.verb == Verb::BorrowMut && !site.place_is_writable {
            return Err(StrictError::Invalid("E_EVIDENCE_MUTABLE_PLACE"));
        }
    }
    for request in requirements {
        if !resolver.prove(&function.producer, &request) {
            return Err(StrictError::EvidenceDenied(request));
        }
    }
    Ok(result)
}
