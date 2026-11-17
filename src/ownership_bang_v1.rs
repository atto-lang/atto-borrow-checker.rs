//! Typed ownership-bang adapter for the master Rust checker.
//!
//! Source tokenization/alias recognition stays in the frontend. This module
//! compares an independently enumerated source ownership-site census with
//! the compiler's typed MIR operations and then invokes the normal verifier.
//! It does NOT trust strings, parse .atto, authenticate type witnesses or
//! make unsafe source origins safe by relabeling them.
use std::collections::{BTreeMap, BTreeSet};

use crate::mir_v1::{verify_mir, MirError, MirFunction};
use crate::{BorrowKind, LoanId, Op, OwnerId, Proof, SharedRegionId};

pub const CONTRACT_VERSION: &str = "atto-ownership-bang-v1";
const MAX_BANG_SITES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    Copy,
    Take,
    Share,
    Borrow,
    BorrowMut,
}

/// Source spelling is metadata; it may never change ownership semantics.
/// The frontend must separately enforce punctuation adjacency, precedence,
/// single operand evaluation, token boundary rules and formatter output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Spelling {
    Preferred,
    Compact,
    LegacyRt,
    LegacyMutablePrefix,
}

/// A declaration from the trusted compiler-local place resolver, not a
/// capability that an untrusted .atto program may construct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAuthority {
    /// A uniquely owned, addressable canonical root.
    Owned,
    /// An existing scoped loan; Copy may detach a snapshot but cannot Share,
    /// Take, or create an untracked reborrow from the loan.
    BorrowedLoan,
    /// Actor-confined state requires a separate authenticated critical scope.
    ActorState,
    /// Computed, ambiguous, FFI, projected alias with unproved root, etc.
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BangSite {
    pub instruction_id: u64,
    pub source_node_id: u64,
    pub verb: Verb,
    pub spelling: Spelling,
    pub source_authority: SourceAuthority,
    pub from: OwnerId,
    /// The fresh owner minted by Copy or Take.
    pub into: Option<OwnerId>,
    /// Borrow/borrow mut mints a loan; BorrowedLoan Copy consumes no loan.
    /// Instead this field names the already-active loan to read through.
    pub loan: Option<LoanId>,
    /// The immutable shared region minted by Share.
    pub region: Option<SharedRegionId>,
    /// Only a proven addressable, writable place can be mutably borrowed.
    /// This is claimed by the native type/place checker, not inferred here.
    pub place_is_writable: bool,
}

/// Source-owned census and mapping contract. An independently generated
/// instruction-ID list must be supplied; do not construct it by mapping sites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BangManifest {
    pub version: String,
    pub sites: Vec<BangSite>,
    pub source_bang_instruction_ids: Vec<u64>,
}

/// Differentiate a malformed source-to-MIR adapter from an unsafe MIR graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BangError {
    Invalid(&'static str),
    Mir(MirError),
}

fn missing_or_extra(site: &BangSite, needs_into: bool, needs_loan: bool, needs_region: bool) -> bool {
    site.into.is_some() != needs_into
        || site.loan.is_some() != needs_loan
        || site.region.is_some() != needs_region
}

fn expected_operation(site: &BangSite) -> Result<Op, BangError> {
    let invalid = BangError::Invalid;
    if site.instruction_id == 0 || site.source_node_id == 0 || site.from == 0 {
        return Err(invalid("E_BANG_ID_ZERO"));
    }
    if site.spelling == Spelling::LegacyMutablePrefix && site.verb != Verb::BorrowMut {
        return Err(invalid("E_BANG_SPELLING_KIND"));
    }
    if matches!(site.source_authority, SourceAuthority::ActorState | SourceAuthority::Unknown) {
        return Err(invalid("E_BANG_AUTHORITY"));
    }
    let owned = site.source_authority == SourceAuthority::Owned;
    match site.verb {
        Verb::Copy => {
            if missing_or_extra(site, true, !owned, false) {
                return Err(invalid("E_BANG_OPERANDS"));
            }
            let into = site.into.ok_or(invalid("E_BANG_OPERANDS"))?;
            if into == 0 || into == site.from {
                return Err(invalid("E_BANG_DESTINATION"));
            }
            if owned {
                Ok(Op::Copy { from: site.from, into })
            } else {
                Ok(Op::CopyThrough {
                    owner: site.from,
                    loan: site.loan.ok_or(invalid("E_BANG_OPERANDS"))?,
                    into,
                })
            }
        }
        Verb::Take => {
            if !owned {
                return Err(invalid("E_BANG_TAKE_BORROWED"));
            }
            if missing_or_extra(site, true, false, false) {
                return Err(invalid("E_BANG_OPERANDS"));
            }
            let into = site.into.ok_or(invalid("E_BANG_OPERANDS"))?;
            if into == 0 || into == site.from {
                return Err(invalid("E_BANG_DESTINATION"));
            }
            Ok(Op::Move { from: site.from, into })
        }
        Verb::Borrow | Verb::BorrowMut => {
            if !owned {
                return Err(invalid("E_BANG_REBORROW_UNPROVEN"));
            }
            if missing_or_extra(site, false, true, false) {
                return Err(invalid("E_BANG_OPERANDS"));
            }
            let kind = if site.verb == Verb::BorrowMut {
                if !site.place_is_writable {
                    return Err(invalid("E_BANG_MUTABLE_PLACE_REQUIRED"));
                }
                BorrowKind::Mutable
            } else {
                BorrowKind::Shared
            };
            Ok(Op::Borrow {
                owner: site.from,
                loan: site.loan.ok_or(invalid("E_BANG_OPERANDS"))?,
                kind,
            })
        }
        Verb::Share => {
            if !owned {
                return Err(invalid("E_BANG_SHARE_BORROWED"));
            }
            if missing_or_extra(site, false, false, true) {
                return Err(invalid("E_BANG_OPERANDS"));
            }
            // Never turn an unchecked Share into a proof. The MIR operation
            // must explicitly carry its trusted transitive Sync witness.
            Ok(Op::PublishFrozen {
                owner: site.from,
                region: site.region.ok_or(invalid("E_BANG_OPERANDS"))?,
                sync_proven: true,
            })
        }
    }
}

/// Check source-site inventory and typed MIR *before* returning the canonical
/// graph's proof. The source census MUST be computed independently from the
/// MIR instruction stream; IDs and claimed origin/type facts alone prove no
/// source authenticity. A positive proof does not certify machine-code output.
pub fn verify_bang_mir(
    function: &MirFunction,
    manifest: &BangManifest,
) -> Result<Proof, BangError> {
    if manifest.version != CONTRACT_VERSION {
        return Err(BangError::Invalid("E_BANG_VERSION"));
    }
    let sites = &manifest.sites;
    let source_bang_instruction_ids = &manifest.source_bang_instruction_ids;
    if sites.len() > MAX_BANG_SITES || source_bang_instruction_ids.len() > MAX_BANG_SITES {
        return Err(BangError::Invalid("E_BANG_INVENTORY_BUDGET"));
    }
    let mut expected = BTreeSet::new();
    for &id in source_bang_instruction_ids {
        if id == 0 || !expected.insert(id) {
            return Err(BangError::Invalid("E_BANG_SOURCE_CENSUS"));
        }
    }
    let mut actual = BTreeMap::new();
    for site in sites {
        let op = expected_operation(site)?;
        if actual
            .insert(site.instruction_id, (site.source_node_id, op))
            .is_some()
        {
            return Err(BangError::Invalid("E_BANG_DUPLICATE_SITE"));
        }
    }
    let observed: BTreeSet<_> = actual.keys().copied().collect();
    if expected != observed {
        return Err(BangError::Invalid("E_BANG_INCOMPLETE_SOURCE_CENSUS"));
    }
    let mut seen = BTreeSet::new();
    for block in &function.blocks {
        for instruction in &block.instructions {
            if let Some((node, op)) = actual.get(&instruction.instruction_id) {
                if instruction.source_node_id != *node || &instruction.operation != op {
                    return Err(BangError::Invalid("E_BANG_MIR_MISMATCH"));
                }
                if !seen.insert(instruction.instruction_id) {
                    return Err(BangError::Invalid("E_BANG_DUPLICATE_MIR_SITE"));
                }
            }
        }
    }
    if seen != expected {
        return Err(BangError::Invalid("E_BANG_MISSING_MIR_SITE"));
    }
    verify_mir(function).map_err(BangError::Mir)
}
