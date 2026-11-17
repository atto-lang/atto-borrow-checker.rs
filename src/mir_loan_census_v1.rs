//! Diagnostic projection from a validated typed-MIR instruction census into
//! SSA loan facts. Not a signed compiler proof and never an admission gate.
//!
//! The compiler must independently derive AND attest the full instruction,
//! origin, alias, exception/cancellation and emitted-effect inventories before
//! any result could influence accepted AttoLang programs.
use crate::mir_v1::{self, MirError, MirFunction};
use crate::polonius_facts_v1::{Error, Facts, OriginId, OriginUse, Point, PointId};
use crate::polonius_ssa_v1::{analyze_ssa, Definition, Input, PhiInput, SsaReport};
use crate::Op;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_DIAGNOSTIC_FACTS: usize = 100_000;
const MAX_DIAGNOSTIC_LOANS: usize = 2_048;

/// The full typed-MIR instruction ID must have exactly one fact row. These
/// caller-supplied use/def origins are NOT authenticated by this interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstructionFacts {
    pub instruction_id: u64,
    pub use_origins: Vec<OriginId>,
    pub define_origins: Vec<OriginId>,
    /// Required on Op::Borrow; forbidden on every other operation.
    pub borrow_origin: Option<OriginId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhiEdge {
    /// Last instruction of the predecessor block.
    pub predecessor_instruction_id: u64,
    /// First instruction of the successor block.
    pub successor_instruction_id: u64,
    pub source: OriginId,
    pub destination: OriginId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub instruction_facts: Vec<InstructionFacts>,
    pub phi_edges: Vec<PhiEdge>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    Invalid(&'static str),
    Mir(MirError),
    Ssa(Error),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticProjection {
    pub instruction_to_point: BTreeMap<u64, PointId>,
    pub report: SsaReport,
}

/// All point/control-flow topology and Borrow/EndBorrow loan IDs are derived
/// from the validated MIR instruction list. Writes conservatively invalidate
/// *every* issued loan, since this model cannot independently establish alias
/// disjointness. It rejects all other unmodeled operations/effects.
///
/// Success is an observation, NOT safe-to-codegen authorization. In particular
/// the completeness of use_origins, define_origins, and aliases is untrusted.
pub fn project(
    mir: &MirFunction,
    evidence: &Evidence,
) -> Result<DiagnosticProjection, BridgeError> {
    // Bound nested, caller-owned fact arrays BEFORE any copy/solver work.
    // A 4096-row instruction census can otherwise hide millions of origins.
    let mut fact_count = evidence.phi_edges.len();
    for row in &evidence.instruction_facts {
        fact_count = fact_count
            .checked_add(row.use_origins.len())
            .and_then(|n| n.checked_add(row.define_origins.len()))
            .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_FACT_BUDGET"))?;
        if fact_count > MAX_DIAGNOSTIC_FACTS {
            return Err(BridgeError::Invalid("E_DIAGNOSTIC_FACT_BUDGET"));
        }
    }
    // Enforce typed MIR contract, source ID inventory, effect agreement, and
    // claimed provenance next. This does not authenticate the producer.
    mir_v1::validate_and_lower(mir).map_err(BridgeError::Mir)?;
    let instruction_count: usize = mir.blocks.iter().map(|b| b.instructions.len()).sum();
    if instruction_count == 0
        || instruction_count > 4096
        || instruction_count != evidence.instruction_facts.len()
        || evidence.phi_edges.len() > 16_384
    {
        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BUDGET_OR_INVENTORY"));
    }
    let mut facts_by_instruction = BTreeMap::new();
    for facts in &evidence.instruction_facts {
        if facts.instruction_id == 0
            || facts_by_instruction
                .insert(facts.instruction_id, facts)
                .is_some()
        {
            return Err(BridgeError::Invalid("E_DIAGNOSTIC_DUPLICATE_FACT"));
        }
    }

    let mut instruction_to_point = BTreeMap::<u64, PointId>::new();
    let mut block_first = BTreeMap::<u32, PointId>::new();
    let mut block_last = BTreeMap::<u32, PointId>::new();
    let mut id = 1u32;
    for block in &mir.blocks {
        if block.instructions.is_empty() || block_first.insert(block.id, id).is_some() {
            return Err(BridgeError::Invalid(
                "E_DIAGNOSTIC_EMPTY_OR_DUPLICATE_BLOCK",
            ));
        }
        for instruction in &block.instructions {
            if instruction_to_point
                .insert(instruction.instruction_id, id)
                .is_some()
            {
                return Err(BridgeError::Invalid("E_DIAGNOSTIC_DUPLICATE_INSTRUCTION"));
            }
            id = id
                .checked_add(1)
                .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_ID_OVERFLOW"))?;
        }
        block_last.insert(block.id, id - 1);
    }
    if instruction_to_point.len() != facts_by_instruction.len()
        || !instruction_to_point.keys().eq(facts_by_instruction.keys())
    {
        return Err(BridgeError::Invalid("E_DIAGNOSTIC_INCOMPLETE_CENSUS"));
    }
    let mut issued_loans = BTreeSet::new();
    let mut borrowed_origins = BTreeSet::new();
    let mut invalidating_operations = 0usize;
    for block in &mir.blocks {
        for instruction in &block.instructions {
            match instruction.operation {
                Op::Borrow { loan, .. } => {
                    if loan == 0 || !issued_loans.insert(loan) {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_LOAN_ID"));
                    }
                    // The provenance witness must be present on an actual
                    // MIR Borrow, never on a free-standing caller fact.
                    if let Some(origin) = facts_by_instruction[&instruction.instruction_id].borrow_origin {
                        if origin != 0 {
                            borrowed_origins.insert(origin);
                        }
                    }
                    if issued_loans.len() > MAX_DIAGNOSTIC_LOANS {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_LOAN_BUDGET"));
                    }
                }
                Op::Write { .. } | Op::Drop { .. } => {
                    invalidating_operations += 1;
                }
                _ => {}
            }
        }
    }
    // Each destructive MIR instruction invalidates ALL loans in this
    // conservative alias model. Cap the expanded fact set up front.
    let expanded = issued_loans.len()
        .checked_mul(invalidating_operations)
        .and_then(|n| n.checked_add(fact_count))
        .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_FACT_BUDGET"))?;
    if expanded > MAX_DIAGNOSTIC_FACTS {
        return Err(BridgeError::Invalid("E_DIAGNOSTIC_FACT_BUDGET"));
    }

    // Borrowed SSA origins may pass through phi joins, but a phi result is
    // accepted as a return witness only when ALL of its incoming origins
    // can be traced back to explicit MIR Borrow operations. This is still
    // caller-supplied origin metadata, not authenticated compiler evidence.
    let mut phi_sources = BTreeMap::<OriginId, BTreeSet<OriginId>>::new();
    let mut phi_dependents = BTreeMap::<OriginId, BTreeSet<OriginId>>::new();
    for edge in &evidence.phi_edges {
        phi_sources.entry(edge.destination).or_default().insert(edge.source);
        phi_dependents.entry(edge.source).or_default().insert(edge.destination);
    }
    let mut remaining: BTreeMap<OriginId, usize> = phi_sources
        .iter()
        .map(|(&origin, sources)| (origin, sources.len()))
        .collect();
    let mut queue: VecDeque<OriginId> = borrowed_origins.iter().copied().collect();
    while let Some(origin) = queue.pop_front() {
        if let Some(destinations) = phi_dependents.get(&origin) {
            for &destination in destinations {
                let count = remaining.get_mut(&destination).expect("indexed phi destination");
                if *count > 0 {
                    *count -= 1;
                    if *count == 0 && borrowed_origins.insert(destination) {
                        queue.push_back(destination);
                    }
                }
            }
        }
    }
    let mut points = Vec::with_capacity(instruction_count);
    let mut uses = Vec::new();
    let mut definitions = Vec::new();
    for block in &mir.blocks {
        for (index, instruction) in block.instructions.iter().enumerate() {
            let point_id = instruction_to_point[&instruction.instruction_id];
            let row = facts_by_instruction[&instruction.instruction_id];
            let successors = if index + 1 < block.instructions.len() {
                vec![point_id + 1]
            } else {
                let mut successors = Vec::with_capacity(block.successors.len());
                for &succ in &block.successors {
                    successors.push(
                        *block_first
                            .get(&succ)
                            .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_CFG"))?,
                    );
                }
                successors
            };
            let mut point = Point {
                id: point_id,
                successors,
                live_origins: vec![],
                subset: vec![],
                issue: vec![],
                kill: vec![],
                invalidate: vec![],
            };
            let mut local_uses = BTreeSet::new();
            let mut local_definitions = BTreeSet::new();
            for &origin in &row.use_origins {
                if origin == 0 || !local_uses.insert(origin) {
                    return Err(BridgeError::Invalid("E_DIAGNOSTIC_ORIGIN_USE"));
                }
                uses.push(OriginUse {
                    point: point_id,
                    origin,
                });
            }
            for &origin in &row.define_origins {
                if origin == 0 || !local_definitions.insert(origin) {
                    return Err(BridgeError::Invalid("E_DIAGNOSTIC_ORIGIN_DEF"));
                }
                definitions.push(Definition {
                    point: point_id,
                    origin,
                });
            }
            match instruction.operation {
                Op::Init { .. } => {
                    if row.borrow_origin.is_some() {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"));
                    }
                }
                Op::Borrow { loan, .. } => {
                    let origin = row
                        .borrow_origin
                        .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"))?;
                    if origin == 0 {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"));
                    }
                    point.issue.push((origin, loan));
                }
                Op::EndBorrow { loan } => {
                    if row.borrow_origin.is_some() {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"));
                    }
                    point.kill.push(loan);
                }
                Op::Write { .. } | Op::Drop { .. } => {
                    if row.borrow_origin.is_some() {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"));
                    }
                    point.invalidate = issued_loans.iter().copied().collect();
                }
                Op::Return => {
                    if row.borrow_origin.is_some() {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN"));
                    }
                    // Missing borrowed-return metadata could shorten a loan.
                    // This is intentionally conservative even for unit-return
                    // functions that create and consume temporary borrows.
                    if !issued_loans.is_empty() && row.use_origins.is_empty() {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_RETURN_WITNESS_REQUIRED"));
                    }
                    if !issued_loans.is_empty()
                        && !row.use_origins.iter().any(|origin| borrowed_origins.contains(origin))
                    {
                        return Err(BridgeError::Invalid("E_DIAGNOSTIC_RETURN_BORROW_PROVENANCE"));
                    }
                }
                _ => return Err(BridgeError::Invalid("E_DIAGNOSTIC_UNMODELED_OPERATION")),
            }
            points.push(point);
        }
    }
    if uses.len().saturating_add(definitions.len()) > MAX_DIAGNOSTIC_FACTS {
        return Err(BridgeError::Invalid("E_DIAGNOSTIC_FACT_BUDGET"));
    }
    let mut phi_inputs = Vec::new();
    for &phi in &evidence.phi_edges {
        let predecessor = *instruction_to_point
            .get(&phi.predecessor_instruction_id)
            .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_PHI_INSTRUCTION"))?;
        let successor = *instruction_to_point
            .get(&phi.successor_instruction_id)
            .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_PHI_INSTRUCTION"))?;
        if !block_last.values().any(|&last| last == predecessor)
            || !block_first.values().any(|&first| first == successor)
        {
            return Err(BridgeError::Invalid("E_DIAGNOSTIC_PHI_BOUNDARY"));
        }
        phi_inputs.push(PhiInput {
            predecessor,
            successor,
            source: phi.source,
            destination: phi.destination,
        });
    }
    let entry = *block_first
        .get(&mir.entry)
        .ok_or(BridgeError::Invalid("E_DIAGNOSTIC_CFG_ENTRY"))?;
    let input = Input {
        template: Facts { entry, points },
        uses,
        definitions,
        phi_inputs,
    };
    let report = analyze_ssa(&input).map_err(BridgeError::Ssa)?;
    Ok(DiagnosticProjection {
        instruction_to_point,
        report,
    })
}
