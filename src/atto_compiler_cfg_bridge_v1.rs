//! Closed, bounded adapter from a *real* AttoLang compiler typed-CFG
//! manifest to the independent SSA/Polonius-inspired diagnostic checker.
//!
//! Input is not authenticated. Only a SHA-bound, compiler-checked typed-IR
//! producer plus independent emission/instruction inventory can someday
//! promote the result. This module MUST NOT authorize production codegen.
use crate::polonius_facts_v1::{Error, Facts, OriginUse, Point, PointId};
use crate::polonius_ssa_v1::{analyze_ssa, Definition, Input, SsaReport};
use std::collections::{BTreeMap, BTreeSet};

pub const CONTRACT: &str = "ATTO_LOAN_CFG_V1";
const MAX_BYTES: usize = 1_048_576;
const MAX_FUNCTIONS: usize = 256;
const MAX_POINTS: usize = 1024;
const MAX_LOANS: usize = 256;
const MAX_EDGES: usize = 8192;
const MAX_REFS: usize = 16_384;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    Invalid(&'static str),
    Ssa(Error),
}
#[derive(Debug, Clone)]
pub struct FunctionReport {
    pub name: String,
    pub node_count: usize,
    pub loan_count: usize,
    pub ssa: SsaReport,
}
#[derive(Debug, Clone)]
pub struct DifferentialReport {
    pub contract: &'static str,
    pub functions: Vec<FunctionReport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Issue,
    Marker,
    End,
    Set,
    Eval,
    Condition,
    Return,
}
#[derive(Clone, Debug)]
struct Row {
    id: PointId,
    kind: Kind,
    loan: u32,
    owner: u32,
    flag: u32,
    via: u32,
    succ: Vec<PointId>,
    reads: Vec<(u32, u32)>,
    direct: Vec<u32>,
    trap: bool,
    conditional: bool,
}
fn invalid(msg: &'static str) -> BridgeError {
    BridgeError::Invalid(msg)
}
fn number(s: &str) -> Result<u32, BridgeError> {
    if s.is_empty()
        || s.len() > 10
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("E_WIRE_NONCANONICAL_NUMBER"));
    }
    s.parse().map_err(|_| invalid("E_WIRE_NUMBER_OVERFLOW"))
}
fn bool_num(s: &str) -> Result<bool, BridgeError> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(invalid("E_WIRE_FLAG")),
    }
}
fn numbers(s: &str) -> Result<Vec<u32>, BridgeError> {
    if s == "-" {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for item in s.split(',') {
        result.push(number(item)?);
        if result.len() > MAX_REFS {
            return Err(invalid("E_WIRE_FACT_BUDGET"));
        }
    }
    Ok(result)
}
fn borrowed(s: &str) -> Result<Vec<(u32, u32)>, BridgeError> {
    if s == "-" {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for item in s.split(',') {
        let (loan, owner) = item
            .split_once(':')
            .ok_or_else(|| invalid("E_WIRE_LOAN_READ"))?;
        let loan = number(loan)?;
        let owner = number(owner)?;
        if loan == 0 {
            return Err(invalid("E_WIRE_LOAN_ID"));
        }
        result.push((loan, owner));
        if result.len() > MAX_REFS {
            return Err(invalid("E_WIRE_FACT_BUDGET"));
        }
    }
    Ok(result)
}
fn row(line: &str) -> Result<Row, BridgeError> {
    let fields: Vec<_> = line.split('|').collect();
    if fields.len() != 12 || fields[0] != "P" {
        return Err(invalid("E_WIRE_POINT_SHAPE"));
    }
    let kind = match fields[2] {
        "I" => Kind::Issue,
        "M" => Kind::Marker,
        "E" => Kind::End,
        "S" => Kind::Set,
        "V" => Kind::Eval,
        "C" => Kind::Condition,
        "R" => Kind::Return,
        _ => return Err(invalid("E_WIRE_POINT_KIND")),
    };
    let id = number(fields[1])?;
    let loan = number(fields[3])?;
    let owner = number(fields[4])?;
    let flag = u32::from(bool_num(fields[5])?);
    let via = number(fields[6])?;
    let succ = numbers(fields[7])?;
    let reads = borrowed(fields[8])?;
    let direct = numbers(fields[9])?;
    let trap = bool_num(fields[10])?;
    let conditional = bool_num(fields[11])?;
    if id == 0
        || match kind {
            Kind::Issue | Kind::Marker | Kind::End => loan == 0 || via != 0,
            Kind::Set => loan != 0 || flag != 0,
            _ => loan != 0 || owner != 0 || flag != 0 || via != 0,
        }
    {
        return Err(invalid("E_WIRE_POINT_FIELDS"));
    }
    if (kind != Kind::Set && kind != Kind::Eval && kind != Kind::Condition && kind != Kind::Return)
        && (!reads.is_empty() || !direct.is_empty() || trap || conditional)
    {
        return Err(invalid("E_WIRE_EVENT_HAS_GUEST_EXPR"));
    }
    if kind == Kind::Return && !succ.is_empty() {
        return Err(invalid("E_WIRE_RETURN_EDGE"));
    }
    Ok(Row {
        id,
        kind,
        loan,
        owner,
        flag,
        via,
        succ,
        reads,
        direct,
        trap,
        conditional,
    })
}
fn one_function(name: String, entry: u32, rows: Vec<Row>) -> Result<FunctionReport, BridgeError> {
    let count = rows.len();
    if count == 0 || count > MAX_POINTS || entry == 0 || entry as usize > count {
        return Err(invalid("E_WIRE_FUNCTION_RANGE"));
    }
    let mut ids = BTreeSet::new();
    let mut incoming = vec![0usize; count + 1];
    let mut edges = 0usize;
    for r in &rows {
        if r.id == 0 || r.id as usize > count || !ids.insert(r.id) {
            return Err(invalid("E_WIRE_POINT_INVENTORY"));
        }
        let mut successors = BTreeSet::new();
        for &id in &r.succ {
            if id == 0 || id as usize > count || !successors.insert(id) {
                return Err(invalid("E_WIRE_CFG_EDGE"));
            }
            incoming[id as usize] += 1;
            edges += 1;
            if edges > MAX_EDGES {
                return Err(invalid("E_WIRE_CFG_BUDGET"));
            }
        }
    }
    if ids.len() != count || incoming[entry as usize] != 0 {
        return Err(invalid("E_WIRE_CFG_ENTRY_OR_GAPS"));
    }
    let mut owners = BTreeMap::<u32, (u32, bool)>::new();
    for r in &rows {
        if r.kind == Kind::Issue && owners.insert(r.loan, (r.owner, r.flag == 1)).is_some() {
            return Err(invalid("E_WIRE_DUPLICATE_LOAN"));
        }
    }
    if owners.len() > MAX_LOANS {
        return Err(invalid("E_WIRE_LOAN_BUDGET"));
    }
    let mut points = Vec::new();
    let mut uses = Vec::new();
    let mut definitions = Vec::new();
    let mut borrowed_use_points = Vec::new();
    let mut fact_count = 0usize;
    for r in &rows {
        let mut issue = Vec::new();
        let mut kill = Vec::new();
        let mut invalidate = Vec::new();
        match r.kind {
            Kind::Issue => {
                issue.push((r.loan, r.loan));
                definitions.push(Definition {
                    point: r.id,
                    origin: r.loan,
                });
            }
            Kind::End => {
                if owners
                    .get(&r.loan)
                    .is_none_or(|(owner, _)| *owner != r.owner)
                {
                    return Err(invalid("E_WIRE_END_OWNER"));
                }
                kill.push(r.loan);
            }
            Kind::Marker => {
                if owners
                    .get(&r.loan)
                    .is_none_or(|(owner, ex)| *owner != r.owner || (r.flag == 1 && !ex))
                {
                    return Err(invalid("E_WIRE_MARKER_OWNER"));
                }
            }
            Kind::Set => {
                if r.via != 0
                    && owners
                        .get(&r.via)
                        .is_none_or(|(owner, ex)| *owner != r.owner || !ex)
                {
                    return Err(invalid("E_WIRE_WRITE_THROUGH"));
                }
                if r.via != 0 {
                    // A store through a loan is a use even without an RHS load.
                    borrowed_use_points.push((r.id, r.via));
                }
            }
            Kind::Eval | Kind::Condition | Kind::Return => {}
        }
        for &(loan, owner) in &r.reads {
            if owners
                .get(&loan)
                .is_none_or(|(issued_owner, _)| *issued_owner != owner)
            {
                return Err(invalid("E_WIRE_TYPED_LOAN_USE_OWNER"));
            }
            borrowed_use_points.push((r.id, loan));
        }
        // Visit each known loan once per point, not once per direct read.
        // Loan issuance conflicts with an already-live overlapping loan when
        // either is exclusive. A shared/shared issuance remains admissible.
        let direct: BTreeSet<_> = r.direct.iter().copied().collect();
        invalidate.extend(owners.iter().filter_map(|(&loan, &(owner, exclusive))| {
            let issuance_conflict = r.kind == Kind::Issue
                && loan != r.loan
                && owner == r.owner
                && (exclusive || r.flag == 1);
            let write_conflict = r.kind == Kind::Set && owner == r.owner && loan != r.via;
            let read_conflict = exclusive && direct.contains(&owner);
            (issuance_conflict || write_conflict || read_conflict).then_some(loan)
        }));
        let mut seen = BTreeSet::new();
        if r.kind == Kind::Set && r.via != 0 {
            seen.insert(r.via);
            uses.push(OriginUse {
                point: r.id,
                origin: r.via,
            });
        }
        for &(loan, _) in &r.reads {
            if seen.insert(loan) {
                uses.push(OriginUse {
                    point: r.id,
                    origin: loan,
                });
            }
        }
        fact_count = fact_count.saturating_add(
            r.succ.len()
                + r.reads.len()
                + r.direct.len()
                + usize::from(r.kind == Kind::Set && r.via != 0)
                + issue.len()
                + kill.len()
                + invalidate.len(),
        );
        if fact_count > MAX_REFS {
            return Err(invalid("E_WIRE_FACT_BUDGET"));
        }
        points.push(Point {
            id: r.id,
            successors: r.succ.clone(),
            live_origins: vec![],
            subset: vec![],
            issue,
            kill,
            invalidate,
        });
    }
    let input = Input {
        template: Facts { entry, points },
        uses,
        definitions,
        phi_inputs: vec![],
    };
    let ssa = analyze_ssa(&input).map_err(BridgeError::Ssa)?;
    for (point, loan) in borrowed_use_points {
        if !ssa
            .loan_report
            .live_loans_on_entry
            .get(&point)
            .is_some_and(|loans| loans.contains(&loan))
        {
            return Err(invalid("E_WIRE_BORROWED_LOAD_HAS_NO_LIVE_LOAN"));
        }
    }
    // The input contract has no independently attested exception/conditional
    // cleanup. Reject if an inferred live loan enters such a point.
    for r in &rows {
        if (r.trap || r.conditional)
            && ssa
                .loan_report
                .live_loans_on_entry
                .get(&r.id)
                .is_some_and(|loans| !loans.is_empty())
        {
            return Err(invalid("E_WIRE_UNPROVEN_EXCEPTION_OR_CONDITIONAL"));
        }
    }
    Ok(FunctionReport {
        name,
        node_count: count,
        loan_count: owners.len(),
        ssa,
    })
}
/// Parse complete compiler-derived typed CFG evidence, then execute the
/// *actual* separate Rust SSA oracle on every closed function.
///
/// Returned reports are observations only; omitted source guest effects
/// cannot be authenticated by parsing this payload.
pub fn analyze_manifest(text: &str) -> Result<DifferentialReport, BridgeError> {
    if text.len() > MAX_BYTES || text.bytes().any(|b| b == 0 || b == b'\r') {
        return Err(invalid("E_WIRE_BYTE_BUDGET_OR_CONTROL"));
    }
    let mut lines = text.split_terminator('\n');
    if lines.next() != Some(CONTRACT) {
        return Err(invalid("E_WIRE_CONTRACT"));
    }
    let mut functions = Vec::new();
    let mut names = BTreeSet::new();
    loop {
        let line = lines.next().ok_or_else(|| invalid("E_WIRE_MISSING_END"))?;
        if line == "END" {
            if lines.next().is_some() {
                return Err(invalid("E_WIRE_TRAILING_DATA"));
            }
            break;
        }
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 4 || fields[0] != "F" {
            return Err(invalid("E_WIRE_FUNCTION_HEADER"));
        }
        let name = fields[1];
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !names.insert(name.to_string())
        {
            return Err(invalid("E_WIRE_FUNCTION_NAME"));
        }
        let entry = number(fields[2])?;
        let count = number(fields[3])? as usize;
        if count == 0 || count > MAX_POINTS || functions.len() >= MAX_FUNCTIONS {
            return Err(invalid("E_WIRE_FUNCTION_BUDGET"));
        }
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            rows.push(row(lines
                .next()
                .ok_or_else(|| invalid("E_WIRE_TRUNCATED_POINT_INVENTORY"))?)?);
        }
        functions.push(one_function(name.to_string(), entry, rows)?);
    }
    if functions.is_empty() {
        return Err(invalid("E_WIRE_NO_FUNCTIONS"));
    }
    Ok(DifferentialReport {
        contract: CONTRACT,
        functions,
    })
}
