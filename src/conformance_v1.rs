//! Backend conformance against the canonical checker.
//!
//! Three levels (see `docs/CONFORMANCE_PLAN.md`):
//!
//! - **L1 graph**: every backend's in-pass ownership engine and this canonical
//!   checker produce the same verdict and the *exact* canonical code on the
//!   shared source-free corpus `conformance/graph-cases-v1.json`.
//! - **L2 source**: backends compile the `.atto` corpus owned by
//!   `atto-platform-conformance` (BCV1); verdicts compare at *family* level.
//! - **L3 cross-verification**: for each compiled function a backend exports
//!   its own verdict plus the `atto-borrow-mir-v1` graph it derived; the
//!   canonical checker re-verifies the graph and classifies any disagreement.
//!
//! This module computes classifications only. It never upgrades a result to
//! guest execution or certification: a model-level AGREE says the backend's
//! exported graph and verdict are consistent, not that its codegen is safe.

use crate::mir_v1::{self, MirError};
use crate::wire_v1::{self, Fields, Json, WireError, WireGraph, WireMir, UNSUPPORTED_EFFECT};
use crate::{verify, Diagnostic, Proof};

pub const GRAPH_CASES_SCHEMA: &str = "atto-borrow-graph-cases-v1";
/// Older vendored copies in each backend repository use this schema name.
pub const LEGACY_GRAPH_CASES_SCHEMA: &str = "atto-borrow-conformance-v1";
pub const GRAPH_RESULTS_SCHEMA: &str = "atto-borrow-graph-results-v1";
pub const BACKEND_REPORT_SCHEMA: &str = "atto-borrow-backend-report-v1";

/// The backend repositories (`atto-lang/atto-source.<name>`) in scope.
pub const BACKENDS: &[&str] = &[
    "java",
    "llvm",
    "net",
    "wasm",
    "forge",
    "cranelift",
    "js",
    "rs",
    "hdl",
];

// ---------------------------------------------------------------------------
// Diagnostic registry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeClass {
    /// A genuine ownership error in the user's program.
    Semantic,
    /// A conservative reject of the restricted canonical model (loops,
    /// divergent joins, unrepresentable effects). Not a language rule, and
    /// never evidence for or against a backend.
    ModelLimit,
    /// Malformed graph or MIR: a correct source frontend can never produce it.
    /// Seeing one from a backend export is an adapter defect.
    Adapter,
    /// Analysis budget exhausted; fail closed, never evidence.
    Budget,
}

impl CodeClass {
    pub fn name(self) -> &'static str {
        return match self {
            CodeClass::Semantic => "SEMANTIC",
            CodeClass::ModelLimit => "MODEL_LIMIT",
            CodeClass::Adapter => "ADAPTER",
            CodeClass::Budget => "BUDGET",
        };
    }
}

/// One canonical diagnostic code.
///
/// `families` are the coarse source-level codes used by the `.atto` corpus
/// (BCV1 in `atto-platform-conformance`) and by backend compilers such as
/// `attoc`. A backend's source-level reject conforms when its code is either
/// the canonical code itself or one of these families.
#[derive(Clone, Copy, Debug)]
pub struct CodeInfo {
    pub code: &'static str,
    pub class: CodeClass,
    pub families: &'static [&'static str],
}

const fn semantic(code: &'static str, families: &'static [&'static str]) -> CodeInfo {
    return CodeInfo {
        code,
        class: CodeClass::Semantic,
        families,
    };
}

const fn of(code: &'static str, class: CodeClass) -> CodeInfo {
    return CodeInfo {
        code,
        class,
        families: &[],
    };
}

/// Every code the canonical checker (V0 + MIR V1 envelope) can emit.
/// `tests/conformance_registry_v1.rs` fails if a code is added without a row.
pub const REGISTRY: &[CodeInfo] = &[
    // Moves, drops, copies.
    semantic("E_USE_AFTER_MOVE_OR_DROP", &["E_MOVED", "E_DROPPED"]),
    semantic(
        "E_COPY_PROOF_REQUIRED",
        &["E_COPY_SHALLOW_ALIAS", "E_MOVED"],
    ),
    semantic("E_DEEP_COPY_PROOF_REQUIRED", &["E_COPY_GRAPH_UNPROVEN"]),
    // Loans.
    semantic("E_BORROW_CONFLICT", &["E_BORROW", "E_SHARE_ALIAS"]),
    semantic("E_MUT_LOAN_REQUIRED", &["E_BORROW", "E_MUTABILITY"]),
    semantic("E_LOAN_ESCAPE", &["E_BORROW", "E_LIFETIME"]),
    semantic("E_SUSPEND_WITH_LIVE_LOAN", &["E_LOAN_SUSPEND"]),
    // Freeze / share / weak / pin.
    semantic("E_FROZEN_WRITE", &["E_SHARED_MUTATION"]),
    semantic("E_FROZEN_BORROW_MUT", &["E_SHARED_MUTATION", "E_BORROW"]),
    semantic("E_DEEP_FREEZE_PROOF_REQUIRED", &["E_SHARE_ALIAS"]),
    semantic("E_SHARED_FROZEN_PROOF_REQUIRED", &["E_SHARE_ALIAS"]),
    semantic("E_WEAK_GENERATION_PROOF_REQUIRED", &["E_WEAK_PROVENANCE"]),
    semantic("E_WEAK_SHARED_REGION_REQUIRED", &["E_WEAK_PROVENANCE"]),
    semantic("E_PIN_ADDRESS_PROOF_REQUIRED", &["E_PIN"]),
    semantic("E_ALREADY_PINNED", &["E_PIN"]),
    semantic("E_PIN_RELOCATION", &["E_PIN"]),
    semantic("E_PIN_BOUNDARY_TRANSFER", &["E_PIN_BOUNDARY_TRANSFER"]),
    semantic("E_PIN_STORAGE_TRANSFER", &["E_PIN_BOUNDARY_TRANSFER"]),
    // Tasks and actors.
    semantic("E_TASK_CAPTURE_PROOF", &["E_TASK_CAPTURE"]),
    semantic("E_ACTOR_BORROW_ESCAPE", &["E_ACTOR_LOAN_ESCAPE"]),
    semantic("E_ACTOR_SEND_PROOF_REQUIRED", &["E_ACTOR_SEND"]),
    semantic("E_ACTOR_COPY_SEND_PROOF_REQUIRED", &["E_ACTOR_SEND"]),
    semantic("E_ACTOR_SEND_PENDING", &["E_ACTOR_SEND"]),
    semantic("E_ACTOR_SEND_UNRESOLVED", &["E_ACTOR_SEND"]),
    // Restricted-model limits.
    of("E_CFG_CYCLE_UNPROVEN", CodeClass::ModelLimit),
    of("E_CFG_JOIN_UNPROVEN", CodeClass::ModelLimit),
    of(UNSUPPORTED_EFFECT, CodeClass::ModelLimit),
    // Malformed graph / identities.
    of("E_CFG_DUPLICATE_BLOCK", CodeClass::Adapter),
    of("E_CFG_EDGE", CodeClass::Adapter),
    of("E_CFG_ENTRY", CodeClass::Adapter),
    of("E_CFG_UNREACHABLE", CodeClass::Adapter),
    of("E_IMPLICIT_EXIT", CodeClass::Adapter),
    of("E_RETURN_WITH_SUCCESSOR", CodeClass::Adapter),
    of("E_OWNER_DEF_REUSED", CodeClass::Adapter),
    of("E_OWNER_ID_REUSED_OR_BUDGET", CodeClass::Adapter),
    of("E_OWNER_ID_ZERO", CodeClass::Adapter),
    of("E_LOAN_DEF_REUSED", CodeClass::Adapter),
    of("E_LOAN_ID_REUSED", CodeClass::Adapter),
    of("E_LOAN_ID_ZERO", CodeClass::Adapter),
    of("E_UNKNOWN_LOAN", CodeClass::Adapter),
    of("E_REGION_DEF_REUSED", CodeClass::Adapter),
    of("E_REGION_ID_ZERO", CodeClass::Adapter),
    of("E_WEAK_DEF_REUSED", CodeClass::Adapter),
    of("E_WEAK_ID_REUSED_OR_BUDGET", CodeClass::Adapter),
    of("E_WEAK_ID_ZERO", CodeClass::Adapter),
    of("E_UNKNOWN_WEAK", CodeClass::Adapter),
    of("E_SEND_TICKET_DEF_REUSED", CodeClass::Adapter),
    of("E_SEND_TICKET_ID_ZERO", CodeClass::Adapter),
    of("E_SEND_TICKET_REUSED", CodeClass::Adapter),
    of("E_UNKNOWN_ACTOR_SEND_TICKET", CodeClass::Adapter),
    // MIR V1 envelope.
    of("E_MIR_VERSION", CodeClass::Adapter),
    of("E_MIR_PRODUCER", CodeClass::Adapter),
    of("E_MIR_DUPLICATE_EXPECTED_ID", CodeClass::Adapter),
    of("E_MIR_DUPLICATE_OR_MISSING_ID", CodeClass::Adapter),
    of("E_MIR_EFFECT_MISMATCH", CodeClass::Adapter),
    of("E_MIR_INCOMPLETE_INVENTORY", CodeClass::Adapter),
    // Budgets.
    of("E_CFG_BUDGET", CodeClass::Budget),
    of("E_LOAN_BUDGET", CodeClass::Budget),
    of("E_OWNER_ID_BUDGET", CodeClass::Budget),
    of("E_REGION_BUDGET", CodeClass::Budget),
    of("E_WEAK_BUDGET", CodeClass::Budget),
    of("E_SEND_TICKET_BUDGET", CodeClass::Budget),
    of("E_SHADOW_EVENT_BUDGET", CodeClass::Budget),
    of("E_MIR_CFG_BUDGET", CodeClass::Budget),
    of("E_MIR_INVENTORY_BUDGET", CodeClass::Budget),
];

pub fn code_info(code: &str) -> Option<&'static CodeInfo> {
    return REGISTRY.iter().find(|info| info.code == code);
}

/// All source-level ownership family codes known to the registry.
pub fn ownership_families() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = REGISTRY
        .iter()
        .flat_map(|info| info.families.iter().copied())
        .collect();
    out.sort_unstable();
    out.dedup();
    return out;
}

/// Is `local` (a backend's code) an acceptable spelling of canonical `code`?
pub fn code_conforms(local: &str, canonical: &str) -> bool {
    if local == canonical {
        return true;
    }
    return code_info(canonical).is_some_and(|info| info.families.contains(&local));
}

/// Does a backend code denote an ownership error at all (canonical or family)?
pub fn is_ownership_code(code: &str) -> bool {
    return code_info(code).is_some() || ownership_families().contains(&code);
}

// ---------------------------------------------------------------------------
// Canonical verdicts
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept(Proof),
    Reject {
        code: String,
        block: Option<u32>,
        operation: Option<usize>,
    },
}

impl Verdict {
    fn from_diagnostic(diagnostic: Diagnostic) -> Self {
        return Verdict::Reject {
            code: diagnostic.code.to_string(),
            block: Some(diagnostic.block),
            operation: Some(diagnostic.operation),
        };
    }

    pub fn code(&self) -> Option<&str> {
        return match self {
            Verdict::Accept(_) => None,
            Verdict::Reject { code, .. } => Some(code),
        };
    }

    pub fn is_accept(&self) -> bool {
        return matches!(self, Verdict::Accept(_));
    }

    pub fn to_json(&self) -> Json {
        match self {
            Verdict::Accept(proof) => Json::Obj(vec![
                ("verdict".into(), Json::Str("accept".into())),
                ("code".into(), Json::Null),
                (
                    "cleanupByExit".into(),
                    Json::Obj(
                        proof
                            .cleanup_by_exit
                            .iter()
                            .map(|(block, owners)| {
                                (
                                    block.to_string(),
                                    Json::Arr(
                                        owners.iter().map(|&o| Json::Int(u64::from(o))).collect(),
                                    ),
                                )
                            })
                            .collect(),
                    ),
                ),
            ]),
            Verdict::Reject {
                code,
                block,
                operation,
            } => Json::Obj(vec![
                ("verdict".into(), Json::Str("reject".into())),
                ("code".into(), Json::Str(code.clone())),
                (
                    "class".into(),
                    Json::Str(
                        code_info(code)
                            .map(|info| info.class.name())
                            .unwrap_or("UNREGISTERED")
                            .into(),
                    ),
                ),
                (
                    "block".into(),
                    block.map_or(Json::Null, |b| Json::Int(u64::from(b))),
                ),
                (
                    "operation".into(),
                    operation.map_or(Json::Null, |o| Json::Int(o as u64)),
                ),
            ]),
        }
    }
}

pub fn verdict_for_graph(graph: &WireGraph) -> Verdict {
    return match graph.to_program() {
        Err((block, operation, _kind)) => Verdict::Reject {
            code: UNSUPPORTED_EFFECT.to_string(),
            block: Some(block),
            operation: Some(operation),
        },
        Ok(program) => match verify(&program) {
            Ok(proof) => Verdict::Accept(proof),
            Err(diagnostic) => Verdict::from_diagnostic(diagnostic),
        },
    };
}

pub fn verdict_for_mir(mir: &WireMir) -> Verdict {
    if let Some((block, _instruction, _kind)) = mir.unsupported.first() {
        return Verdict::Reject {
            code: UNSUPPORTED_EFFECT.to_string(),
            block: Some(*block),
            operation: None,
        };
    }
    return match mir_v1::verify_mir(&mir.function) {
        Ok(proof) => Verdict::Accept(proof),
        Err(MirError::Unsafe(diagnostic)) => Verdict::from_diagnostic(diagnostic),
        Err(MirError::Invalid(code)) => Verdict::Reject {
            code: code.to_string(),
            block: None,
            operation: None,
        },
    };
}

// ---------------------------------------------------------------------------
// L1: graph corpus
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GraphCase {
    pub id: String,
    pub category: String,
    pub expect_accept: bool,
    pub diagnostic: Option<String>,
    pub graph: WireGraph,
}

#[derive(Clone, Debug)]
pub struct GraphCorpus {
    pub schema: String,
    pub cases: Vec<GraphCase>,
}

pub fn decode_graph_corpus(value: &Json) -> Result<GraphCorpus, WireError> {
    let mut f = Fields::of(value, "")?;
    let schema = f.str("schema")?.to_string();
    if schema != GRAPH_CASES_SCHEMA && schema != LEGACY_GRAPH_CASES_SCHEMA {
        return Err(WireError {
            message: format!("unsupported corpus schema {schema:?}"),
            at: "schema".into(),
        });
    }
    let mut cases: Vec<GraphCase> = Vec::new();
    for (index, case) in f.arr("cases")?.iter().enumerate() {
        let at = format!("cases[{index}]");
        let mut cf = Fields::of(case, &at)?;
        let id = cf.str("id")?.to_string();
        if cases.iter().any(|c| c.id == id) {
            return Err(WireError {
                message: format!("duplicate case id {id:?}"),
                at,
            });
        }
        let category = cf.str("category")?.to_string();
        let expect_path = cf.path("expected");
        let expect_accept = match cf.str("expected")? {
            "accept" => true,
            "reject" => false,
            _ => {
                return Err(WireError {
                    message: "expected accept or reject".into(),
                    at: expect_path,
                })
            }
        };
        let diagnostic = cf.opt_str("diagnostic")?.map(str::to_string);
        if expect_accept == diagnostic.is_some() {
            return Err(WireError {
                message: "accept cases carry no diagnostic; reject cases need one".into(),
                at: cf.path("diagnostic"),
            });
        }
        let graph_path = cf.path("graph");
        let graph = wire_v1::decode_graph(cf.req("graph")?, &graph_path)?;
        cf.finish_allowing(&["note", "spec"])?;
        cases.push(GraphCase {
            id,
            category,
            expect_accept,
            diagnostic,
            graph,
        });
    }
    // Header metadata (backends, evidence policy, ...) is descriptive only.
    f.finish_allowing(&[
        "version",
        "rustCanonical",
        "javaShadow",
        "scope",
        "certification",
        "backends",
        "evidence",
        "evidencePolicy",
        "note",
    ])?;
    return Ok(GraphCorpus { schema, cases });
}

#[derive(Clone, Debug)]
pub struct GraphCaseOutcome {
    pub id: String,
    pub expected: Option<String>,
    pub actual: Verdict,
    pub conforms: bool,
}

/// Run the canonical checker itself over the corpus (L1 self-conformance).
pub fn run_graph_corpus(corpus: &GraphCorpus) -> Vec<GraphCaseOutcome> {
    return corpus
        .cases
        .iter()
        .map(|case| {
            let actual = verdict_for_graph(&case.graph);
            let conforms = match (&actual, case.expect_accept) {
                (Verdict::Accept(_), true) => true,
                (Verdict::Reject { code, .. }, false) => case.diagnostic.as_deref() == Some(code),
                _ => false,
            };
            GraphCaseOutcome {
                id: case.id.clone(),
                expected: case.diagnostic.clone(),
                actual,
                conforms,
            }
        })
        .collect();
}

/// One backend engine's L1 result for one corpus case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphResult {
    pub backend: String,
    pub case: String,
    pub accept: bool,
    pub code: Option<String>,
    /// The engine cannot represent an op in this case and says so instead of
    /// guessing. Coverage gap, not a semantic result.
    pub unsupported: bool,
}

pub fn decode_graph_result(value: &Json) -> Result<GraphResult, WireError> {
    let mut f = Fields::of(value, "")?;
    let schema = f.str("schema")?;
    if schema != GRAPH_RESULTS_SCHEMA {
        return Err(WireError {
            message: format!("expected schema {GRAPH_RESULTS_SCHEMA}"),
            at: "schema".into(),
        });
    }
    let backend = f.str("backend")?.to_string();
    let case = f.str("case")?.to_string();
    let (accept, unsupported) = match f.str("verdict")? {
        "accept" => (true, false),
        "reject" => (false, false),
        "unsupported" => (false, true),
        _ => {
            return Err(WireError {
                message: "expected accept, reject or unsupported".into(),
                at: "verdict".into(),
            })
        }
    };
    let code = f.opt_str("code")?.map(str::to_string);
    if (accept || unsupported) == code.is_some() {
        return Err(WireError {
            message: "only reject carries a code".into(),
            at: "code".into(),
        });
    }
    f.finish_allowing(&["message", "note", "reason"])?;
    return Ok(GraphResult {
        backend,
        case,
        accept,
        code,
        unsupported,
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphResultClass {
    Conforms,
    WrongVerdict,
    WrongCode,
    /// The corpus has a case for which the backend reported nothing.
    Missing,
    /// The backend reported a case id the corpus does not contain.
    UnknownCase,
    /// The backend reported the same case more than once.
    Duplicate,
    /// The engine declared it cannot represent this case.
    Unsupported,
}

impl GraphResultClass {
    pub fn name(&self) -> &'static str {
        return match self {
            GraphResultClass::Conforms => "CONFORMS",
            GraphResultClass::WrongVerdict => "WRONG_VERDICT",
            GraphResultClass::WrongCode => "WRONG_CODE",
            GraphResultClass::Missing => "MISSING",
            GraphResultClass::UnknownCase => "UNKNOWN_CASE",
            GraphResultClass::Duplicate => "DUPLICATE",
            GraphResultClass::Unsupported => "UNSUPPORTED",
        };
    }

    /// UNSUPPORTED is a tolerated coverage gap unless `require_full`.
    pub fn fails(&self, require_full: bool) -> bool {
        return match self {
            GraphResultClass::Conforms => false,
            GraphResultClass::Unsupported => require_full,
            _ => true,
        };
    }
}

/// Compare one backend's engine results to the corpus. L1 requires the exact
/// canonical code, not merely the family: the engine runs the same abstract
/// graph, so there is no source-level ambiguity to absorb.
pub fn compare_graph_results(
    corpus: &GraphCorpus,
    results: &[GraphResult],
) -> Vec<(String, GraphResultClass)> {
    let mut out = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for result in results {
        if seen.contains(&result.case.as_str()) {
            out.push((result.case.clone(), GraphResultClass::Duplicate));
            continue;
        }
        seen.push(&result.case);
        let Some(case) = corpus.cases.iter().find(|c| c.id == result.case) else {
            out.push((result.case.clone(), GraphResultClass::UnknownCase));
            continue;
        };
        let class = if result.unsupported {
            GraphResultClass::Unsupported
        } else if case.expect_accept != result.accept {
            GraphResultClass::WrongVerdict
        } else if case.diagnostic != result.code {
            GraphResultClass::WrongCode
        } else {
            GraphResultClass::Conforms
        };
        out.push((case.id.clone(), class));
    }
    for case in &corpus.cases {
        if !seen.contains(&case.id.as_str()) {
            out.push((case.id.clone(), GraphResultClass::Missing));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// L3: backend report cross-verification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct LocalVerdict {
    pub accept: bool,
    pub code: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BackendRecord {
    pub backend: String,
    pub compiler_git_sha: String,
    pub source_path: String,
    pub case: Option<String>,
    pub function: String,
    pub local: LocalVerdict,
    pub mir: Result<WireMir, String>,
}

pub fn decode_backend_record(value: &Json) -> Result<BackendRecord, WireError> {
    let mut f = Fields::of(value, "")?;
    let schema = f.str("schema")?;
    if schema != BACKEND_REPORT_SCHEMA {
        return Err(WireError {
            message: format!("expected schema {BACKEND_REPORT_SCHEMA}"),
            at: "schema".into(),
        });
    }
    let backend = f.str("backend")?.to_string();
    if !BACKENDS.contains(&backend.as_str()) {
        return Err(WireError {
            message: format!("unknown backend {backend:?}"),
            at: "backend".into(),
        });
    }
    let compiler_git_sha = f.str("compilerGitSha")?.to_string();
    let source_path = f.str("sourcePath")?.to_string();
    let case = f.opt_str("case")?.map(str::to_string);
    let function = f.str("function")?.to_string();

    let local_path = f.path("local");
    let mut lf = Fields::of(f.req("local")?, &local_path)?;
    let accept = match lf.str("verdict")? {
        "accept" => true,
        "reject" => false,
        _ => {
            return Err(WireError {
                message: "expected accept or reject".into(),
                at: lf.path("verdict"),
            })
        }
    };
    let code = lf.opt_str("code")?.map(str::to_string);
    if accept == code.is_some() {
        return Err(WireError {
            message: "accept carries no code; reject needs one".into(),
            at: lf.path("code"),
        });
    }
    lf.finish_allowing(&["message"])?;

    let mir = match (f.opt("mir"), f.opt_str("mirUnavailable")?) {
        (Some(mir), None) => Ok(wire_v1::decode_mir(mir, "mir")?),
        (None, Some(reason)) => Err(reason.to_string()),
        _ => {
            return Err(WireError {
                message: "exactly one of mir / mirUnavailable is required".into(),
                at: "mir".into(),
            })
        }
    };
    f.finish_allowing(&["note"])?;
    return Ok(BackendRecord {
        backend,
        compiler_git_sha,
        source_path,
        case,
        function,
        local: LocalVerdict { accept, code },
        mir,
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossClass {
    /// Same verdict; for rejects the local code is the canonical code or one
    /// of its families.
    Agree,
    /// UNSOUND: the backend accepted a graph the canonical checker rejects
    /// for a semantic reason. Always a failure.
    BackendPermissive,
    /// The backend rejected what the canonical checker accepts. Conservative
    /// but non-conformant; a failure unless explicitly tolerated.
    BackendStricter,
    /// Both reject, but the backend's code is not a family of the canonical one.
    CodeMismatch,
    /// The exported graph is malformed (identity reuse, bad inventory, ...).
    AdapterDefect,
    /// Canonical model limit or budget: no evidence either way.
    OutOfScope,
    /// The backend rejected for a non-ownership reason (syntax, types, ...).
    NonOwnershipReject,
    /// No MIR exported: no cross-verification evidence.
    NotExported,
}

impl CrossClass {
    pub fn name(&self) -> &'static str {
        return match self {
            CrossClass::Agree => "AGREE",
            CrossClass::BackendPermissive => "BACKEND_PERMISSIVE",
            CrossClass::BackendStricter => "BACKEND_STRICTER",
            CrossClass::CodeMismatch => "CODE_MISMATCH",
            CrossClass::AdapterDefect => "ADAPTER_DEFECT",
            CrossClass::OutOfScope => "OUT_OF_SCOPE",
            CrossClass::NonOwnershipReject => "NON_OWNERSHIP_REJECT",
            CrossClass::NotExported => "NOT_EXPORTED",
        };
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CrossPolicy {
    /// Treat BACKEND_STRICTER as tolerated rather than failing.
    pub allow_stricter: bool,
    /// Treat NOT_EXPORTED as failing (use once a backend claims full export).
    pub require_mir: bool,
}

impl CrossClass {
    pub fn fails(&self, policy: CrossPolicy) -> bool {
        return match self {
            CrossClass::Agree | CrossClass::OutOfScope | CrossClass::NonOwnershipReject => false,
            CrossClass::BackendStricter => !policy.allow_stricter,
            CrossClass::NotExported => policy.require_mir,
            CrossClass::BackendPermissive
            | CrossClass::CodeMismatch
            | CrossClass::AdapterDefect => true,
        };
    }
}

pub fn classify(local: &LocalVerdict, canonical: Option<&Verdict>) -> CrossClass {
    if !local.accept {
        let code = local.code.as_deref().unwrap_or_default();
        if !is_ownership_code(code) {
            return CrossClass::NonOwnershipReject;
        }
    }
    let Some(canonical) = canonical else {
        return CrossClass::NotExported;
    };
    let canonical_class = canonical
        .code()
        .map(|code| code_info(code).map_or(CodeClass::Adapter, |info| info.class));
    match canonical_class {
        Some(CodeClass::Adapter) => return CrossClass::AdapterDefect,
        Some(CodeClass::ModelLimit | CodeClass::Budget) => return CrossClass::OutOfScope,
        Some(CodeClass::Semantic) | None => {}
    }
    return match (local.accept, canonical) {
        (true, Verdict::Accept(_)) => CrossClass::Agree,
        (true, Verdict::Reject { .. }) => CrossClass::BackendPermissive,
        (false, Verdict::Accept(_)) => CrossClass::BackendStricter,
        (false, Verdict::Reject { code, .. }) => {
            if code_conforms(local.code.as_deref().unwrap_or_default(), code) {
                CrossClass::Agree
            } else {
                CrossClass::CodeMismatch
            }
        }
    };
}

pub fn cross_check(record: &BackendRecord) -> (Option<Verdict>, CrossClass) {
    let canonical = record.mir.as_ref().ok().map(verdict_for_mir);
    let class = classify(&record.local, canonical.as_ref());
    return (canonical, class);
}
