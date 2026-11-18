//! These tests use a closed wire fixture whose point topology matches a
//! compiler-lowered scalar borrow. Live end-to-end compiler fixtures are run
//! in a separate SHA-bound CI composition, not invented by this unit test.
use atto_borrow_checker::atto_compiler_cfg_bridge_v1::{analyze_manifest, BridgeError, CONTRACT};

fn basic() -> String {
    format!(
        "{CONTRACT}\n\
F|main|7|7\n\
P|1|R|0|0|0|0|-|-|0|0|0\n\
P|2|S|0|0|0|0|1|-|-|0|0\n\
P|3|E|1|0|0|0|2|-|-|0|0\n\
P|4|S|0|1|0|0|3|1:0|-|0|0\n\
P|5|M|1|0|0|0|4|-|-|0|0\n\
P|6|I|1|0|0|0|5|-|-|0|0\n\
P|7|S|0|0|0|0|6|-|-|0|0\n\
END\n"
    )
}
fn replace_once(before: &str, after: &str) -> String {
    let source = basic();
    assert_eq!(source.matches(before).count(), 1);
    source.replace(before, after)
}
fn invalid(result: Result<impl std::fmt::Debug, BridgeError>) {
    assert!(
        result.is_err(),
        "malformed or unsafe compiler evidence must reject"
    );
}
#[test]
fn independent_ssa_check_accepts_closed_compiler_shaped_scalar_borrow() {
    let report = analyze_manifest(&basic()).unwrap();
    assert_eq!(report.contract, CONTRACT);
    assert_eq!(report.functions.len(), 1);
    let main = &report.functions[0];
    assert_eq!(main.name, "main");
    assert_eq!(main.node_count, 7);
    assert_eq!(main.loan_count, 1);
    assert!(main.ssa.inference_steps > 0);
    assert!(main.ssa.loan_report.live_loans_on_entry[&4].contains(&1));
    assert!(!main.ssa.loan_report.live_loans_on_entry[&2].contains(&1));
}
#[test]
fn early_loan_end_before_real_guest_use_fails_independent_liveness() {
    // Exact same issue, read, and end but rewire to execute End before
    // the typed LoanRead: issuance -> marker -> end -> use -> owner store.
    let mut source = basic();
    source = source.replace("P|5|M|1|0|0|0|4|-|-|0|0", "P|5|M|1|0|0|0|3|-|-|0|0");
    source = source.replace("P|3|E|1|0|0|0|2|-|-|0|0", "P|3|E|1|0|0|0|4|-|-|0|0");
    source = source.replace("P|4|S|0|1|0|0|3|1:0|-|0|0", "P|4|S|0|1|0|0|2|1:0|-|0|0");
    invalid(analyze_manifest(&source));
}
#[test]
fn missing_borrowed_load_origin_is_not_implicitly_inferred() {
    let s = replace_once("P|4|S|0|1|0|0|3|1:0|-|0|0", "P|4|S|0|1|0|0|3|9:0|-|0|0");
    invalid(analyze_manifest(&s));
}
#[test]
fn wrong_borrowed_owner_is_rejected() {
    let s = replace_once("P|4|S|0|1|0|0|3|1:0|-|0|0", "P|4|S|0|1|0|0|3|1:999|-|0|0");
    invalid(analyze_manifest(&s));
}
#[test]
fn unknown_cfg_edge_fails_closed() {
    let s = replace_once("P|6|I|1|0|0|0|5|-|-|0|0", "P|6|I|1|0|0|0|999|-|-|0|0");
    invalid(analyze_manifest(&s));
}
#[test]
fn duplicate_instruction_id_and_truncated_census_fail_closed() {
    let s = replace_once("P|7|S|0|0|0|0|6|-|-|0|0", "P|6|S|0|0|0|0|6|-|-|0|0");
    invalid(analyze_manifest(&s));
    let s = basic().replace("P|3|E|1|0|0|0|2|-|-|0|0\n", "");
    invalid(analyze_manifest(&s));
}
#[test]
fn unknown_kind_wrong_version_and_surplus_rows_reject() {
    let s = replace_once("P|5|M|1|0|0|0|4|-|-|0|0", "P|5|X|1|0|0|0|4|-|-|0|0");
    invalid(analyze_manifest(&s));
    invalid(analyze_manifest(&basic().replacen(
        CONTRACT,
        "ATTO_LOAN_CFG_V0",
        1,
    )));
    invalid(analyze_manifest(&(basic() + "P|8|R|0|0|0|0|-|-|-|0|0\n")));
}
#[test]
fn byte_budget_rejects_before_parser_work() {
    let huge = "x".repeat(1_048_577);
    invalid(analyze_manifest(&huge));
}
#[test]
fn write_before_last_borrow_use_is_detected() {
    // Move owner store to before the actual typed loan use; leave the
    // original End downstream, so independent SSA liveness must see the
    // offending active loan when invalidating that owner.
    let mut source = basic();
    source = source.replace("P|5|M|1|0|0|0|4|-|-|0|0", "P|5|M|1|0|0|0|2|-|-|0|0");
    source = source.replace("P|2|S|0|0|0|0|1|-|-|0|0", "P|2|S|0|0|0|0|4|-|-|0|0");
    source = source.replace("P|4|S|0|1|0|0|3|1:0|-|0|0", "P|4|S|0|1|0|0|3|1:0|-|0|0");
    source = source.replace("P|3|E|1|0|0|0|2|-|-|0|0", "P|3|E|1|0|0|0|1|-|-|0|0");
    invalid(analyze_manifest(&source));
}
