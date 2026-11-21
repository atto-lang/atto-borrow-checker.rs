//! Native canonical checker: standalone, fails closed, no source compiler dependency.
use std::{env, fs, process};
fn main() {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: verify-actor-state-mir <compiler-report>");
        process::exit(2);
    }
    let input = match fs::read_to_string(&args[1]) {
        Ok(input) => input,
        Err(e) => { eprintln!("E_REPORT_INPUT: {e}"); process::exit(2); }
    };
    match atto_borrow_checker::actor_source_mir_v0::verify_bounded_guard_wire(&input) {
        Ok(receipt) => {
            println!("CANONICAL_ACTOR_GUARD_V0_PASS source_sha256={} fields={} events={}",
                receipt.source_sha256, receipt.field_count, receipt.event_count);
            println!("EVIDENCE_LEVEL=RESTRICTED_SOURCE_BOUND_FLAT_GUARD_ONLY; \
                FULL_CFG_NLL=NOT_VERIFIED; GUEST_CERTIFICATION=NOT_VERIFIED");
        }
        Err(e) => { eprintln!("E_CANONICAL_GUARD_IR: {e}"); process::exit(1); }
    }
}
