//! Native canonical checker: standalone, fails closed, no source compiler dependency.
use std::{env, fs, process};
fn main() {
    let args: Vec<_> = env::args_os().collect();
    let cfg_v1 = args.len() == 3 && args[1] == "--cfg-v1";
    if args.len() != 2 && !cfg_v1 {
        eprintln!("usage: verify-actor-state-mir [--cfg-v1] <compiler-report>");
        process::exit(2);
    }
    let input = match fs::read_to_string(&args[if cfg_v1 { 2 } else { 1 }]) {
        Ok(input) => input,
        Err(e) => { eprintln!("E_REPORT_INPUT: {e}"); process::exit(2); }
    };
    if cfg_v1 {
        match atto_borrow_checker::actor_source_cfg_v1::verify_bounded_diamond_wire(&input) {
            Ok(receipt) => {
                println!("CANONICAL_ACTOR_DIAMOND_V1_PASS source_sha256={} fields={} then={} else={} blocks={}",
                    receipt.source_sha256, receipt.field_count,
                    receipt.branch_events[0], receipt.branch_events[1],
                    receipt.reachable_blocks);
                println!("EVIDENCE_LEVEL=RESTRICTED_LITERAL_DIAMOND_ONLY; FULL_CFG_NLL=NOT_VERIFIED");
            }
            Err(error) => { eprintln!("E_CANONICAL_CFG_V1: {error}"); process::exit(1); }
        }
        return;
    }
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
