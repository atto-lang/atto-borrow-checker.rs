//! Host CLI for checking a real Atto compiler CFG manifest with the
//! independent canonical Rust SSA loan oracle. Never authorizes codegen.
use atto_borrow_checker::atto_compiler_cfg_bridge_v1::analyze_manifest;
use std::{fs, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [manifest] = args.as_slice() else {
        eprintln!("usage: atto-cfg-ssa-check <compiler-loan-cfg.manifest>");
        return ExitCode::from(2);
    };
    let data = match fs::read_to_string(manifest) {
        Ok(s) => s,
        Err(error) => {
            eprintln!("cannot read {manifest}: {error}");
            return ExitCode::from(2);
        }
    };
    match analyze_manifest(&data) {
        Ok(report) => {
            for function in report.functions {
                println!(
                    "SSA_DIAGNOSTIC_OK {} {} {}",
                    function.name, function.node_count, function.loan_count
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("INDEPENDENT_SSA_REJECT {error:?}");
            ExitCode::from(1)
        }
    }
}
