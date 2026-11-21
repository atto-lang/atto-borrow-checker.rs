//! Host CLI for checking a real Atto compiler CFG manifest with the
//! independent canonical Rust SSA loan oracle. Never authorizes codegen.
//! "-" reads a bounded compiler manifest from stdin for token-free CLI piping.
use atto_borrow_checker::atto_compiler_cfg_bridge_v1::analyze_manifest;
use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

fn read_limited(mut input: impl Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read loan CFG manifest: {error}"))?;
    if bytes.is_empty() {
        return Err("loan CFG manifest is empty".into());
    }
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("loan CFG manifest exceeds 8 MiB limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "loan CFG manifest is not UTF-8".into())
}

fn read_manifest(path: &str) -> Result<String, String> {
    if path == "-" {
        return read_limited(io::stdin().lock());
    }
    let file = File::open(path).map_err(|error| format!("cannot open {path}: {error}"))?;
    read_limited(file)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [manifest] = args.as_slice() else {
        eprintln!("usage: atto-cfg-ssa-check <compiler-loan-cfg.manifest | ->");
        return ExitCode::from(2);
    };
    let data = match read_manifest(manifest) {
        Ok(s) => s,
        Err(error) => {
            eprintln!("atto-cfg-ssa-check: {error}");
            return ExitCode::from(2);
        }
    };
    match analyze_manifest(&data) {
        Ok(report) if report.functions.is_empty() => {
            eprintln!("INDEPENDENT_SSA_REJECT E_NO_FUNCTIONS");
            ExitCode::from(1)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_manifest() {
        assert_eq!(
            read_limited(&b""[..]).unwrap_err(),
            "loan CFG manifest is empty"
        );
    }

    #[test]
    fn accepts_bounded_utf8_manifest() {
        assert_eq!(
            read_limited(&b"ATTO_LOAN_CFG_V1\n"[..]).unwrap(),
            "ATTO_LOAN_CFG_V1\n"
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(
            read_limited(&[0xff, 0x80][..]).unwrap_err(),
            "loan CFG manifest is not UTF-8"
        );
    }

    #[test]
    fn rejects_manifest_over_budget() {
        let oversized = vec![b'a'; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            read_limited(oversized.as_slice()).unwrap_err(),
            "loan CFG manifest exceeds 8 MiB limit"
        );
    }
}
