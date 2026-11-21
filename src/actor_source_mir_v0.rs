//! Strict consumer of compiler-exported restricted actor-state guard events.
//!
//! The event set is source-derived but NOT authenticated independently of
//! compiler lowering. CI MUST verify actual source bytes, producer commit and
//! that no unreported effects or emitted code exist. This module does not
//! prove transitive effects, CFG joins, NLL or executable actor guest safety.
use crate::cyclic_v1::{self, Block, LoanKind, Op, Place, Program, Root};

const MAX_BYTES: usize = 64 * 1024;
const MAX_EVENTS: usize = 512;
const MAX_FIELDS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardReceipt {
    pub source_sha256: String,
    pub event_count: usize,
    pub field_count: usize,
}

fn parse_uint(text: &str) -> Result<usize, &'static str> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) ||
       (text.len() > 1 && text.starts_with('0')) {
        return Err("noncanonical integer");
    }
    text.parse::<usize>().map_err(|_| "integer overflows")
}

fn fields<'a>(line: &'a str, prefix: &str, expected: usize) -> Result<Vec<&'a str>, &'static str> {
    let v: Vec<_> = line.split('\t').collect();
    if v.len() != expected || v[0] != prefix {
        return Err("invalid or unexpected event record");
    }
    Ok(v)
}

/// Reject unknown fields, malformed/oversized reports, forbidden writes, and
/// event lifetimes before running the independent Rust cyclic borrow oracle.
pub fn verify_bounded_guard_wire(input: &str) -> Result<GuardReceipt, String> {
    if input.is_empty() || input.len() > MAX_BYTES ||
       input.bytes().any(|b| b == b'\r' || b == b'\0') || !input.ends_with('\n') {
        return Err("invalid bounded report bytes".into());
    }
    let mut ls = input.lines();
    let first = fields(ls.next().ok_or("no wire header")?, "ATTO_ACTOR_STATE_MIR_V0", 2)?;
    let digest = first[1];
    if digest.len() != 64 ||
       !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid source digest".into());
    }
    let root = fields(ls.next().ok_or("missing root")?, "ROOT", 3)?;
    if root[1] != "1" {
        return Err("invalid root identity".into());
    }
    let count = parse_uint(root[2])?;
    if count == 0 || count > MAX_FIELDS {
        return Err("invalid bounded concrete field count".into());
    }
    let loan = fields(ls.next().ok_or("missing loan")?, "LOAN", 3)?;
    if loan[1] != "1" {
        return Err("invalid loan identity".into());
    }
    let exclusive = match loan[2] {
        "EXCLUSIVE" => true,
        "SHARED" => false,
        _ => return Err("unknown loan kind".into()),
    };
    let mut ops = vec![Op::Borrow {
        loan: 1, place: Place::root(1),
        kind: if exclusive { LoanKind::Exclusive } else { LoanKind::Shared },
    }];
    let mut event_count = 0;
    loop {
        let line = ls.next().ok_or("missing end loan")?;
        if line == "END\t1" {
            break;
        }
        if event_count >= MAX_EVENTS {
            return Err("bounded event budget exceeded".into());
        }
        let v: Vec<_> = line.split('\t').collect();
        if v.len() != 4 {
            return Err("invalid state access record".into());
        }
        let field = parse_uint(v[1])?;
        let line_no = parse_uint(v[2])?;
        let col = parse_uint(v[3])?;
        if field >= count || line_no == 0 || col == 0 {
            return Err("field out of bounds or absent source position".into());
        }
        match v[0] {
            "READ" => ops.push(Op::ReadThrough(1)),
            "WRITE" if exclusive => ops.push(Op::WriteThrough(1)),
            "WRITE" => return Err("write through a shared guard".into()),
            _ => return Err("unknown actor-state effect".into()),
        }
        event_count += 1;
    }
    if event_count == 0 || ls.next() != Some("DONE") || ls.next().is_some() {
        return Err("empty or unterminated event inventory".into());
    }
    ops.push(Op::EndLoan(1));
    let ir = Program {
        roots: vec![Root { id: 1, is_copy: false, is_transferable: false }],
        blocks: vec![Block { id: 0, ops, successors: vec![] }],
        entry: 0,
    };
    cyclic_v1::check(&ir).map_err(|e| format!(
        "canonical borrow checker rejected guard events: {:?}, block {}, op {}",
        e.code, e.block, e.operation
    ))?;
    Ok(GuardReceipt {
        source_sha256: digest.to_string(),
        event_count,
        field_count: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> String {
        format!("ATTO_ACTOR_STATE_MIR_V0\t{}\nROOT\t1\t2\nLOAN\t1\tEXCLUSIVE\nREAD\t0\t1\t1\nWRITE\t0\t2\t1\nREAD\t1\t3\t1\nEND\t1\nDONE\n", "a".repeat(64))
    }
    #[test]
    fn strict_source_bound_report_is_checked_by_cyclic_oracle() {
        let r = verify_bounded_guard_wire(&good()).unwrap();
        assert_eq!(r.field_count, 2);
        assert_eq!(r.event_count, 3);
    }
    #[test]
    fn rejects_forged_or_incomplete_transport() {
        for payload in [
            good().replace("\nEND\t1\n", "\n"),
            good().replace("DONE\n", "PENDING\n"),
            good().replace("READ\t1\t3\t1", "READ\t9\t3\t1"),
            good().replace("ROOT\t1\t2", "ROOT\t1\t257"),
            good().replace("LOAN\t1\tEXCLUSIVE", "LOAN\t0\tEXCLUSIVE"),
            good().replace("WRITE\t0\t2\t1", "WRITE\t0\t0\t1"),
            good().replace("a".repeat(64).as_str(), "g".repeat(64).as_str()),
            good().replace("READ\t0\t1\t1", "CALL\t0\t1\t1"),
            good().replace("DONE\n", "DONE\nDONE\n"),
            good().replace("LOAN\t1\tEXCLUSIVE", "LOAN\t1\tSHARED"),
        ] {
            assert!(verify_bounded_guard_wire(&payload).is_err(), "{payload}");
        }
    }
    #[test]
    fn rejects_oversized_cyclic_and_duplicate_event_inputs() {
        let mut report = good();
        for _ in 0..MAX_EVENTS {
            report = report.replace("\nEND\t1\n", "\nREAD\t0\t2\t1\nEND\t1\n");
        }
        assert!(verify_bounded_guard_wire(&report).is_err());
        assert!(verify_bounded_guard_wire(&good().repeat(100)).is_err());
    }
}
