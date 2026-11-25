//! `atto-borrow-wire-v1`: the JSON interchange between backend compilers and
//! the canonical checker.
//!
//! Each `atto-source.*` compiler runs its own in-pass borrow checker. To be
//! cross-verified, a backend exports the ownership-event graph it derived (and
//! its own verdict) in this format, and the canonical checker re-verifies it.
//!
//! The decoder is deliberately strict and fails closed:
//! - unknown, missing, duplicated or mistyped keys reject;
//! - numbers must be non-negative integers that fit the target id type;
//! - input size and nesting depth are bounded before allocation grows;
//! - `UnknownEffect` (an operation a backend cannot faithfully represent)
//!   is a canonical reject, never an ownership no-op.
//!
//! No external dependencies: the crate stays dependency-free.

use std::collections::BTreeMap;

use crate::mir_v1::{Effect, Instruction, MirBlock, MirFunction, Producer};
use crate::{Block, BorrowKind, Op, Program, Traits};

pub const WIRE_VERSION: &str = "atto-borrow-wire-v1";
/// Hard cap on one JSON document (a graph, a MIR function or one report line).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

/// Canonical diagnostic for an operation a backend could not represent.
pub const UNSUPPORTED_EFFECT: &str = "E_MIR_UNSUPPORTED_EFFECT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Only non-negative integers are admitted; ids and counters need no more.
    Int(u64),
    Str(String),
    Arr(Vec<Json>),
    /// Insertion-ordered; duplicate keys are rejected at parse time.
    Obj(Vec<(String, Json)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    pub message: String,
    /// JSON path-ish location, e.g. `blocks[0].ops[2].owner`.
    pub at: String,
}

impl WireError {
    fn new(at: &str, message: impl Into<String>) -> Self {
        WireError {
            message: message.into(),
            at: at.to_string(),
        }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.at.is_empty() {
            return write!(f, "{}", self.message);
        }
        return write!(f, "{}: {}", self.at, self.message);
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

pub fn parse_json(text: &str) -> Result<Json, WireError> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(WireError::new("", "document exceeds size budget"));
    }
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.err("trailing characters after JSON value"));
    }
    return Ok(value);
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, message: &str) -> WireError {
        return WireError::new(&format!("byte {}", self.pos), message);
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn eat(&mut self, literal: &[u8]) -> bool {
        if self.bytes[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            return true;
        }
        return false;
    }

    fn value(&mut self, depth: usize) -> Result<Json, WireError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting depth budget exceeded"));
        }
        match self.bytes.get(self.pos) {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') if self.eat(b"null") => Ok(Json::Null),
            Some(b't') if self.eat(b"true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'0'..=b'9') => self.integer(),
            Some(b'-') => Err(self.err("negative numbers are not admitted")),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn integer(&mut self) -> Result<Json, WireError> {
        let start = self.pos;
        while matches!(self.bytes.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if matches!(self.bytes.get(self.pos), Some(b'.' | b'e' | b'E')) {
            return Err(self.err("fractional/exponent numbers are not admitted"));
        }
        let digits = &self.bytes[start..self.pos];
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(self.err("leading zeros are not admitted"));
        }
        let text = std::str::from_utf8(digits).expect("ascii digits");
        return text
            .parse::<u64>()
            .map(Json::Int)
            .map_err(|_| self.err("integer exceeds u64"));
    }

    fn string(&mut self) -> Result<String, WireError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(&b) = self.bytes.get(self.pos) else {
                return Err(self.err("unterminated string"));
            };
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(&esc) = self.bytes.get(self.pos) else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                0x00..=0x1f => return Err(self.err("raw control character in string")),
                _ => {
                    // Copy one UTF-8 scalar; input is &str so boundaries are valid.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..]).expect("valid utf-8");
                    let ch = rest.chars().next().expect("non-empty");
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, WireError> {
        let Some(chunk) = self.bytes.get(self.pos..self.pos + 4) else {
            return Err(self.err("short \\u escape"));
        };
        let text = std::str::from_utf8(chunk).map_err(|_| self.err("bad \\u escape"))?;
        let value = u32::from_str_radix(text, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.pos += 4;
        return Ok(value);
    }

    fn unicode_escape(&mut self) -> Result<char, WireError> {
        let first = self.hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            if !self.eat(b"\\u") {
                return Err(self.err("unpaired surrogate"));
            }
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(self.err("unpaired surrogate"));
            }
            let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            return char::from_u32(code).ok_or_else(|| self.err("invalid code point"));
        }
        return char::from_u32(first).ok_or_else(|| self.err("unpaired surrogate"));
    }

    fn array(&mut self, depth: usize) -> Result<Json, WireError> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b"]") {
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"]") {
                return Ok(Json::Arr(items));
            }
            return Err(self.err("expected ',' or ']'"));
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, WireError> {
        self.pos += 1;
        let mut fields: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.eat(b"}") {
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err(self.err("expected object key"));
            }
            let key = self.string()?;
            if fields.iter().any(|(existing, _)| *existing == key) {
                return Err(self.err("duplicate object key"));
            }
            self.skip_ws();
            if !self.eat(b":") {
                return Err(self.err("expected ':'"));
            }
            self.skip_ws();
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.skip_ws();
            if self.eat(b",") {
                continue;
            }
            if self.eat(b"}") {
                return Ok(Json::Obj(fields));
            }
            return Err(self.err("expected ',' or '}'"));
        }
    }
}

// ---------------------------------------------------------------------------
// JSON writing (compact, deterministic)
// ---------------------------------------------------------------------------

pub fn write_json(value: &Json) -> String {
    let mut out = String::new();
    write_into(value, &mut out);
    return out;
}

fn write_into(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(n) => out.push_str(&n.to_string()),
        Json::Str(s) => write_string(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_into(item, out);
            }
            out.push(']');
        }
        Json::Obj(fields) => {
            out.push('{');
            for (i, (key, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_into(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------
// Strict object access
// ---------------------------------------------------------------------------

/// A view over a JSON object that tracks which keys were consumed so that
/// `finish` can reject anything unexpected.
pub struct Fields<'a> {
    at: String,
    fields: &'a [(String, Json)],
    used: Vec<bool>,
}

impl<'a> Fields<'a> {
    pub fn of(value: &'a Json, at: &str) -> Result<Self, WireError> {
        match value {
            Json::Obj(fields) => Ok(Fields {
                at: at.to_string(),
                fields,
                used: vec![false; fields.len()],
            }),
            _ => Err(WireError::new(at, "expected object")),
        }
    }

    pub fn path(&self, key: &str) -> String {
        if self.at.is_empty() {
            return key.to_string();
        }
        return format!("{}.{}", self.at, key);
    }

    pub fn opt(&mut self, key: &str) -> Option<&'a Json> {
        let index = self.fields.iter().position(|(k, _)| k == key)?;
        self.used[index] = true;
        return Some(&self.fields[index].1);
    }

    pub fn req(&mut self, key: &str) -> Result<&'a Json, WireError> {
        let path = self.path(key);
        return self
            .opt(key)
            .ok_or_else(|| WireError::new(&path, "missing required key"));
    }

    pub fn str(&mut self, key: &str) -> Result<&'a str, WireError> {
        let path = self.path(key);
        match self.req(key)? {
            Json::Str(s) => Ok(s),
            _ => Err(WireError::new(&path, "expected string")),
        }
    }

    pub fn opt_str(&mut self, key: &str) -> Result<Option<&'a str>, WireError> {
        let path = self.path(key);
        match self.opt(key) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::Str(s)) => Ok(Some(s)),
            Some(_) => Err(WireError::new(&path, "expected string or null")),
        }
    }

    pub fn bool(&mut self, key: &str) -> Result<bool, WireError> {
        let path = self.path(key);
        match self.req(key)? {
            Json::Bool(b) => Ok(*b),
            _ => Err(WireError::new(&path, "expected boolean")),
        }
    }

    pub fn u64(&mut self, key: &str) -> Result<u64, WireError> {
        let path = self.path(key);
        match self.req(key)? {
            Json::Int(n) => Ok(*n),
            _ => Err(WireError::new(&path, "expected non-negative integer")),
        }
    }

    pub fn u32(&mut self, key: &str) -> Result<u32, WireError> {
        let path = self.path(key);
        let n = self.u64(key)?;
        return u32::try_from(n).map_err(|_| WireError::new(&path, "integer exceeds u32"));
    }

    pub fn arr(&mut self, key: &str) -> Result<&'a [Json], WireError> {
        let path = self.path(key);
        match self.req(key)? {
            Json::Arr(items) => Ok(items),
            _ => Err(WireError::new(&path, "expected array")),
        }
    }

    /// Reject keys that were present but never consumed (fail closed on typos
    /// such as `"onwer"` that would otherwise silently drop an operand).
    pub fn finish(self) -> Result<(), WireError> {
        for (index, used) in self.used.iter().enumerate() {
            if !used {
                let key = &self.fields[index].0;
                return Err(WireError::new(&self.path(key), "unknown key"));
            }
        }
        return Ok(());
    }

    /// Like `finish`, but permits documentation-only keys (e.g. `"note"`).
    pub fn finish_allowing(mut self, ignorable: &[&str]) -> Result<(), WireError> {
        for key in ignorable {
            let _ = self.opt(key);
        }
        return self.finish();
    }
}

fn u32_list(items: &[Json], at: &str) -> Result<Vec<u32>, WireError> {
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            Json::Int(n) => out.push(
                u32::try_from(*n)
                    .map_err(|_| WireError::new(&format!("{at}[{i}]"), "integer exceeds u32"))?,
            ),
            _ => return Err(WireError::new(&format!("{at}[{i}]"), "expected integer")),
        }
    }
    return Ok(out);
}

fn u64_list(items: &[Json], at: &str) -> Result<Vec<u64>, WireError> {
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item {
            Json::Int(n) => out.push(*n),
            _ => return Err(WireError::new(&format!("{at}[{i}]"), "expected integer")),
        }
    }
    return Ok(out);
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// A decoded operation: either a canonical V0 `Op`, or an operation the
/// producing backend declared it cannot faithfully represent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireOp {
    Op(Op),
    UnknownEffect { kind: String },
}

pub fn decode_op(value: &Json, at: &str) -> Result<WireOp, WireError> {
    let mut f = Fields::of(value, at)?;
    let name = f.str("op")?;
    let op = match name {
        "Init" => Op::Init {
            owner: f.u32("owner")?,
            traits: Traits {
                is_copy: f.bool("copy")?,
                is_send: f.bool("send")?,
            },
        },
        "Read" => Op::Read {
            owner: f.u32("owner")?,
        },
        "Write" => Op::Write {
            owner: f.u32("owner")?,
        },
        "Borrow" => Op::Borrow {
            owner: f.u32("owner")?,
            loan: f.u32("loan")?,
            kind: match f.str("kind")? {
                "Shared" => BorrowKind::Shared,
                "Mutable" => BorrowKind::Mutable,
                _ => {
                    return Err(WireError::new(
                        &f.path("kind"),
                        "expected Shared or Mutable",
                    ))
                }
            },
        },
        "WriteThrough" => Op::WriteThrough {
            owner: f.u32("owner")?,
            loan: f.u32("loan")?,
        },
        "EndBorrow" => Op::EndBorrow {
            loan: f.u32("loan")?,
        },
        "Move" => Op::Move {
            from: f.u32("from")?,
            into: f.u32("into")?,
        },
        "Copy" => Op::Copy {
            from: f.u32("from")?,
            into: f.u32("into")?,
        },
        "DeepCopy" => Op::DeepCopy {
            from: f.u32("from")?,
            into: f.u32("into")?,
            graph_proven: f.bool("graphProven")?,
        },
        "Drop" => Op::Drop {
            owner: f.u32("owner")?,
        },
        "Freeze" => Op::Freeze {
            from: f.u32("from")?,
            into: f.u32("into")?,
            deep_proven: f.bool("deepProven")?,
        },
        "PinStorage" => Op::PinStorage {
            owner: f.u32("owner")?,
            stable_address_proven: f.bool("stableAddressProven")?,
        },
        "RelocateStorage" => Op::RelocateStorage {
            owner: f.u32("owner")?,
        },
        "CreateWeak" => Op::CreateWeak {
            region: f.u32("region")?,
            weak: f.u32("weak")?,
            generation_fenced: f.bool("generationFenced")?,
        },
        "ProbeWeak" => Op::ProbeWeak {
            weak: f.u32("weak")?,
            generation_fenced: f.bool("generationFenced")?,
        },
        "TaskCaptureCopy" => Op::TaskCaptureCopy {
            owner: f.u32("owner")?,
        },
        "TaskCaptureMove" => Op::TaskCaptureMove {
            owner: f.u32("owner")?,
        },
        "Suspend" => Op::Suspend,
        "ActorHopBorrow" => Op::ActorHopBorrow {
            owner: f.u32("owner")?,
        },
        "ActorSendPrepare" => Op::ActorSendPrepare {
            owner: f.u32("owner")?,
            ticket: f.u32("ticket")?,
        },
        "ActorSendCommit" => Op::ActorSendCommit {
            ticket: f.u32("ticket")?,
        },
        "ActorSendAbort" => Op::ActorSendAbort {
            ticket: f.u32("ticket")?,
        },
        "ActorSendMove" => Op::ActorSendMove {
            owner: f.u32("owner")?,
        },
        "ActorSendCopy" => Op::ActorSendCopy {
            owner: f.u32("owner")?,
        },
        "PublishFrozen" => Op::PublishFrozen {
            owner: f.u32("owner")?,
            region: f.u32("region")?,
            sync_proven: f.bool("syncProven")?,
        },
        "PromoteGuarded" => Op::PromoteGuarded {
            owner: f.u32("owner")?,
            region: f.u32("region")?,
        },
        "Return" => Op::Return,
        "UnknownEffect" => {
            let kind = f.str("kind")?.to_string();
            f.finish()?;
            return Ok(WireOp::UnknownEffect { kind });
        }
        other => {
            return Err(WireError::new(
                &f.path("op"),
                format!("unknown operation {other:?}"),
            ))
        }
    };
    f.finish()?;
    return Ok(WireOp::Op(op));
}

/// Encode a canonical op using exactly the shape `decode_op` accepts.
pub fn encode_op(op: &Op) -> Json {
    let s = |v: &str| Json::Str(v.to_string());
    let n = |v: u32| Json::Int(u64::from(v));
    let b = Json::Bool;
    let fields: Vec<(&str, Json)> = match *op {
        Op::Init { owner, traits } => vec![
            ("op", s("Init")),
            ("owner", n(owner)),
            ("copy", b(traits.is_copy)),
            ("send", b(traits.is_send)),
        ],
        Op::Read { owner } => vec![("op", s("Read")), ("owner", n(owner))],
        Op::Write { owner } => vec![("op", s("Write")), ("owner", n(owner))],
        Op::Borrow { owner, loan, kind } => vec![
            ("op", s("Borrow")),
            ("owner", n(owner)),
            ("loan", n(loan)),
            (
                "kind",
                s(match kind {
                    BorrowKind::Shared => "Shared",
                    BorrowKind::Mutable => "Mutable",
                }),
            ),
        ],
        Op::WriteThrough { owner, loan } => vec![
            ("op", s("WriteThrough")),
            ("owner", n(owner)),
            ("loan", n(loan)),
        ],
        Op::EndBorrow { loan } => vec![("op", s("EndBorrow")), ("loan", n(loan))],
        Op::Move { from, into } => vec![("op", s("Move")), ("from", n(from)), ("into", n(into))],
        Op::Copy { from, into } => vec![("op", s("Copy")), ("from", n(from)), ("into", n(into))],
        Op::DeepCopy {
            from,
            into,
            graph_proven,
        } => vec![
            ("op", s("DeepCopy")),
            ("from", n(from)),
            ("into", n(into)),
            ("graphProven", b(graph_proven)),
        ],
        Op::Drop { owner } => vec![("op", s("Drop")), ("owner", n(owner))],
        Op::Freeze {
            from,
            into,
            deep_proven,
        } => vec![
            ("op", s("Freeze")),
            ("from", n(from)),
            ("into", n(into)),
            ("deepProven", b(deep_proven)),
        ],
        Op::PinStorage {
            owner,
            stable_address_proven,
        } => vec![
            ("op", s("PinStorage")),
            ("owner", n(owner)),
            ("stableAddressProven", b(stable_address_proven)),
        ],
        Op::RelocateStorage { owner } => vec![("op", s("RelocateStorage")), ("owner", n(owner))],
        Op::CreateWeak {
            region,
            weak,
            generation_fenced,
        } => vec![
            ("op", s("CreateWeak")),
            ("region", n(region)),
            ("weak", n(weak)),
            ("generationFenced", b(generation_fenced)),
        ],
        Op::ProbeWeak {
            weak,
            generation_fenced,
        } => vec![
            ("op", s("ProbeWeak")),
            ("weak", n(weak)),
            ("generationFenced", b(generation_fenced)),
        ],
        Op::TaskCaptureCopy { owner } => vec![("op", s("TaskCaptureCopy")), ("owner", n(owner))],
        Op::TaskCaptureMove { owner } => vec![("op", s("TaskCaptureMove")), ("owner", n(owner))],
        Op::Suspend => vec![("op", s("Suspend"))],
        Op::ActorHopBorrow { owner } => vec![("op", s("ActorHopBorrow")), ("owner", n(owner))],
        Op::ActorSendPrepare { owner, ticket } => vec![
            ("op", s("ActorSendPrepare")),
            ("owner", n(owner)),
            ("ticket", n(ticket)),
        ],
        Op::ActorSendCommit { ticket } => {
            vec![("op", s("ActorSendCommit")), ("ticket", n(ticket))]
        }
        Op::ActorSendAbort { ticket } => vec![("op", s("ActorSendAbort")), ("ticket", n(ticket))],
        Op::ActorSendMove { owner } => vec![("op", s("ActorSendMove")), ("owner", n(owner))],
        Op::ActorSendCopy { owner } => vec![("op", s("ActorSendCopy")), ("owner", n(owner))],
        Op::PublishFrozen {
            owner,
            region,
            sync_proven,
        } => vec![
            ("op", s("PublishFrozen")),
            ("owner", n(owner)),
            ("region", n(region)),
            ("syncProven", b(sync_proven)),
        ],
        Op::PromoteGuarded { owner, region } => vec![
            ("op", s("PromoteGuarded")),
            ("owner", n(owner)),
            ("region", n(region)),
        ],
        Op::Return => vec![("op", s("Return"))],
    };
    return Json::Obj(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    );
}

// ---------------------------------------------------------------------------
// Graphs (source-free conformance cases)
// ---------------------------------------------------------------------------

/// A source-free ownership graph, as used by the graph conformance corpus.
#[derive(Clone, Debug)]
pub struct WireGraph {
    pub entry: u32,
    pub blocks: Vec<WireBlock>,
}

#[derive(Clone, Debug)]
pub struct WireBlock {
    pub id: u32,
    pub ops: Vec<WireOp>,
    pub successors: Vec<u32>,
}

impl WireGraph {
    /// Lower to the canonical program, or report the first unrepresentable
    /// operation as `(block, operation, kind)`.
    pub fn to_program(&self) -> Result<Program, (u32, usize, String)> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let mut operations = Vec::with_capacity(block.ops.len());
            for (index, op) in block.ops.iter().enumerate() {
                match op {
                    WireOp::Op(op) => operations.push(op.clone()),
                    WireOp::UnknownEffect { kind } => {
                        return Err((block.id, index, kind.clone()));
                    }
                }
            }
            blocks.push(Block {
                id: block.id,
                operations,
                successors: block.successors.clone(),
            });
        }
        return Ok(Program {
            entry: self.entry,
            blocks,
        });
    }
}

pub fn decode_graph(value: &Json, at: &str) -> Result<WireGraph, WireError> {
    let mut f = Fields::of(value, at)?;
    let entry = f.u32("entry")?;
    let blocks_path = f.path("blocks");
    let mut blocks = Vec::new();
    for (bi, block) in f.arr("blocks")?.iter().enumerate() {
        let bpath = format!("{blocks_path}[{bi}]");
        let mut bf = Fields::of(block, &bpath)?;
        let id = bf.u32("id")?;
        let ops_path = bf.path("ops");
        let mut ops = Vec::new();
        for (oi, op) in bf.arr("ops")?.iter().enumerate() {
            ops.push(decode_op(op, &format!("{ops_path}[{oi}]"))?);
        }
        let succ_path = bf.path("successors");
        let successors = u32_list(bf.arr("successors")?, &succ_path)?;
        bf.finish()?;
        blocks.push(WireBlock {
            id,
            ops,
            successors,
        });
    }
    f.finish()?;
    return Ok(WireGraph { entry, blocks });
}

// ---------------------------------------------------------------------------
// MIR functions (backend exports)
// ---------------------------------------------------------------------------

/// A decoded MIR function. `unsupported` lists instructions whose op the
/// backend marked as `UnknownEffect`; such a function always rejects with
/// `E_MIR_UNSUPPORTED_EFFECT` and is never lowered to the canonical program.
#[derive(Clone, Debug)]
pub struct WireMir {
    pub function: MirFunction,
    pub unsupported: Vec<(u32, u64, String)>,
}

fn decode_effect(text: &str, at: &str) -> Result<Effect, WireError> {
    return match text {
        "Ownership" => Ok(Effect::Ownership),
        "Suspension" => Ok(Effect::Suspension),
        "ActorBoundary" => Ok(Effect::ActorBoundary),
        "Control" => Ok(Effect::Control),
        "Unsupported" => Ok(Effect::Unsupported),
        _ => Err(WireError::new(at, "unknown effect")),
    };
}

pub fn effect_name(effect: Effect) -> &'static str {
    return match effect {
        Effect::Ownership => "Ownership",
        Effect::Suspension => "Suspension",
        Effect::ActorBoundary => "ActorBoundary",
        Effect::Control => "Control",
        Effect::Unsupported => "Unsupported",
    };
}

pub fn decode_mir(value: &Json, at: &str) -> Result<WireMir, WireError> {
    let mut f = Fields::of(value, at)?;
    let version = f.str("version")?.to_string();
    let producer_path = f.path("producer");
    let mut pf = Fields::of(f.req("producer")?, &producer_path)?;
    let producer = Producer {
        compiler_git_sha: pf.str("compilerGitSha")?.to_string(),
        source_sha256: pf.str("sourceSha256")?.to_string(),
        source_unit_id: pf.u64("sourceUnitId")?,
        function_id: pf.u64("functionId")?,
    };
    pf.finish()?;
    let entry = f.u32("entry")?;
    let expected_path = f.path("expectedInstructionIds");
    let expected_instruction_ids = u64_list(f.arr("expectedInstructionIds")?, &expected_path)?;
    let blocks_path = f.path("blocks");
    let mut blocks = Vec::new();
    let mut unsupported = Vec::new();
    for (bi, block) in f.arr("blocks")?.iter().enumerate() {
        let bpath = format!("{blocks_path}[{bi}]");
        let mut bf = Fields::of(block, &bpath)?;
        let id = bf.u32("id")?;
        let ins_path = bf.path("instructions");
        let mut instructions = Vec::new();
        for (ii, ins) in bf.arr("instructions")?.iter().enumerate() {
            let ipath = format!("{ins_path}[{ii}]");
            let mut inf = Fields::of(ins, &ipath)?;
            let instruction_id = inf.u64("instructionId")?;
            let source_node_id = inf.u64("sourceNodeId")?;
            let effect_path = inf.path("effect");
            let effect = decode_effect(inf.str("effect")?, &effect_path)?;
            let op_path = inf.path("op");
            let op = decode_op(inf.req("op")?, &op_path)?;
            inf.finish()?;
            let operation = match op {
                WireOp::Op(op) => op,
                WireOp::UnknownEffect { kind } => {
                    if effect != Effect::Unsupported {
                        return Err(WireError::new(
                            &effect_path,
                            "UnknownEffect requires effect Unsupported",
                        ));
                    }
                    unsupported.push((id, instruction_id, kind));
                    // MIR envelope validation rejects this effect before lowering.
                    Op::Return
                }
            };
            instructions.push(Instruction {
                instruction_id,
                source_node_id,
                effect,
                operation,
            });
        }
        let succ_path = bf.path("successors");
        let successors = u32_list(bf.arr("successors")?, &succ_path)?;
        bf.finish()?;
        blocks.push(MirBlock {
            id,
            instructions,
            successors,
        });
    }
    f.finish()?;
    return Ok(WireMir {
        function: MirFunction {
            version,
            producer,
            entry,
            expected_instruction_ids,
            blocks,
        },
        unsupported,
    });
}

pub fn encode_mir(function: &MirFunction) -> Json {
    let s = |v: &str| Json::Str(v.to_string());
    let blocks = function
        .blocks
        .iter()
        .map(|block| {
            Json::Obj(vec![
                ("id".into(), Json::Int(u64::from(block.id))),
                (
                    "instructions".into(),
                    Json::Arr(
                        block
                            .instructions
                            .iter()
                            .map(|ins| {
                                Json::Obj(vec![
                                    ("instructionId".into(), Json::Int(ins.instruction_id)),
                                    ("sourceNodeId".into(), Json::Int(ins.source_node_id)),
                                    ("effect".into(), s(effect_name(ins.effect))),
                                    ("op".into(), encode_op(&ins.operation)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "successors".into(),
                    Json::Arr(
                        block
                            .successors
                            .iter()
                            .map(|&b| Json::Int(u64::from(b)))
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    return Json::Obj(vec![
        ("version".into(), s(&function.version)),
        (
            "producer".into(),
            Json::Obj(vec![
                (
                    "compilerGitSha".into(),
                    s(&function.producer.compiler_git_sha),
                ),
                ("sourceSha256".into(), s(&function.producer.source_sha256)),
                (
                    "sourceUnitId".into(),
                    Json::Int(function.producer.source_unit_id),
                ),
                (
                    "functionId".into(),
                    Json::Int(function.producer.function_id),
                ),
            ]),
        ),
        ("entry".into(), Json::Int(u64::from(function.entry))),
        (
            "expectedInstructionIds".into(),
            Json::Arr(
                function
                    .expected_instruction_ids
                    .iter()
                    .map(|&id| Json::Int(id))
                    .collect(),
            ),
        ),
        ("blocks".into(), Json::Arr(blocks)),
    ]);
}

/// Convenience for building lookup maps of string-keyed objects.
pub fn object_map(value: &Json) -> Option<BTreeMap<&str, &Json>> {
    match value {
        Json::Obj(fields) => Some(fields.iter().map(|(k, v)| (k.as_str(), v)).collect()),
        _ => None,
    }
}

/// Wrap a canonical program as a well-formed MIR function: one instruction per
/// op, ids `1..=n` in block order, `sourceNodeId == instructionId`, effects
/// from `mir_v1::expected_effect`. Used for golden examples and tests; a real
/// backend must take ids from its own typed IR, not renumber like this.
pub fn mir_from_program(program: &Program, producer: Producer) -> MirFunction {
    let mut next = 0u64;
    let mut ids = Vec::new();
    let blocks = program
        .blocks
        .iter()
        .map(|block| MirBlock {
            id: block.id,
            instructions: block
                .operations
                .iter()
                .map(|op| {
                    next += 1;
                    ids.push(next);
                    Instruction {
                        instruction_id: next,
                        source_node_id: next,
                        effect: crate::mir_v1::expected_effect(op),
                        operation: op.clone(),
                    }
                })
                .collect(),
            successors: block.successors.clone(),
        })
        .collect();
    return MirFunction {
        version: crate::mir_v1::CONTRACT_VERSION.to_string(),
        producer,
        entry: program.entry,
        expected_instruction_ids: ids,
        blocks,
    };
}
