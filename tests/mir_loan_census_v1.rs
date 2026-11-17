use atto_borrow_checker::mir_loan_census_v1::{
    project, BridgeError, Evidence, InstructionFacts,
};
use atto_borrow_checker::mir_v1::{
    Effect, Instruction, MirBlock, MirFunction, Producer, CONTRACT_VERSION,
};
use atto_borrow_checker::polonius_facts_v1::Code;
use atto_borrow_checker::{BorrowKind, Op, Traits};

fn ins(id: u64, effect: Effect, operation: Op) -> Instruction {
    Instruction {
        instruction_id: id,
        source_node_id: id + 100,
        effect,
        operation,
    }
}
fn row(id: u64, use_origins: &[u32], define_origins: &[u32], borrow_origin: Option<u32>) -> InstructionFacts {
    InstructionFacts {
        instruction_id: id,
        use_origins: use_origins.to_vec(),
        define_origins: define_origins.to_vec(),
        borrow_origin,
    }
}
fn source() -> (MirFunction, Evidence) {
    let traits = Traits { is_copy: false, is_send: false };
    let mir = MirFunction {
        version: CONTRACT_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 2,
        },
        entry: 0,
        expected_instruction_ids: (1..=8).collect(),
        blocks: vec![
            MirBlock { id: 0, instructions: vec![
                ins(1, Effect::Ownership, Op::Init { owner: 1, traits }),
                ins(2, Effect::Ownership, Op::Borrow { owner: 1, loan: 7, kind: BorrowKind::Mutable }),
            ], successors: vec![1, 2] },
            MirBlock { id: 1, instructions: vec![
                ins(3, Effect::Control, Op::Return),
            ], successors: vec![] },
            MirBlock { id: 2, instructions: vec![
                ins(4, Effect::Ownership, Op::Write { owner: 1 }),
                ins(5, Effect::Ownership, Op::EndBorrow { loan: 7 }),
                ins(6, Effect::Ownership, Op::Init { owner: 2, traits }),
                ins(7, Effect::Ownership, Op::Borrow { owner: 2, loan: 8, kind: BorrowKind::Mutable }),
                ins(8, Effect::Control, Op::Return),
            ], successors: vec![] },
        ],
    };
    let evidence = Evidence {
        instruction_facts: vec![
            row(1, &[], &[10], None),
            row(2, &[], &[], Some(10)),
            row(3, &[10], &[], None),
            row(4, &[], &[], None),
            row(5, &[], &[], None),
            row(6, &[], &[20], None),
            row(7, &[], &[], Some(20)),
            row(8, &[20], &[], None),
        ],
        phi_edges: vec![],
    };
    (mir, evidence)
}
#[test]
fn mir_derived_cfg_allows_some_borrow_none_write_and_reborrow() {
    let (mir, evidence) = source();
    let result = project(&mir, &evidence).unwrap();
    let some = result.instruction_to_point[&3];
    let none_write = result.instruction_to_point[&4];
    let none_return = result.instruction_to_point[&8];
    assert!(result.report.loan_report.live_loans_on_entry[&some].contains(&7));
    assert!(!result.report.loan_report.live_loans_on_entry[&none_write].contains(&7));
    assert!(result.report.loan_report.live_loans_on_entry[&none_return].contains(&8));
}
#[test]
fn a_write_with_live_origin_does_not_escape_borrow_checks() {
    let (mir, mut evidence) = source();
    evidence.instruction_facts[3].use_origins.push(10);
    let result = project(&mir, &evidence).unwrap_err();
    assert!(matches!(result, BridgeError::Ssa(e) if e.code == Code::InvalidatedLoan));
}
#[test]
fn missing_instruction_census_is_rejected() {
    let (mir, mut evidence) = source();
    evidence.instruction_facts.pop();
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_BUDGET_OR_INVENTORY")));
}
#[test]
fn duplicate_instruction_census_is_rejected() {
    let (mir, mut evidence) = source();
    evidence.instruction_facts[7] = evidence.instruction_facts[6].clone();
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_DUPLICATE_FACT")));
}
#[test]
fn missing_borrow_origin_and_return_use_are_rejected() {
    let (mir, mut evidence) = source();
    evidence.instruction_facts[1].borrow_origin = None;
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_BORROW_ORIGIN")));
    let (mir, mut evidence) = source();
    evidence.instruction_facts[2].use_origins.clear();
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_RETURN_WITNESS_REQUIRED")));
}
#[test]
fn unknown_or_actor_effects_must_not_disappear_from_census() {
    let (mut mir, evidence) = source();
    mir.blocks[2].instructions[0].operation = Op::ActorHopBorrow { owner: 1 };
    mir.blocks[2].instructions[0].effect = Effect::ActorBoundary;
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_UNMODELED_OPERATION")));
}
#[test]
fn stale_mir_source_inventory_is_rejected_before_lifetime_work() {
    let (mut mir, evidence) = source();
    mir.expected_instruction_ids.pop();
    assert!(matches!(project(&mir, &evidence), Err(BridgeError::Mir(_))));
}
#[test]
fn no_silent_acceptance_of_unknown_suspension() {
    let (mut mir, evidence) = source();
    mir.blocks[2].instructions[0].operation = Op::Suspend;
    mir.blocks[2].instructions[0].effect = Effect::Suspension;
    assert_eq!(project(&mir, &evidence), Err(BridgeError::Invalid("E_DIAGNOSTIC_UNMODELED_OPERATION")));
}
