//! Regression cases for disjoint fields, last-use loan termination, and
//! method-effect footprints represented in the restricted cyclic V1 model.
//!
//! This is a typed-IR oracle, NOT source-to-MIR certification. In particular,
//! a compiler must authenticate projections and effect summaries independently;
//! the mere presence of a narrow Write(place) event proves nothing about the
//! accuracy or completeness of a compiled method's side effects.
use atto_borrow_checker::cyclic_v1::{check, Block, Code, LoanKind, Op, Place, Program, Root};

fn person() -> Place {
    Place::root(1)
}
fn name() -> Place {
    person().field(1)
}
fn age() -> Place {
    person().field(2)
}
fn shared(id: u32, place: Place) -> Op {
    Op::Borrow { loan: id, place, kind: LoanKind::Shared }
}
fn exclusive(id: u32, place: Place) -> Op {
    Op::Borrow { loan: id, place, kind: LoanKind::Exclusive }
}
fn block(id: u32, ops: Vec<Op>, successors: &[u32]) -> Block {
    Block { id, ops, successors: successors.to_vec() }
}
fn graph(blocks: Vec<Block>) -> Program {
    Program {
        roots: vec![Root { id: 1, is_copy: false, is_transferable: true }],
        blocks,
        entry: 0,
    }
}
fn linear(ops: Vec<Op>) -> Program {
    graph(vec![block(0, ops, &[])])
}
fn reject(ir: Program, expected: Code) {
    assert_eq!(check(&ir).unwrap_err().code, expected);
}

#[test]
fn a_live_name_read_loan_allows_an_unrelated_age_write() {
    check(&linear(vec![
        shared(10, name()),
        Op::Write(age()),
        Op::ReadThrough(10),
        Op::EndLoan(10),
    ])).unwrap();
}

#[test]
fn a_live_name_read_loan_rejects_a_name_write() {
    reject(linear(vec![
        shared(10, name()),
        Op::Write(name()),
        Op::ReadThrough(10),
        Op::EndLoan(10),
    ]), Code::LoanConflict);
}

#[test]
fn distinct_nested_field_projections_are_disjoint() {
    check(&linear(vec![
        shared(10, person().field(3).field(1)),
        Op::Write(person().field(3).field(2)),
        Op::ReadThrough(10),
        Op::EndLoan(10),
    ])).unwrap();
}

#[test]
fn parent_and_descendant_projections_overlap() {
    reject(linear(vec![
        shared(10, person().field(3)),
        Op::Write(person().field(3).field(2)),
    ]), Code::LoanConflict);
}

#[test]
fn two_sibling_exclusive_loans_can_be_live_at_once() {
    check(&linear(vec![
        exclusive(10, name()),
        exclusive(11, age()),
        Op::WriteThrough(11),
        Op::ReadThrough(10),
        Op::EndLoan(11),
        Op::EndLoan(10),
    ])).unwrap();
}

#[test]
fn explicit_last_use_ends_a_loan_before_mutating_its_field() {
    // EndLoan must come from independently validated CFG/last-use evidence.
    check(&linear(vec![
        shared(10, name()),
        Op::ReadThrough(10),
        Op::EndLoan(10),
        Op::Write(name()),
    ])).unwrap();
    // Merely claiming the last value is unimportant is not enough.
    reject(linear(vec![
        shared(10, name()),
        Op::ReadThrough(10),
        Op::Write(name()),
        Op::EndLoan(10),
    ]), Code::LoanConflict);
}

#[test]
fn ended_borrow_cannot_be_resurrected_by_a_later_read() {
    reject(linear(vec![
        shared(10, name()),
        Op::EndLoan(10),
        Op::ReadThrough(10),
    ]), Code::LoanNotLive);
}

#[test]
fn whole_receiver_mutability_conflicts_with_a_live_field_loan() {
    // Model an unproven method accepting &mut self as an exclusive whole-root
    // borrow. We cannot infer that its actual body only modifies age.
    reject(linear(vec![
        shared(10, name()),
        exclusive(11, person()),
        Op::EndLoan(11),
        Op::EndLoan(10),
    ]), Code::LoanConflict);
}

#[test]
fn an_authenticated_age_only_effect_can_preserve_a_name_loan() {
    // This models the EFFECT of a method after its exact field footprint has
    // already been proven and expanded into typed MIR by the compiler.
    check(&linear(vec![
        shared(10, name()),
        Op::Read(age()),
        Op::Write(age()),
        Op::ReadThrough(10),
        Op::EndLoan(10),
    ])).unwrap();
}

#[test]
fn a_mutating_method_summary_must_not_hide_a_name_write() {
    // A compiler that emits Write(age) but omits a real Write(name) is unsound.
    // When the full footprint is emitted, the oracle correctly rejects it.
    reject(linear(vec![
        shared(10, name()),
        Op::Write(age()),
        Op::Write(name()),
        Op::EndLoan(10),
    ]), Code::LoanConflict);
}

#[test]
fn branch_join_keeps_the_live_field_loan_and_allows_disjoint_writes() {
    check(&graph(vec![
        block(0, vec![shared(10, name())], &[1, 2]),
        block(1, vec![Op::Write(age())], &[3]),
        block(2, vec![Op::Read(age())], &[3]),
        block(3, vec![Op::ReadThrough(10), Op::EndLoan(10), Op::Write(name())], &[]),
    ])).unwrap();
}

#[test]
fn one_branch_writing_the_borrowed_field_is_a_conflict() {
    reject(graph(vec![
        block(0, vec![shared(10, name())], &[1, 2]),
        block(1, vec![Op::Write(age())], &[3]),
        block(2, vec![Op::Write(name())], &[3]),
        block(3, vec![Op::ReadThrough(10), Op::EndLoan(10)], &[]),
    ]), Code::LoanConflict);
}

#[test]
fn live_field_loan_blocks_whole_owner_move_and_suspension() {
    reject(linear(vec![
        shared(10, name()),
        Op::Move(person()),
        Op::EndLoan(10),
    ]), Code::LoanConflict);
    reject(linear(vec![
        shared(10, name()),
        Op::Suspend,
        Op::EndLoan(10),
    ]), Code::UnsupportedSuspension);
}

#[test]
fn moved_sibling_does_not_poison_an_unmoved_field() {
    check(&linear(vec![
        Op::Move(name()),
        Op::Read(age()),
        Op::Reinitialize(name()),
        Op::Read(person()),
    ])).unwrap();
    reject(linear(vec![
        Op::Move(name()),
        Op::Read(person()),
    ]), Code::UseAfterMove);
}
