//! Named lifetimes must constrain existing borrows, never invent owner rights.
//! The browser parser can reject unsupported generic syntax without making
//! this canonical checker silently treat lifetimes as runtime expressions.
use atto_borrow_checker::lifetime_v1::{Error, Lifetimes};
use atto_borrow_checker::BorrowKind::{Mutable, Shared};

#[test]
fn lt_a_is_a_plain_identifier_and_not_rust_apostrophe_syntax() {
    let mut c = Lifetimes::new();
    assert_eq!(c.bind("'a"), Err(Error::InvalidName));
    assert_eq!(c.bind(""), Err(Error::InvalidName));
    assert_eq!(c.bind("a-b"), Err(Error::InvalidName));
    assert_eq!(c.bind("9abc"), Err(Error::InvalidName));
    assert!(c.bind("a").is_ok());
    assert!(c.bind("long_lived_2").is_ok());
    assert_eq!(c.bind("a"), Err(Error::DuplicateBinder));
}

#[test]
fn named_lifetime_may_borrow_outer_owner_with_shared_loans() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.enter_scope().unwrap();
    c.bind("a").unwrap();
    c.borrow_named(1, 10, Shared, "a").unwrap();
    c.borrow_named(1, 11, Shared, "a").unwrap();
    assert_eq!(c.borrow_named(1, 12, Mutable, "a"), Err(Error::Conflict));
    c.end_borrow(10).unwrap();
    c.end_borrow(11).unwrap();
    c.leave_scope().unwrap();
    assert_eq!(
        c.borrow_named(1, 13, Shared, "a"),
        Err(Error::UnknownBinder)
    );
}

#[test]
fn lifetime_declared_outside_owner_cannot_outlive_inner_storage() {
    let mut c = Lifetimes::new();
    c.bind("outer").unwrap();
    c.enter_scope().unwrap();
    c.own(2).unwrap();
    assert_eq!(
        c.borrow_named(2, 5, Shared, "outer"),
        Err(Error::OutlivesOwner)
    );
    // A named lifetime declared alongside the owned storage is valid.
    c.bind("inner").unwrap();
    c.borrow_named(2, 5, Shared, "inner").unwrap();
    c.end_borrow(5).unwrap();
    c.leave_scope().unwrap();
}

#[test]
fn implicit_argument_borrow_still_requires_one_exclusive_writer() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.borrow_implicit(1, 1, Shared).unwrap();
    assert_eq!(c.borrow_implicit(1, 2, Mutable), Err(Error::Conflict));
    c.end_borrow(1).unwrap();
    c.borrow_implicit(1, 2, Mutable).unwrap();
    assert_eq!(c.borrow_implicit(1, 3, Shared), Err(Error::Conflict));
    c.end_borrow(2).unwrap();
    c.borrow_implicit(1, 3, Shared).unwrap();
    c.end_borrow(3).unwrap();
}

#[test]
fn borrow_cannot_escape_or_cross_await_without_proven_continuation() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.bind("a").unwrap();
    c.borrow_named(1, 2, Shared, "a").unwrap();
    assert_eq!(c.return_loan(2), Err(Error::LoanEscape));
    assert_eq!(c.suspend(), Err(Error::SuspendWithLiveLoan));
    c.end_borrow(2).unwrap();
    assert_eq!(c.suspend(), Ok(()));
}

#[test]
fn a_scope_with_unended_loan_fails_closed_without_mutating_the_scope() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.enter_scope().unwrap();
    c.bind("a").unwrap();
    c.borrow_named(1, 3, Shared, "a").unwrap();
    assert_eq!(c.leave_scope(), Err(Error::LiveLoanAtExit));
    c.end_borrow(3).unwrap();
    c.leave_scope().unwrap();
    assert_eq!(c.leave_scope(), Err(Error::RootScopeExit));
}

#[test]
fn drop_bang_rejected_while_a_named_or_implicit_loan_is_live() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.bind("a").unwrap();
    c.borrow_named(1, 2, Shared, "a").unwrap();
    assert_eq!(c.drop_owner(1), Err(Error::CannotDropBorrowedOwner));
    c.end_borrow(2).unwrap();
    c.drop_owner(1).unwrap();
    assert_eq!(c.borrow_named(1, 3, Shared, "a"), Err(Error::UnknownOwner));
    assert_eq!(c.drop_owner(1), Err(Error::UnknownOwner));
}

#[test]
fn loan_and_owner_ids_cannot_be_reused_after_scope_exit_or_drop() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.bind("a").unwrap();
    c.borrow_named(1, 2, Shared, "a").unwrap();
    c.end_borrow(2).unwrap();
    assert_eq!(c.borrow_named(1, 2, Shared, "a"), Err(Error::DuplicateLoan));
    c.drop_owner(1).unwrap();
    assert_eq!(c.own(1), Err(Error::DuplicateOwner));
}

#[test]
fn unseen_lifetime_owner_and_loan_are_diagnosed() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    assert_eq!(
        c.borrow_named(1, 2, Shared, "missing"),
        Err(Error::UnknownBinder)
    );
    assert_eq!(c.borrow_implicit(9, 2, Shared), Err(Error::UnknownOwner));
    assert_eq!(c.end_borrow(2), Err(Error::UnknownLoan));
    assert_eq!(c.return_loan(2), Err(Error::UnknownLoan));
}

#[test]
fn nested_binder_name_may_be_reused_only_after_prior_scope_exits() {
    let mut c = Lifetimes::new();
    c.enter_scope().unwrap();
    c.bind("a").unwrap();
    c.enter_scope().unwrap();
    assert_eq!(c.bind("a"), Err(Error::DuplicateBinder));
    c.leave_scope().unwrap();
    c.leave_scope().unwrap();
    c.enter_scope().unwrap();
    c.bind("a").unwrap();
    c.leave_scope().unwrap();
}

#[test]
fn historical_owner_budget_cannot_be_evaded_by_dropping_or_leaving_scopes() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    for id in 2..=4096 {
        c.enter_scope().unwrap();
        c.own(id).unwrap();
        c.drop_owner(id).unwrap();
        c.leave_scope().unwrap();
    }
    assert_eq!(c.own(4097), Err(Error::ScopeBudget));
    assert_eq!(c.own(2), Err(Error::DuplicateOwner));
    assert_eq!(c.own(0), Err(Error::DuplicateOwner));
    assert_eq!(c.borrow_implicit(4097, 1, Shared), Err(Error::UnknownOwner));
    c.borrow_implicit(1, 1, Shared).unwrap();
    c.end_borrow(1).unwrap();
    c.drop_owner(1).unwrap();
}

#[test]
fn binder_byte_boundary_is_checked_before_allocation() {
    let mut c = Lifetimes::new();
    let valid = "a".repeat(256);
    let too_long = "a".repeat(257);
    assert_eq!(c.bind(&too_long), Err(Error::ScopeBudget));
    assert_eq!(c.bind(&valid), Ok(()));
    assert_eq!(c.bind(&valid), Err(Error::DuplicateBinder));
    c.own(1).unwrap();
    assert_eq!(
        c.borrow_named(1, 1, Shared, &too_long),
        Err(Error::UnknownBinder)
    );
    c.borrow_named(1, 1, Shared, &valid).unwrap();
    c.end_borrow(1).unwrap();
}

#[test]
fn historical_loan_budget_is_distinct_from_duplicate_and_failed_borrow_is_atomic() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    for loan in 1..=1024 {
        c.borrow_implicit(1, loan, Shared).unwrap();
        c.end_borrow(loan).unwrap();
    }
    assert_eq!(c.borrow_implicit(1, 1025, Mutable), Err(Error::ScopeBudget));
    assert_eq!(c.borrow_implicit(1, 1, Shared), Err(Error::DuplicateLoan));
    assert_eq!(c.end_borrow(1025), Err(Error::UnknownLoan));
    assert_eq!(c.suspend(), Ok(()));
    c.drop_owner(1).unwrap();
}

#[test]
fn ended_implicit_borrow_releases_owner_without_named_lifetime() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.borrow_implicit(1, 1, Shared).unwrap();
    assert_eq!(c.borrow_implicit(1, 2, Mutable), Err(Error::Conflict));
    c.end_borrow(1).unwrap();
    c.borrow_implicit(1, 2, Mutable).unwrap();
    c.end_borrow(2).unwrap();
    c.suspend().unwrap();
    c.drop_owner(1).unwrap();
}

#[test]
fn owner_loan_counts_are_independent_and_release_only_the_matching_loan() {
    let mut c = Lifetimes::new();
    for owner in 1..=128 {
        c.own(owner).unwrap();
        c.borrow_implicit(owner, owner, Shared).unwrap();
    }
    c.borrow_implicit(1, 129, Shared).unwrap();
    c.end_borrow(1).unwrap();
    assert_eq!(c.borrow_implicit(1, 130, Mutable), Err(Error::Conflict));
    assert_eq!(c.drop_owner(1), Err(Error::CannotDropBorrowedOwner));
    c.end_borrow(129).unwrap();
    c.borrow_implicit(1, 130, Mutable).unwrap();
    assert_eq!(c.borrow_implicit(1, 131, Shared), Err(Error::Conflict));
    c.end_borrow(130).unwrap();
    c.drop_owner(1).unwrap();
    assert_eq!(c.drop_owner(2), Err(Error::CannotDropBorrowedOwner));
    for owner in 2..=128 {
        c.end_borrow(owner).unwrap();
        c.drop_owner(owner).unwrap();
    }
    assert_eq!(c.suspend(), Ok(()));
}

#[test]
fn loan_scope_counts_follow_issue_depth_even_when_ended_in_a_child() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.bind("outer").unwrap();
    c.borrow_implicit(1, 1, Shared).unwrap();
    c.enter_scope().unwrap();
    c.borrow_named(1, 2, Shared, "outer").unwrap();
    c.enter_scope().unwrap();
    c.end_borrow(1).unwrap();
    c.leave_scope().unwrap();
    assert_eq!(c.leave_scope(), Err(Error::LiveLoanAtExit));
    assert_eq!(c.end_borrow(1), Err(Error::UnknownLoan));
    c.end_borrow(2).unwrap();
    c.leave_scope().unwrap();
    c.borrow_implicit(1, 3, Mutable).unwrap();
    c.end_borrow(3).unwrap();
    c.drop_owner(1).unwrap();
}

#[test]
fn unrelated_scope_can_exit_with_outer_exclusive_loan() {
    let mut c = Lifetimes::new();
    c.own(1).unwrap();
    c.borrow_implicit(1, 1, Mutable).unwrap();
    c.enter_scope().unwrap();
    c.own(2).unwrap();
    c.borrow_implicit(2, 2, Mutable).unwrap();
    assert_eq!(c.leave_scope(), Err(Error::LiveLoanAtExit));
    c.end_borrow(2).unwrap();
    c.leave_scope().unwrap();
    assert_eq!(c.drop_owner(2), Err(Error::UnknownOwner));
    assert_eq!(c.drop_owner(1), Err(Error::CannotDropBorrowedOwner));
    c.end_borrow(1).unwrap();
    c.drop_owner(1).unwrap();
}

use atto_borrow_checker::lifetime_v1::{
    resolve_return_contract, BorrowedFormal, ReturnContractError,
};

fn formal(lifetime: Option<u16>, mutable: bool) -> BorrowedFormal {
    BorrowedFormal { lifetime, mutable }
}

#[test]
fn single_input_elision_and_named_selection_are_distinct() {
    let one = resolve_return_contract(0, &[formal(None, false)], formal(None, false)).unwrap();
    assert_eq!(one.allowed_origins(), &[0]);
    assert_eq!(one.check_origins(&[Some(0), Some(0)]), Ok(()));
    assert_eq!(
        one.check_origins(&[None]),
        Err(ReturnContractError::InvalidOrigin)
    );
    let inputs = [formal(Some(0), false), formal(Some(1), false)];
    assert_eq!(
        resolve_return_contract(2, &inputs, formal(None, false)),
        Err(ReturnContractError::Ambiguous)
    );
    let left = resolve_return_contract(2, &inputs, formal(Some(0), false)).unwrap();
    assert_eq!(left.allowed_origins(), &[0]);
    assert_eq!(
        left.check_origins(&[Some(0), Some(1)]),
        Err(ReturnContractError::InvalidOrigin)
    );
}

#[test]
fn same_named_region_admits_multiple_origins_without_granting_mutability() {
    let inputs = [formal(Some(0), false), formal(Some(0), true)];
    let contract = resolve_return_contract(1, &inputs, formal(Some(0), false)).unwrap();
    assert_eq!(contract.allowed_origins(), &[0, 1]);
    assert_eq!(contract.check_origins(&[Some(1), Some(0)]), Ok(()));
    assert_eq!(
        resolve_return_contract(1, &inputs, formal(Some(0), true)),
        Err(ReturnContractError::Mutability)
    );
    assert!(resolve_return_contract(0, &[formal(None, true)], formal(None, true)).is_ok());
}

#[test]
fn malformed_or_unbacked_signature_and_return_census_fail_closed() {
    use ReturnContractError::*;
    assert_eq!(
        resolve_return_contract(0, &[], formal(None, false)),
        Err(NoInput)
    );
    assert_eq!(
        resolve_return_contract(1, &[formal(None, false)], formal(Some(0), false)),
        Err(NoInput)
    );
    assert_eq!(
        resolve_return_contract(1, &[formal(Some(1), false)], formal(Some(0), false)),
        Err(UnknownLifetime)
    );
    assert_eq!(
        resolve_return_contract(0, &[formal(None, false)], formal(Some(0), false)),
        Err(UnknownLifetime)
    );
    let contract = resolve_return_contract(0, &[formal(None, false)], formal(None, false)).unwrap();
    assert_eq!(contract.check_origins(&[]), Err(NoReturnEvidence));
    assert_eq!(
        contract.check_origins(&[Some(usize::MAX)]),
        Err(InvalidOrigin)
    );
    assert_eq!(contract.check_origins(&vec![Some(0); 1025]), Err(Budget));
    assert_eq!(
        resolve_return_contract(0, &vec![formal(None, false); 1025], formal(None, false)),
        Err(Budget)
    );
    assert_eq!(
        resolve_return_contract(1025, &[formal(None, false)], formal(None, false)),
        Err(Budget)
    );
}
