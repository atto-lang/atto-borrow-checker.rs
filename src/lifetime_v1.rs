//! Conservative named lifetime model for lt! a and Borrow<T, lt=a>.
//!
//! This is a type/loan constraint checker, not guest pointer codegen.
//! Explicit named lifetimes never grant extra ownership or turn a borrow into
//! something Sendable. Implicit argument borrowing uses the same machinery.
use crate::{BorrowKind, LoanId, OwnerId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SCOPE_DEPTH: usize = 128;
const MAX_BINDERS: usize = 1024;
// Bound retained identifier bytes and the historical owner-ID census.
const MAX_BINDER_BYTES: usize = 256;
const MAX_OWNERS: usize = 4096;
const MAX_LOANS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidName,
    DuplicateBinder,
    UnknownBinder,
    DuplicateOwner,
    UnknownOwner,
    DuplicateLoan,
    UnknownLoan,
    OutlivesOwner,
    Conflict,
    LoanEscape,
    LiveLoanAtExit,
    SuspendWithLiveLoan,
    CannotDropBorrowedOwner,
    ScopeBudget,
    RootScopeExit,
}

#[derive(Debug, Default)]
struct Scope {
    names: Vec<String>,
    owners: Vec<OwnerId>,
}
#[derive(Debug)]
struct Loan {
    owner: OwnerId,
    mutable: bool,
    depth: usize,
}

/// All identities are trusted compiler-generated owner/loan IDs. The model
/// rejects reuse across nested scopes so old SSA references cannot resurrect.
#[derive(Debug)]
pub struct Lifetimes {
    scopes: Vec<Scope>,
    binders: BTreeMap<String, usize>,
    owners: BTreeMap<OwnerId, usize>,
    loans: BTreeMap<LoanId, Loan>,
    seen_owners: BTreeSet<OwnerId>,
    seen_loans: BTreeSet<LoanId>,
}
impl Default for Lifetimes {
    fn default() -> Self {
        Self::new()
    }
}
impl Lifetimes {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::default()],
            binders: BTreeMap::new(),
            owners: BTreeMap::new(),
            loans: BTreeMap::new(),
            seen_owners: BTreeSet::new(),
            seen_loans: BTreeSet::new(),
        }
    }
    fn depth(&self) -> usize {
        self.scopes.len() - 1
    }

    /// Both lt! a and lifetime! a are type-level binders; Rust apostrophe
    /// lifetime names are intentionally invalid AttoLang.
    pub fn bind(&mut self, name: &str) -> Result<(), Error> {
        if name.len() > MAX_BINDER_BYTES {
            return Err(Error::ScopeBudget);
        }
        if name.is_empty()
            || !name
                .bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(Error::InvalidName);
        }
        if self.binders.contains_key(name) {
            return Err(Error::DuplicateBinder);
        }
        if self.binders.len() >= MAX_BINDERS {
            return Err(Error::ScopeBudget);
        }
        self.binders.insert(name.to_owned(), self.depth());
        self.scopes
            .last_mut()
            .expect("root exists")
            .names
            .push(name.to_owned());
        Ok(())
    }
    pub fn enter_scope(&mut self) -> Result<(), Error> {
        if self.scopes.len() >= MAX_SCOPE_DEPTH {
            return Err(Error::ScopeBudget);
        }
        self.scopes.push(Scope::default());
        Ok(())
    }
    /// A loan cannot silently escape a lexical scope via a temporary,
    /// exceptional edge, or a hidden compiler local.
    pub fn leave_scope(&mut self) -> Result<(), Error> {
        if self.scopes.len() == 1 {
            return Err(Error::RootScopeExit);
        }
        let depth = self.depth();
        if self.loans.values().any(|l| l.depth >= depth) {
            return Err(Error::LiveLoanAtExit);
        }
        let ended = self.scopes.pop().expect("checked nonroot scope");
        for name in ended.names {
            self.binders.remove(&name);
        }
        for id in ended.owners {
            self.owners.remove(&id);
        }
        Ok(())
    }
    pub fn own(&mut self, id: OwnerId) -> Result<(), Error> {
        if id == 0 || self.seen_owners.contains(&id) {
            return Err(Error::DuplicateOwner);
        }
        if self.seen_owners.len() >= MAX_OWNERS {
            return Err(Error::ScopeBudget);
        }
        self.seen_owners.insert(id);
        self.owners.insert(id, self.depth());
        self.scopes.last_mut().expect("root exists").owners.push(id);
        Ok(())
    }

    pub fn borrow_named(
        &mut self,
        owner: OwnerId,
        loan: LoanId,
        kind: BorrowKind,
        lifetime: &str,
    ) -> Result<(), Error> {
        let binder_depth = *self.binders.get(lifetime).ok_or(Error::UnknownBinder)?;
        self.borrow_at(owner, loan, kind, binder_depth)
    }
    /// Nonprimitive function parameters borrow implicitly, without a source
    /// Borrow<T> wrapper or an explicit call-site borrow! operation.
    pub fn borrow_implicit(
        &mut self,
        owner: OwnerId,
        loan: LoanId,
        kind: BorrowKind,
    ) -> Result<(), Error> {
        self.borrow_at(owner, loan, kind, self.depth())
    }
    fn borrow_at(
        &mut self,
        owner: OwnerId,
        loan: LoanId,
        kind: BorrowKind,
        binder_depth: usize,
    ) -> Result<(), Error> {
        let owner_depth = *self.owners.get(&owner).ok_or(Error::UnknownOwner)?;
        // Lifetime declared outside the owner's lexical storage cannot
        // outlive the owner. This is a conservative outlives constraint.
        if binder_depth < owner_depth {
            return Err(Error::OutlivesOwner);
        }
        if loan == 0 || self.seen_loans.contains(&loan) {
            return Err(Error::DuplicateLoan);
        }
        if self.seen_loans.len() >= MAX_LOANS {
            return Err(Error::ScopeBudget);
        }
        let mutable = kind == BorrowKind::Mutable;
        if self
            .loans
            .values()
            .any(|l| l.owner == owner && (l.mutable || mutable))
        {
            return Err(Error::Conflict);
        }
        self.seen_loans.insert(loan);
        self.loans.insert(
            loan,
            Loan {
                owner,
                mutable,
                depth: self.depth(),
            },
        );
        Ok(())
    }
    pub fn end_borrow(&mut self, id: LoanId) -> Result<(), Error> {
        self.loans.remove(&id).map(|_| ()).ok_or(Error::UnknownLoan)
    }
    /// Return signatures that prove longer outlives relations are a later
    /// profile. V1 never allows an arbitrary borrowed local to escape.
    pub fn return_loan(&self, id: LoanId) -> Result<(), Error> {
        if !self.loans.contains_key(&id) {
            return Err(Error::UnknownLoan);
        }
        Err(Error::LoanEscape)
    }
    pub fn suspend(&self) -> Result<(), Error> {
        if self.loans.is_empty() {
            Ok(())
        } else {
            Err(Error::SuspendWithLiveLoan)
        }
    }
    pub fn drop_owner(&mut self, owner: OwnerId) -> Result<(), Error> {
        if !self.owners.contains_key(&owner) {
            return Err(Error::UnknownOwner);
        }
        if self.loans.values().any(|loan| loan.owner == owner) {
            return Err(Error::CannotDropBorrowedOwner);
        }
        self.owners.remove(&owner);
        Ok(())
    }
}
