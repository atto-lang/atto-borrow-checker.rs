//! Strict, bounded task cancellation/lock cleanup PATH oracle (V1 target).
//! This verifies caller-supplied typed CFG exit paths. It does NOT independently
//! discover exits, bind runtime callbacks, implement locking, or certify guests.
//! The producing compiler must independently enumerate every exit and bind
//! source/MIR facts before accepting a proof for code generation.
use std::collections::BTreeSet;

const MAX_PATHS: usize = 4096;
const MAX_EVENTS_PER_PATH: usize = 16384;
const MAX_TOTAL_EVENTS: usize = 65536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitKind { Return, Throw, Raise, Panic, Cancelled, Timeout }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// Created only after an authenticated lock grant + checked lease entry.
    LockAcquired { lease: u64 },
    /// Exact-token guard disposal in reverse acquisition order.
    LockReleased { lease: u64 },
    /// Neither await nor scheduler handoff may occur under a synchronous lease.
    Suspension,
    /// Cooperative safe point; requires unwind before terminal publication.
    CancellationObserved,
    /// A child is part of the same tenant/actor structured TaskScope.
    ChildAdmitted { id: u64, tenant: u64, actor: u64 },
    /// A *physical* quiescence acknowledgment, not a cancellation request.
    ChildPhysicallyRetired { id: u64 },
    /// Terminal completion after ALL active guards and descendants retired.
    ScopePhysicallyRetired,
}

#[derive(Clone, Debug)]
pub struct ExitPath {
    pub id: u64,
    pub kind: ExitKind,
    pub tenant: u64,
    pub actor: u64,
    pub events: Vec<Event>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub path_id: u64,
    pub event_index: usize,
}

fn bad(code: &'static str, path: &ExitPath, at: usize) -> Diagnostic {
    Diagnostic { code, path_id: path.id, event_index: at }
}

/// The expected id census MUST be provided by an independent compiler pass.
/// A successful result proves only submitted-path internal consistency.
pub fn verify_cancel_unwind_paths(
    paths: &[ExitPath],
    expected_path_ids: &[u64],
) -> Result<(), Diagnostic> {
    let envelope = Diagnostic { code: "E_TASK_CLEANUP_CENSUS", path_id: 0, event_index: 0 };
    if paths.is_empty() || paths.len() > MAX_PATHS || expected_path_ids.len() != paths.len() {
        return Err(envelope);
    }
    let mut expected = BTreeSet::new();
    for &id in expected_path_ids {
        if id == 0 || !expected.insert(id) { return Err(envelope); }
    }
    let mut seen = BTreeSet::new();
    let mut total_events = 0usize;
    for path in paths {
        if path.id == 0 || !expected.contains(&path.id) || !seen.insert(path.id)
            || path.tenant == 0 || path.actor == 0 {
            return Err(bad("E_TASK_CLEANUP_CENSUS", path, 0));
        }
        total_events = total_events.saturating_add(path.events.len());
        if path.events.is_empty() || path.events.len() > MAX_EVENTS_PER_PATH
            || total_events > MAX_TOTAL_EVENTS {
            return Err(bad("E_TASK_CLEANUP_BUDGET", path, 0));
        }
        let mut locks = Vec::<u64>::new();
        let mut acquired = BTreeSet::new();
        let mut children = BTreeSet::new();
        let mut all_children = BTreeSet::new();
        let mut cancel_seen = false;
        let mut terminal = false;
        for (at, event) in path.events.iter().copied().enumerate() {
            if terminal { return Err(bad("E_TASK_AFTER_RETIRE", path, at)); }
            match event {
                Event::LockAcquired { lease } => {
                    if cancel_seen { return Err(bad("E_TASK_ADMIT_AFTER_CANCEL", path, at)); }
                    if lease == 0 || !acquired.insert(lease) {
                        return Err(bad("E_TASK_LEASE_REPLAY", path, at));
                    }
                    locks.push(lease);
                }
                Event::LockReleased { lease } => {
                    if locks.pop() != Some(lease) {
                        return Err(bad("E_TASK_LOCK_CLEANUP_ORDER", path, at));
                    }
                }
                Event::Suspension => {
                    if !locks.is_empty() { return Err(bad("E_GUARD_SUSPEND", path, at)); }
                    if cancel_seen { return Err(bad("E_TASK_SUSPEND_DURING_UNWIND", path, at)); }
                }
                Event::CancellationObserved => {
                    if cancel_seen { return Err(bad("E_TASK_CANCEL_REPLAY", path, at)); }
                    cancel_seen = true;
                }
                Event::ChildAdmitted { id, tenant, actor } => {
                    if cancel_seen { return Err(bad("E_TASK_ADMIT_AFTER_CANCEL", path, at)); }
                    if id == 0 || tenant != path.tenant || actor != path.actor {
                        return Err(bad("E_TASK_TENANT_SCOPE", path, at));
                    }
                    if !all_children.insert(id) { return Err(bad("E_TASK_CHILD_REPLAY", path, at)); }
                    children.insert(id);
                }
                Event::ChildPhysicallyRetired { id } => {
                    if !children.remove(&id) {
                        return Err(bad("E_TASK_CHILD_RETIRE_REPLAY", path, at));
                    }
                }
                Event::ScopePhysicallyRetired => {
                    if !locks.is_empty() { return Err(bad("E_TASK_LOCK_LEAK", path, at)); }
                    if !children.is_empty() { return Err(bad("E_TASK_CHILD_NOT_RETIRED", path, at)); }
                    if matches!(path.kind, ExitKind::Cancelled | ExitKind::Timeout) && !cancel_seen {
                        return Err(bad("E_TASK_CANCEL_UNOBSERVED", path, at));
                    }
                    // Once a task has observed cancellation, its final state
                    // cannot be silently rewritten into a successful Return.
                    // A typed cancellation outcome remains distinct from T.
                    if cancel_seen && matches!(path.kind, ExitKind::Return) {
                        return Err(bad("E_TASK_CANCEL_TERMINAL", path, at));
                    }
                    terminal = true;
                }
            }
        }
        if !terminal {
            return Err(bad("E_TASK_NOT_PHYSICALLY_RETIRED", path, path.events.len()));
        }
    }
    if seen != expected { return Err(envelope); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(kind: ExitKind, events: Vec<Event>) -> ExitPath {
        ExitPath { id: 1, kind, tenant: 7, actor: 9, events }
    }
    fn check(kind: ExitKind, events: Vec<Event>) -> Result<(), Diagnostic> {
        verify_cancel_unwind_paths(&[path(kind, events)], &[1])
    }
    fn err(kind: ExitKind, events: Vec<Event>) -> &'static str {
        check(kind, events).expect_err("must reject unsafe task cleanup").code
    }
    const RET: Event = Event::ScopePhysicallyRetired;
    const CAN: Event = Event::CancellationObserved;
    fn lock(id: u64) -> Event { Event::LockAcquired { lease: id } }
    fn release(id: u64) -> Event { Event::LockReleased { lease: id } }
    fn child(id: u64) -> Event {
        Event::ChildAdmitted { id, tenant: 7, actor: 9 }
    }
    fn retired(id: u64) -> Event { Event::ChildPhysicallyRetired { id } }

    #[test]
    fn normal_and_exception_paths_release_every_lease_lifo() {
        for kind in [ExitKind::Return, ExitKind::Throw, ExitKind::Raise, ExitKind::Panic] {
            assert_eq!(check(kind, vec![lock(1), lock(2), release(2), release(1), RET]), Ok(()));
        }
    }
    #[test]
    fn cancellation_and_timeout_release_locks_and_retire_children() {
        for kind in [ExitKind::Cancelled, ExitKind::Timeout] {
            assert_eq!(check(kind, vec![child(10), lock(1), lock(2), CAN,
                release(2), release(1), retired(10), RET]), Ok(()));
        }
    }
    #[test]
    fn unfinished_lease_or_early_retirement_rejected() {
        assert_eq!(err(ExitKind::Cancelled, vec![lock(1), CAN, RET]), "E_TASK_LOCK_LEAK");
        assert_eq!(err(ExitKind::Return, vec![lock(1)]), "E_TASK_NOT_PHYSICALLY_RETIRED");
    }
    #[test]
    fn cleanup_cannot_release_out_of_order_or_replay_a_lease() {
        assert_eq!(err(ExitKind::Cancelled, vec![lock(1), lock(2), CAN,
            release(1), release(2), RET]), "E_TASK_LOCK_CLEANUP_ORDER");
        assert_eq!(err(ExitKind::Return, vec![lock(1), release(1), release(1), RET]),
            "E_TASK_LOCK_CLEANUP_ORDER");
        assert_eq!(err(ExitKind::Return, vec![lock(1), release(1), lock(1), RET]),
            "E_TASK_LEASE_REPLAY");
    }
    #[test]
    fn no_suspend_or_new_lock_during_cancellation_unwind() {
        assert_eq!(err(ExitKind::Cancelled, vec![lock(1), Event::Suspension, CAN,
            release(1), RET]), "E_GUARD_SUSPEND");
        assert_eq!(err(ExitKind::Cancelled, vec![CAN, Event::Suspension, RET]),
            "E_TASK_SUSPEND_DURING_UNWIND");
        assert_eq!(err(ExitKind::Cancelled, vec![CAN, lock(1), release(1), RET]),
            "E_TASK_ADMIT_AFTER_CANCEL");
    }
    #[test]
    fn cancellation_is_not_retirement_and_child_join_is_mandatory() {
        assert_eq!(err(ExitKind::Cancelled, vec![CAN, child(1), RET]),
            "E_TASK_ADMIT_AFTER_CANCEL");
        assert_eq!(err(ExitKind::Cancelled, vec![child(1), CAN, RET]),
            "E_TASK_CHILD_NOT_RETIRED");
        assert_eq!(err(ExitKind::Cancelled, vec![RET]), "E_TASK_CANCEL_UNOBSERVED");
    }
    #[test]
    fn cancellation_observed_cannot_be_reclassified_as_success() {
        assert_eq!(err(ExitKind::Return, vec![CAN, RET]), "E_TASK_CANCEL_TERMINAL");
        assert_eq!(err(ExitKind::Return, vec![lock(1), CAN, release(1), RET]),
            "E_TASK_CANCEL_TERMINAL");
        assert_eq!(check(ExitKind::Cancelled, vec![lock(1), CAN, release(1), RET]), Ok(()));
        // A task that completes successfully before cancellation is observed
        // remains a valid one-shot success outcome.
        assert_eq!(check(ExitKind::Return, vec![lock(1), release(1), RET]), Ok(()));
    }
    #[test]
    fn cannot_forge_foreign_children_or_reuse_child_ids() {
        assert_eq!(err(ExitKind::Return, vec![
            Event::ChildAdmitted { id: 1, tenant: 8, actor: 9 }, RET
        ]), "E_TASK_TENANT_SCOPE");
        assert_eq!(err(ExitKind::Return, vec![child(1), child(1), retired(1), RET]),
            "E_TASK_CHILD_REPLAY");
        assert_eq!(err(ExitKind::Return, vec![child(1), retired(1), retired(1), RET]),
            "E_TASK_CHILD_RETIRE_REPLAY");
    }
    #[test]
    fn only_one_terminal_publication_and_complete_independent_census() {
        assert_eq!(err(ExitKind::Return, vec![RET, RET]), "E_TASK_AFTER_RETIRE");
        let p = path(ExitKind::Return, vec![RET]);
        assert_eq!(verify_cancel_unwind_paths(&[p], &[1, 2]).unwrap_err().code,
            "E_TASK_CLEANUP_CENSUS");
    }
    #[test]
    fn budget_limits_are_fail_closed() {
        assert_eq!(err(ExitKind::Return, vec![Event::Suspension; MAX_EVENTS_PER_PATH + 1]),
            "E_TASK_CLEANUP_BUDGET");
    }
}
