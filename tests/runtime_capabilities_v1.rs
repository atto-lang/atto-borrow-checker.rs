//! Host-model tests with real allocation, Arc/Weak upgrade and RwLock
//! retirement. These are not claims of guest-language backend integration.
use atto_borrow_checker::runtime_capabilities_v1::{
    CapabilityError as E, FreezeLimits, GraphNode, NodeKind, StablePinned, UniqueGraph,
};
use std::marker::PhantomPinned;
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

fn node(id: u32, children: &[u32]) -> GraphNode {
    GraphNode {
        id,
        kind: NodeKind::Plain,
        payload: vec![id as u8],
        children: children.to_vec(),
    }
}
fn cycle(domain: u64) -> UniqueGraph {
    UniqueGraph::new(
        domain,
        1,
        vec![node(1, &[2, 3]), node(2, &[3]), node(3, &[1])],
    )
    .expect("trusted test model has a nonzero domain")
}
fn freeze(graph: UniqueGraph) -> atto_borrow_checker::runtime_capabilities_v1::FrozenOwner {
    graph
        .freeze(FreezeLimits::default())
        .expect("bounded, exclusive graph must freeze")
}

#[test]
fn freezes_complete_cyclic_graph_and_exposes_only_immutable_views() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let reader = owner.share();
    let (root, count, bytes, next) = reader
        .read(&permit, |graph| {
            (
                graph.root(),
                graph.node_count(),
                graph.node(2).unwrap().payload().to_vec(),
                graph.node(1).unwrap().children().to_vec(),
            )
        })
        .unwrap();
    assert_eq!((root, count), (1, 3));
    assert_eq!(bytes, vec![2]);
    assert_eq!(next, vec![2, 3]);
}

#[test]
fn deep_copy_independently_clones_nested_payloads_and_retains_cycle_edges() {
    let mut source = cycle(17);
    let mut copy = source.deep_copy(FreezeLimits::default()).unwrap();
    assert_eq!(source.children(1), Some(&[2, 3][..]));
    assert_eq!(copy.children(1), Some(&[2, 3][..]));
    assert_eq!(copy.children(3), Some(&[1][..])); // cycle remains internal
    assert_eq!(source.payload(2), Some(&[2][..]));
    assert_eq!(copy.payload(2), Some(&[2][..]));
    // Both buffers contain identical bytes, but not the same heap memory.
    assert_ne!(
        source.payload(2).unwrap().as_ptr(),
        copy.payload(2).unwrap().as_ptr()
    );
    copy.replace_payload(2, vec![88, 89]).unwrap();
    assert_eq!(source.payload(2), Some(&[2][..]));
    assert_eq!(copy.payload(2), Some(&[88, 89][..]));
    source.replace_payload(3, vec![12]).unwrap();
    assert_eq!(copy.payload(3), Some(&[3][..]));
    // Both owners remain independently valid for subsequent freezing.
    freeze(source);
    freeze(copy);
}

#[test]
fn deep_copy_preserves_duplicate_internal_references_without_external_aliases() {
    // Two edges in the copy must still refer to ONE cloned local node,
    // not accidentally produce two disjoint children or alias the source.
    let original = UniqueGraph::new(19, 1, vec![node(1, &[2, 2]), node(2, &[1])]).unwrap();
    let mut copy = original.deep_copy(FreezeLimits::default()).unwrap();
    assert_eq!(copy.children(1), Some(&[2, 2][..]));
    copy.replace_payload(2, vec![90]).unwrap();
    assert_eq!(copy.payload(2), Some(&[90][..]));
    assert_eq!(original.payload(2), Some(&[2][..]));
}

#[test]
fn deep_copy_rejects_external_mutable_edges_before_copying() {
    for kind in [
        NodeKind::ExternalMutableAlias,
        NodeKind::InteriorMutable,
        NodeKind::ForeignPointer,
        NodeKind::UnverifiedDynamic,
    ] {
        let mut external = node(2, &[]);
        external.kind = kind;
        let source = UniqueGraph::new(17, 1, vec![node(1, &[2]), external]).unwrap();
        assert_eq!(
            source.deep_copy(FreezeLimits::default()).unwrap_err(),
            E::UnfreezableEdge
        );
        // The source remains owned, not consumed by a failed copy.
        assert_eq!(source.payload(1), Some(&[1][..]));
    }
}

#[test]
fn deep_copy_preflights_graph_limits_and_missing_edges() {
    let source = cycle(17);
    assert_eq!(
        source
            .deep_copy(FreezeLimits {
                max_nodes: 100,
                max_edges: 1,
                max_bytes: 4096,
            })
            .unwrap_err(),
        E::BudgetExceeded
    );
    let missing = UniqueGraph::new(17, 1, vec![node(1, &[999])]).unwrap();
    assert_eq!(
        missing.deep_copy(FreezeLimits::default()).unwrap_err(),
        E::UnknownEdge
    );
}

#[test]
fn freeze_failure_returns_original_exclusive_graph() {
    let mut invalid = node(1, &[2]);
    invalid.kind = NodeKind::ExternalMutableAlias;
    let graph = UniqueGraph::new(17, 1, vec![invalid, node(2, &[])]).unwrap();
    let (error, original) = graph.freeze(FreezeLimits::default()).unwrap_err();
    assert_eq!(error, E::UnfreezableEdge);
    // No ownership was silently consumed or leaked on a validation failure.
    let (next_error, _) = original.freeze(FreezeLimits::default()).unwrap_err();
    assert_eq!(next_error, E::UnfreezableEdge);
}

#[test]
fn refuses_every_unproven_mutable_or_foreign_graph_edge() {
    for kind in [
        NodeKind::ExternalMutableAlias,
        NodeKind::InteriorMutable,
        NodeKind::ForeignPointer,
        NodeKind::UnverifiedDynamic,
    ] {
        let mut child = node(2, &[]);
        child.kind = kind;
        let graph = UniqueGraph::new(17, 1, vec![node(1, &[2]), child]).unwrap();
        assert_eq!(
            graph.freeze(FreezeLimits::default()).unwrap_err().0,
            E::UnfreezableEdge,
            "{kind:?}"
        );
    }
}

#[test]
fn rejects_missing_children_and_unreachable_graph_components() {
    let missing = UniqueGraph::new(17, 1, vec![node(1, &[999])]).unwrap();
    assert_eq!(
        missing.freeze(FreezeLimits::default()).unwrap_err().0,
        E::UnknownEdge
    );
    let disconnected = UniqueGraph::new(17, 1, vec![node(1, &[]), node(2, &[])]).unwrap();
    assert_eq!(
        disconnected.freeze(FreezeLimits::default()).unwrap_err().0,
        E::DisconnectedGraph
    );
}

#[test]
fn rejects_duplicate_zero_and_missing_root_ids() {
    let duplicate = UniqueGraph::new(17, 1, vec![node(1, &[1]), node(1, &[])]).unwrap();
    assert_eq!(
        duplicate.freeze(FreezeLimits::default()).unwrap_err().0,
        E::DuplicateNode
    );
    let zero = UniqueGraph::new(17, 1, vec![node(0, &[])]).unwrap();
    assert_eq!(
        zero.freeze(FreezeLimits::default()).unwrap_err().0,
        E::InvalidNode
    );
    let wrong_root = UniqueGraph::new(17, 4, vec![node(1, &[])]).unwrap();
    assert_eq!(
        wrong_root.freeze(FreezeLimits::default()).unwrap_err().0,
        E::UnknownEdge
    );
    assert!(matches!(
        UniqueGraph::new(0, 1, vec![node(1, &[])]),
        Err(E::InvalidDomain)
    ));
}

#[test]
fn charges_node_edge_and_byte_budgets_before_freeze_publication() {
    let graph = cycle(17);
    assert_eq!(
        graph
            .freeze(FreezeLimits {
                max_nodes: 2,
                max_edges: 10,
                max_bytes: 10,
            })
            .unwrap_err()
            .0,
        E::BudgetExceeded
    );
    let graph = cycle(17);
    assert_eq!(
        graph
            .freeze(FreezeLimits {
                max_nodes: 10,
                max_edges: 1,
                max_bytes: 10,
            })
            .unwrap_err()
            .0,
        E::BudgetExceeded
    );
    let graph = cycle(17);
    assert_eq!(
        graph
            .freeze(FreezeLimits {
                max_nodes: 10,
                max_edges: 10,
                max_bytes: 2,
            })
            .unwrap_err()
            .0,
        E::BudgetExceeded
    );
}

#[test]
fn weak_upgrade_works_only_for_exact_owner_minted_region_rights() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let weak = owner.downgrade();
    assert_eq!(
        weak.upgrade(&permit)
            .unwrap()
            .read(&permit, |g| g.node_count()),
        Ok(3)
    );
    // Same numerical domain is not enough: a permit belongs to one region.
    let other = freeze(cycle(17));
    let wrong = other.issue_read_permit();
    assert!(weak.upgrade(&wrong).is_none());
    assert_eq!(
        owner.share().read(&wrong, |g| g.node_count()),
        Err(E::WrongDomain)
    );
    let foreign = freeze(cycle(77)).issue_read_permit();
    assert!(weak.upgrade(&foreign).is_none());
}

#[test]
fn retirement_invalidates_weak_upgrades_and_existing_strong_reads() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let strong = owner.share();
    let weak = strong.downgrade();
    assert!(weak.upgrade(&permit).is_some());
    assert_eq!(owner.retire(), Ok(()));
    assert!(weak.upgrade(&permit).is_none());
    assert_eq!(strong.read(&permit, |g| g.node_count()), Err(E::Retired));
    // Idempotent retirement does not reopen the region.
    assert_eq!(owner.retire(), Ok(()));
}

#[test]
fn dropping_host_owner_retires_without_releasing_physical_arc_prematurely() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let strong = owner.share();
    let weak = strong.downgrade();
    drop(owner);
    assert!(weak.upgrade(&permit).is_none());
    assert_eq!(strong.read(&permit, |_| 1), Err(E::Retired));
}

#[test]
fn stale_region_cannot_be_upgraded_to_fresh_allocation_with_same_domain() {
    let first = freeze(cycle(17));
    let permit = first.issue_read_permit();
    let old_weak = first.downgrade();
    drop(first);
    let second = freeze(cycle(17));
    let new_permit = second.issue_read_permit();
    assert!(old_weak.upgrade(&permit).is_none());
    assert!(old_weak.upgrade(&new_permit).is_none());
    assert!(second.downgrade().upgrade(&new_permit).is_some());
}

#[test]
fn retirement_is_nonparking_while_existing_read_scope_is_active() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let shared = owner.share();
    let weak = owner.downgrade();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        shared
            .read(&permit, |graph| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                graph.node_count()
            })
            .unwrap()
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // Existing read may finish, but retirement is already logically effective.
    assert_eq!(owner.retire(), Err(E::Busy));
    assert!(weak.upgrade(&permit).is_none());
    release_tx.send(()).unwrap();
    assert_eq!(reader.join().unwrap(), 3);
    assert_eq!(owner.retire(), Ok(()));
}

#[test]
fn dropping_owner_inside_reader_callback_cannot_deadlock_or_reopen_rights() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let shared = owner.share();
    let weak = owner.downgrade();
    let mut owner = Some(owner);
    assert_eq!(
        shared.read(&permit, |graph| {
            drop(owner.take()); // Must not wait for its own active read lock.
            graph.node_count()
        }),
        Ok(3)
    );
    assert!(weak.upgrade(&permit).is_none());
}

#[test]
fn simultaneous_weak_upgrades_vs_retirement_never_dereference_freed_data() {
    let owner = freeze(cycle(17));
    let permit = owner.issue_read_permit();
    let weak = owner.downgrade();
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let barrier = Arc::clone(&barrier);
        let weak = weak.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1000 {
                if let Some(shared) = weak.upgrade(&permit) {
                    let result = shared.read(&permit, |g| g.node_count());
                    assert!(matches!(result, Ok(3) | Err(E::Retired) | Err(E::Busy)));
                }
            }
        }));
    }
    barrier.wait();
    assert!(matches!(owner.retire(), Ok(()) | Err(E::Busy)));
    for thread in handles {
        thread.join().unwrap();
    }
    assert!(weak.upgrade(&permit).is_none());
    assert_eq!(owner.retire(), Ok(()));
}

#[derive(Debug)]
struct NotUnpin {
    value: u64,
    _pin: PhantomPinned,
}

#[test]
fn pinned_pointee_address_survives_handle_move_and_container_swap() {
    let pinned = StablePinned::new(NotUnpin {
        value: 42,
        _pin: PhantomPinned,
    });
    let original = pinned.view().get_ref() as *const NotUnpin as usize;
    let other = StablePinned::new(NotUnpin {
        value: 7,
        _pin: PhantomPinned,
    });
    let mut handles = [pinned, other];
    handles.swap(0, 1);
    assert_eq!(
        handles[1].view().get_ref() as *const NotUnpin as usize,
        original
    );
    assert_eq!(handles[1].view().get_ref().value, 42);
}

#[test]
fn pinned_storage_survives_moving_handle_between_threads() {
    let pinned = StablePinned::new(NotUnpin {
        value: 93,
        _pin: PhantomPinned,
    });
    let address = pinned.view().get_ref() as *const NotUnpin as usize;
    let join = thread::spawn(move || {
        (
            pinned.view().get_ref() as *const NotUnpin as usize,
            pinned.view().get_ref().value,
        )
    });
    assert_eq!(join.join().unwrap(), (address, 93));
}

#[test]
fn concurrent_freezes_mint_distinct_region_read_capabilities() {
    // Identical numeric actor domains never authorize cross-region reads.
    // Concurrent identity creation must remain unique after CAS retries.
    const COUNT: usize = 12;
    let barrier = Arc::new(Barrier::new(COUNT + 1));
    let workers: Vec<_> = (0..COUNT)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                freeze(cycle(17))
            })
        })
        .collect();
    barrier.wait();
    let owners: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        let permit = owner.issue_read_permit();
        assert_eq!(owner.share().read(&permit, |g| g.node_count()), Ok(3));
        for (other_index, other) in owners.iter().enumerate() {
            if index != other_index {
                assert_eq!(
                    other.share().read(&permit, |g| g.node_count()),
                    Err(E::WrongDomain),
                    "two simultaneously live frozen owners must not share a permit"
                );
            }
        }
    }
}
