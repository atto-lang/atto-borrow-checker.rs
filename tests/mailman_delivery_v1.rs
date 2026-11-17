//! Host Rust graph/lease oracle tests. NOT physical Mailman or .atto guest tests.
use atto_borrow_checker::mailman_delivery_v1::{
    verify_delivery, Allocation, DeliveryLedger, DeliveryMode, DeliveryRequest, Error,
    GraphInventory, SelectedDelivery,
};

fn node(id: u32, children: &[u32]) -> Allocation {
    Allocation {
        id,
        owner_domain: 7,
        allocation_generation: 1,
        mutable: true,
        sendable: true,
        deep_copyable: true,
        frozen: false,
        sync: false,
        references: children.to_vec(),
        escaped_aliases: 0,
        active_readers: 0,
        active_writer: false,
    }
}

fn cyclic() -> GraphInventory {
    GraphInventory {
        root: 1,
        nodes: vec![node(1, &[2, 2]), node(2, &[1, 3]), node(3, &[])],
        expected_reachable: vec![3, 1, 2],
    }
}

fn request(mode: DeliveryMode) -> DeliveryRequest {
    DeliveryRequest {
        mode,
        source_domain: 7,
        destination_domain: 7,
        source_actor_generation: 11,
        destination_actor_generation: 12,
        ticket: 9,
        ticket_generation: 5,
        lease_may_suspend: false,
        pinned_lease_proven: false,
        scoped_lease_proven: true,
        allow_elision: false,
        source_observable_after_send: true,
        copy_identity_or_hooks_observable: true,
    }
}

fn err(graph: &GraphInventory, req: &DeliveryRequest) -> Error {
    verify_delivery(graph, req).unwrap_err()
}

#[test]
fn unique_cyclic_graph_with_repeated_internal_aliases_can_transfer() {
    let proof = verify_delivery(&cyclic(), &request(DeliveryMode::Transfer)).unwrap();
    assert_eq!(proof.selected(), SelectedDelivery::Transfer);
    assert_eq!(proof.reachable(), vec![1, 2, 3]);
}

#[test]
fn reject_missing_nested_nodes_dangling_edges_and_false_census() {
    let mut graph = cyclic();
    graph.nodes[1].references.push(99);
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );

    let mut graph = cyclic();
    graph.nodes.pop();
    graph.expected_reachable.pop();
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );

    let mut graph = cyclic();
    graph.expected_reachable = vec![1, 2, 2];
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );

    let mut graph = cyclic();
    graph.nodes.push(node(4, &[]));
    graph.expected_reachable.push(4);
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );
}

#[test]
fn reject_zero_duplicate_and_budgeted_graph_identifiers() {
    let mut graph = cyclic();
    graph.root = 0;
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::InventoryBudget
    );

    let mut graph = cyclic();
    graph.nodes[1].id = 1;
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::InvalidInventory
    );

    let mut graph = cyclic();
    graph.nodes[0].references = vec![2; 16385];
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::InventoryBudget
    );

    let mut graph = cyclic();
    graph.nodes = (1..=4097).map(|id| node(id, &[])).collect();
    graph.expected_reachable = (1..=4097).collect();
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::InventoryBudget
    );
}

#[test]
fn untracked_nested_alias_blocks_transfer_and_copy_until_guarded() {
    let mut graph = cyclic();
    graph.nodes[2].escaped_aliases = 1;
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::OwnershipNotExclusive
    );
    let mut req = request(DeliveryMode::DeepCopy);
    req.allow_elision = true;
    req.source_observable_after_send = false;
    req.copy_identity_or_hooks_observable = false;
    assert_eq!(
        err(&graph, &req),
        Error::OwnershipNotExclusive
    );
}

#[test]
fn outstanding_read_or_write_loan_blocks_transfer_and_write_lease() {
    for write in [true, false] {
        let mut graph = cyclic();
        graph.nodes[2].active_writer = write;
        graph.nodes[2].active_readers = u32::from(!write);
        assert_eq!(
            err(&graph, &request(DeliveryMode::Transfer)),
            Error::OutstandingLoan
        );
        assert_eq!(
            err(&graph, &request(DeliveryMode::WriteLease)),
            Error::LeaseConflict
        );
    }
}

#[test]
fn read_lease_allows_existing_readers_but_never_a_writer() {
    let mut graph = cyclic();
    graph.nodes[0].active_readers = 3;
    assert_eq!(
        verify_delivery(&graph, &request(DeliveryMode::ReadLease))
            .unwrap()
            .selected(),
        SelectedDelivery::ReadLease
    );
    graph.nodes[0].active_writer = true;
    assert_eq!(
        err(&graph, &request(DeliveryMode::ReadLease)),
        Error::LeaseConflict
    );
}

#[test]
fn lease_requires_scope_and_explicit_pinned_suspension_proof() {
    let graph = cyclic();
    let mut req = request(DeliveryMode::ReadLease);
    req.scoped_lease_proven = false;
    assert_eq!(err(&graph, &req), Error::LeaseScopeRequired);
    req.scoped_lease_proven = true;
    req.lease_may_suspend = true;
    assert_eq!(err(&graph, &req), Error::LeaseSuspendUnproven);
    req.pinned_lease_proven = true;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::ReadLease
    );
}

#[test]
fn cross_heap_handoff_cannot_claim_physical_zero_copy() {
    let graph = cyclic();
    for mode in [
        DeliveryMode::Transfer,
        DeliveryMode::ReadLease,
        DeliveryMode::WriteLease,
    ] {
        let mut req = request(mode);
        req.destination_domain = 13;
        assert_eq!(err(&graph, &req), Error::CrossDomainZeroCopy);
    }
    let mut frozen = cyclic();
    for node in &mut frozen.nodes {
        node.mutable = false;
        node.frozen = true;
        node.sync = true;
    }
    let mut share = request(DeliveryMode::FrozenShare);
    share.destination_domain = 13;
    assert_eq!(err(&frozen, &share), Error::CrossDomainZeroCopy);
    let mut req = request(DeliveryMode::DeepCopy);
    req.destination_domain = 13;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::DeepCopy
    );
}

#[test]
fn deep_copy_requires_transitive_witness_and_sendable() {
    let mut graph = cyclic();
    graph.nodes[2].deep_copyable = false;
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::CopyWitnessRequired
    );
    graph.nodes[2].deep_copyable = true;
    graph.nodes[2].sendable = false;
    assert_eq!(
        err(&graph, &request(DeliveryMode::DeepCopy)),
        Error::NotSendable
    );
}

#[test]
fn frozen_share_requires_all_descendants_frozen_and_sync() {
    let mut graph = cyclic();
    assert_eq!(
        err(&graph, &request(DeliveryMode::FrozenShare)),
        Error::FrozenSyncRequired
    );
    for node in &mut graph.nodes {
        node.mutable = false;
        node.frozen = true;
        node.sync = true;
    }
    assert_eq!(
        verify_delivery(&graph, &request(DeliveryMode::FrozenShare))
            .unwrap()
            .selected(),
        SelectedDelivery::FrozenShare
    );
    graph.nodes[2].sync = false;
    assert_eq!(
        err(&graph, &request(DeliveryMode::FrozenShare)),
        Error::FrozenSyncRequired
    );
}

#[test]
fn copy_elision_requires_dead_source_and_no_observable_copy_semantics() {
    let graph = cyclic();
    let mut req = request(DeliveryMode::DeepCopy);
    req.allow_elision = true;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::DeepCopy
    );
    req.source_observable_after_send = false;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::DeepCopy
    );
    req.copy_identity_or_hooks_observable = false;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::ElidedDeepCopy
    );
    req.destination_domain = 13;
    assert_eq!(
        verify_delivery(&graph, &req).unwrap().selected(),
        SelectedDelivery::DeepCopy
    );
}

#[test]
fn invalid_actor_and_ticket_generations_are_fail_closed() {
    let graph = cyclic();
    let mut req = request(DeliveryMode::Transfer);
    req.destination_actor_generation = 0;
    assert_eq!(err(&graph, &req), Error::StaleGeneration);
    req.destination_actor_generation = 12;
    req.source_actor_generation = 0;
    assert_eq!(err(&graph, &req), Error::StaleGeneration);
    req.source_actor_generation = 11;
    req.ticket_generation = 0;
    assert_eq!(err(&graph, &req), Error::InvalidTicket);
    req.ticket_generation = 5;
    req.ticket = 0;
    assert_eq!(err(&graph, &req), Error::InvalidTicket);
}

#[test]
fn mailbox_prepare_commit_abort_are_single_use_and_bounded() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::Transfer)).unwrap();
    let mut ledger = DeliveryLedger::new(1, 12);
    ledger.prepare(&proof).unwrap();
    assert_eq!(ledger.counts(), (1, 0));
    assert_eq!(ledger.prepare(&proof), Err(Error::DuplicateTicket));
    assert_eq!(ledger.commit(9, 5), Ok(true));
    assert_eq!(ledger.counts(), (0, 1));
    assert_eq!(ledger.abort(9, 5), Err(Error::UnknownTicket));
    assert_eq!(ledger.commit(9, 5), Err(Error::UnknownTicket));
    assert_eq!(ledger.prepare(&proof), Err(Error::DuplicateTicket));
    ledger.finish(9, 5).unwrap();
    assert_eq!(ledger.counts(), (0, 0));

    // A committed transfer consumes these allocations permanently in this
    // model ledger; a later ticket needs a genuinely fresh graph identity.
    let mut fresh = cyclic();
    fresh.root += 10;
    for node in &mut fresh.nodes {
        node.id += 10;
        for child in &mut node.references {
            *child += 10;
        }
    }
    for id in &mut fresh.expected_reachable {
        *id += 10;
    }
    let mut later = request(DeliveryMode::Transfer);
    later.ticket = 10;
    let later = verify_delivery(&fresh, &later).unwrap();
    ledger.prepare(&later).unwrap();
    ledger.abort(10, 5).unwrap();
    assert_eq!(ledger.counts(), (0, 0));
    assert_eq!(ledger.prepare(&later), Err(Error::DuplicateTicket));
}

#[test]
fn reserve_full_mailbox_before_copy_and_do_not_consume_ticket() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::DeepCopy)).unwrap();
    let mut ledger = DeliveryLedger::new(0, 12);
    assert_eq!(ledger.prepare(&proof), Err(Error::MailboxFull));
    assert_eq!(ledger.counts(), (0, 0));

    let mut ledger = DeliveryLedger::new(1, 12);
    ledger.prepare(&proof).unwrap();
    let mut other = request(DeliveryMode::DeepCopy);
    other.ticket = 10;
    let other = verify_delivery(&graph, &other).unwrap();
    assert_eq!(ledger.prepare(&other), Err(Error::MailboxFull));
    ledger.abort(9, 5).unwrap();
    ledger.prepare(&other).unwrap();
    assert_eq!(ledger.commit(10, 5), Ok(false));
}

#[test]
fn tracked_lease_cannot_retire_before_all_derivative_users_quiesce() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::ReadLease)).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    ledger.prepare(&proof).unwrap();
    assert_eq!(ledger.commit(9, 5), Ok(false));
    ledger.enter_lease_user(9, 5).unwrap();
    ledger.enter_lease_user(9, 5).unwrap();
    assert_eq!(ledger.finish(9, 5), Err(Error::LeaseStillActive));
    ledger.exit_lease_user(9, 5).unwrap();
    assert_eq!(ledger.finish(9, 5), Err(Error::LeaseStillActive));
    ledger.exit_lease_user(9, 5).unwrap();
    assert_eq!(ledger.finish(9, 5), Err(Error::LeaseStillActive));
    ledger.release_receiver_lease(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();
    assert_eq!(ledger.counts(), (0, 0));
    assert_eq!(ledger.exit_lease_user(9, 5), Err(Error::UnknownTicket));
}

#[test]
fn rejects_loan_user_on_non_loan_delivery() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::DeepCopy)).unwrap();
    let mut ledger = DeliveryLedger::new(1, 12);
    ledger.prepare(&proof).unwrap();
    ledger.commit(9, 5).unwrap();
    assert_eq!(
        ledger.enter_lease_user(9, 5),
        Err(Error::LeaseScopeRequired)
    );
    ledger.finish(9, 5).unwrap();
}

#[test]
fn unknown_ticket_and_double_settlement_never_mutate_counts() {
    let mut ledger = DeliveryLedger::new(1, 12);
    assert_eq!(ledger.commit(9, 4), Err(Error::UnknownTicket));
    assert_eq!(ledger.abort(9, 4), Err(Error::UnknownTicket));
    assert_eq!(ledger.finish(9, 4), Err(Error::UnknownTicket));
    assert_eq!(ledger.counts(), (0, 0));
}

#[test]
fn simultaneous_lease_requests_are_region_wide_and_conflict_before_admission() {
    let graph = cyclic();
    let read_one = request(DeliveryMode::ReadLease);
    let mut read_two = request(DeliveryMode::ReadLease);
    read_two.ticket = 10;
    let mut write = request(DeliveryMode::WriteLease);
    write.ticket = 11;

    let read_one = verify_delivery(&graph, &read_one).unwrap();
    let read_two = verify_delivery(&graph, &read_two).unwrap();
    let write = verify_delivery(&graph, &write).unwrap();

    let mut ledger = DeliveryLedger::new(3, 12);
    ledger.prepare(&read_one).unwrap();
    ledger.prepare(&read_two).unwrap();
    assert_eq!(ledger.prepare(&write), Err(Error::LeaseConflict));
    ledger.commit(9, 5).unwrap();
    ledger.abort(10, 5).unwrap();
    assert_eq!(ledger.prepare(&write), Err(Error::LeaseConflict));
    ledger.release_receiver_lease(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();
    ledger.prepare(&write).unwrap();
    assert_eq!(ledger.commit(11, 5), Ok(false));
    ledger.release_receiver_lease(11, 5).unwrap();
    ledger.finish(11, 5).unwrap();
}

#[test]
fn pending_transfer_excludes_leases_and_duplicate_copy_readers() {
    let graph = cyclic();
    let transfer = verify_delivery(&graph, &request(DeliveryMode::Transfer)).unwrap();
    let mut read = request(DeliveryMode::ReadLease);
    read.ticket = 12;
    let read = verify_delivery(&graph, &read).unwrap();
    let mut copy = request(DeliveryMode::DeepCopy);
    copy.ticket = 13;
    let copy = verify_delivery(&graph, &copy).unwrap();

    let mut ledger = DeliveryLedger::new(3, 12);
    ledger.prepare(&transfer).unwrap();
    assert_eq!(ledger.prepare(&read), Err(Error::LeaseConflict));
    assert_eq!(ledger.prepare(&copy), Err(Error::LeaseConflict));
    ledger.abort(9, 5).unwrap();
    ledger.prepare(&read).unwrap();
    ledger.prepare(&copy).unwrap();
    assert_eq!(ledger.commit(13, 5), Ok(false));
    ledger.finish(13, 5).unwrap();
    ledger.finish(12, 5).unwrap_err(); // not yet committed
    ledger.commit(12, 5).unwrap();
    ledger.release_receiver_lease(12, 5).unwrap();
    ledger.finish(12, 5).unwrap();
}

#[test]
fn committed_transfer_invalidates_stale_source_proofs() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::Transfer)).unwrap();
    let mut second = request(DeliveryMode::Transfer);
    second.ticket = 14;
    let second = verify_delivery(&graph, &second).unwrap();

    let mut ledger = DeliveryLedger::new(3, 12);
    ledger.prepare(&proof).unwrap();
    ledger.commit(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();
    assert_eq!(ledger.prepare(&second), Err(Error::OwnershipNotExclusive));
}

#[test]
fn ticket_epochs_must_increase_after_prior_aborted_ticket() {
    let graph = cyclic();
    let first = verify_delivery(&graph, &request(DeliveryMode::ReadLease)).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    ledger.prepare(&first).unwrap();
    ledger.abort(9, 5).unwrap();

    let mut stale = request(DeliveryMode::ReadLease);
    stale.ticket_generation = 4;
    assert_eq!(
        ledger.prepare(&verify_delivery(&graph, &stale).unwrap()),
        Err(Error::DuplicateTicket)
    );

    stale.ticket_generation = 6;
    ledger
        .prepare(&verify_delivery(&graph, &stale).unwrap())
        .unwrap();
    ledger.abort(9, 6).unwrap();
}

#[test]
fn malformed_allocation_epoch_is_rejected_before_minting_a_proof() {
    let mut graph = cyclic();
    graph.nodes[1].allocation_generation = 0;
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );
    graph.nodes[1].allocation_generation = 1;
    graph.nodes[1].owner_domain = 0;
    assert_eq!(
        err(&graph, &request(DeliveryMode::Transfer)),
        Error::InvalidInventory
    );
}

#[test]
fn verified_proof_must_match_destination_actor_incarnation() {
    let graph = cyclic();
    let mut req = request(DeliveryMode::Transfer);
    req.destination_actor_generation = 13;
    let proof = verify_delivery(&graph, &req).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    assert_eq!(ledger.prepare(&proof), Err(Error::StaleGeneration));
    assert_eq!(ledger.counts(), (0, 0));
    let mut closed = DeliveryLedger::new(2, 0);
    assert_eq!(
        closed.prepare(&verify_delivery(&graph, &request(DeliveryMode::Transfer)).unwrap()),
        Err(Error::StaleGeneration)
    );
}

#[test]
fn reused_allocation_slot_requires_a_fresh_generation() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::Transfer)).unwrap();
    let mut ledger = DeliveryLedger::new(3, 12);
    ledger.prepare(&proof).unwrap();
    ledger.commit(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();

    let mut stale = request(DeliveryMode::Transfer);
    stale.ticket = 10;
    assert_eq!(
        ledger.prepare(&verify_delivery(&graph, &stale).unwrap()),
        Err(Error::OwnershipNotExclusive)
    );
    let mut newly_allocated = cyclic();
    for node in &mut newly_allocated.nodes {
        node.allocation_generation = 2;
    }
    ledger
        .prepare(&verify_delivery(&newly_allocated, &stale).unwrap())
        .unwrap();
    ledger.abort(10, 5).unwrap();
}

#[test]
fn independent_memory_domains_do_not_alias_on_identical_local_offsets() {
    let first = cyclic();
    let mut ledger = DeliveryLedger::new(3, 12);
    ledger
        .prepare(&verify_delivery(&first, &request(DeliveryMode::Transfer)).unwrap())
        .unwrap();
    ledger.commit(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();

    let mut second = cyclic();
    for node in &mut second.nodes {
        node.owner_domain = 8;
    }
    let mut next = request(DeliveryMode::Transfer);
    next.source_domain = 8;
    next.destination_domain = 8;
    next.ticket = 10;
    ledger
        .prepare(&verify_delivery(&second, &next).unwrap())
        .unwrap();
    ledger.abort(10, 5).unwrap();
}

#[test]
fn frozen_share_escrow_blocks_writer_then_fences_mutation_after_commit() {
    let mut frozen = cyclic();
    for node in &mut frozen.nodes {
        node.frozen = true;
        node.mutable = false;
        node.sync = true;
    }
    let share = verify_delivery(&frozen, &request(DeliveryMode::FrozenShare)).unwrap();
    let mut writer = request(DeliveryMode::WriteLease);
    writer.ticket = 10;
    let writer = verify_delivery(&cyclic(), &writer).unwrap();

    let mut ledger = DeliveryLedger::new(3, 12);
    ledger.prepare(&share).unwrap();
    assert_eq!(ledger.prepare(&writer), Err(Error::LeaseConflict));
    ledger.commit(9, 5).unwrap();
    assert_eq!(ledger.prepare(&writer), Err(Error::OwnershipNotExclusive));
    ledger.finish(9, 5).unwrap();
    assert_eq!(ledger.prepare(&writer), Err(Error::OwnershipNotExclusive));
}

#[test]
fn frozen_share_fanout_is_read_only_and_can_admit_multiple_readers() {
    let mut frozen = cyclic();
    for node in &mut frozen.nodes {
        node.frozen = true;
        node.mutable = false;
        node.sync = true;
    }
    let first = verify_delivery(&frozen, &request(DeliveryMode::FrozenShare)).unwrap();
    let mut req = request(DeliveryMode::FrozenShare);
    req.ticket = 10;
    let second = verify_delivery(&frozen, &req).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    ledger.prepare(&first).unwrap();
    ledger.prepare(&second).unwrap();
    ledger.commit(9, 5).unwrap();
    ledger.commit(10, 5).unwrap();
    ledger.finish(9, 5).unwrap();
    ledger.finish(10, 5).unwrap();
}

#[test]
fn original_remote_receiver_lease_must_finish_before_reclamation() {
    let graph = cyclic();
    let proof = verify_delivery(&graph, &request(DeliveryMode::ReadLease)).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    ledger.prepare(&proof).unwrap();
    ledger.commit(9, 5).unwrap();
    assert_eq!(ledger.finish(9, 5), Err(Error::LeaseStillActive));
    ledger.enter_lease_user(9, 5).unwrap();
    ledger.release_receiver_lease(9, 5).unwrap();
    assert_eq!(ledger.release_receiver_lease(9, 5), Err(Error::LeaseStillActive));
    assert_eq!(ledger.enter_lease_user(9, 5), Err(Error::LeaseStillActive));
    assert_eq!(ledger.finish(9, 5), Err(Error::LeaseStillActive));
    ledger.exit_lease_user(9, 5).unwrap();
    ledger.finish(9, 5).unwrap();
}

#[test]
fn pending_deep_copy_holds_read_guard_until_copy_publication() {
    let graph = cyclic();
    let clone = verify_delivery(&graph, &request(DeliveryMode::DeepCopy)).unwrap();
    let mut writer_request = request(DeliveryMode::WriteLease);
    writer_request.ticket = 10;
    let writer = verify_delivery(&graph, &writer_request).unwrap();
    let mut ledger = DeliveryLedger::new(2, 12);
    ledger.prepare(&clone).unwrap();
    assert_eq!(ledger.prepare(&writer), Err(Error::LeaseConflict));
    ledger.commit(9, 5).unwrap();
    ledger.prepare(&writer).unwrap();
    ledger.abort(10, 5).unwrap();
    ledger.finish(9, 5).unwrap();
}
