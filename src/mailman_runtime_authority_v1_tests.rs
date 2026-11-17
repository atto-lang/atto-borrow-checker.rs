//! Safe Rust host-side tests for authoritative Mailman transfer registry.
//! Not compiled .atto guests, production allocator attestation, or physical heap moves.
use crate::mailman_compiler_bound_v1::{
    verify_compiler_transfer, CompilerBoundTransfer, CompilerSendCensus, Error as BrokerError,
    SourceTransferSite, CONTRACT_VERSION,
};
use crate::mailman_delivery_v1::{
    Allocation, DeliveryMode, DeliveryRequest, Error as DeliveryError, GraphInventory,
};
use crate::mailman_runtime_authority_v1::{
    ActorIdentity, AllocationStamp, DomainAuthority, Error,
};
use crate::mir_v1::{
    Effect, Instruction, MirBlock, MirFunction, Producer, CONTRACT_VERSION as MIR_VERSION,
};
use crate::{Op, Traits};
use std::sync::{Arc, Barrier};
use std::thread;

const SENDER: ActorIdentity = ActorIdentity {
    id: 200,
    generation: 11,
};
const RECEIVER: ActorIdentity = ActorIdentity {
    id: 300,
    generation: 12,
};

fn stamps(offset: u32, generation: u64) -> Vec<AllocationStamp> {
    vec![
        AllocationStamp {
            id: offset + 1,
            generation,
        },
        AllocationStamp {
            id: offset + 2,
            generation,
        },
    ]
}

fn graph(domain: u64, offset: u32, generation: u64) -> GraphInventory {
    let mk = |id: u32, refs: Vec<u32>| Allocation {
        id: offset + id,
        owner_domain: domain,
        allocation_generation: generation,
        mutable: true,
        sendable: true,
        deep_copyable: true,
        frozen: false,
        sync: false,
        references: refs.into_iter().map(|value| value + offset).collect(),
        escaped_aliases: 0,
        active_readers: 0,
        active_writer: false,
    };
    GraphInventory {
        root: offset + 1,
        nodes: vec![mk(1, vec![2, 2]), mk(2, vec![1])],
        expected_reachable: vec![offset + 1, offset + 2],
    }
}

fn instruction(id: u64, effect: Effect, operation: Op) -> Instruction {
    Instruction {
        instruction_id: id,
        source_node_id: id + 100,
        effect,
        operation,
    }
}

fn program(ticket: u32) -> MirFunction {
    MirFunction {
        version: MIR_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 1,
            function_id: 1,
        },
        entry: 0,
        expected_instruction_ids: (1..=7).collect(),
        blocks: vec![
            MirBlock {
                id: 0,
                instructions: vec![
                    instruction(
                        1,
                        Effect::Ownership,
                        Op::Init {
                            owner: 1,
                            traits: Traits {
                                is_copy: false,
                                is_send: true,
                            },
                        },
                    ),
                    instruction(
                        2,
                        Effect::ActorBoundary,
                        Op::ActorSendPrepare { owner: 1, ticket },
                    ),
                ],
                successors: vec![1, 2],
            },
            MirBlock {
                id: 1,
                instructions: vec![
                    instruction(3, Effect::ActorBoundary, Op::ActorSendCommit { ticket }),
                    instruction(4, Effect::Control, Op::Return),
                ],
                successors: vec![],
            },
            MirBlock {
                id: 2,
                instructions: vec![
                    instruction(5, Effect::ActorBoundary, Op::ActorSendAbort { ticket }),
                    instruction(6, Effect::Ownership, Op::Read { owner: 1 }),
                    instruction(7, Effect::Control, Op::Return),
                ],
                successors: vec![],
            },
        ],
    }
}

fn proof(domain: u64, ticket: u32, offset: u32, generation: u64) -> CompilerBoundTransfer {
    let function = program(ticket);
    let census = CompilerSendCensus {
        version: CONTRACT_VERSION.into(),
        producer: function.producer.clone(),
        source_transfer_sites: vec![SourceTransferSite {
            instruction_id: 2,
            source_node_id: 102,
            owner: 1,
            ticket,
            root_allocation: offset + 1,
        }],
    };
    let request = DeliveryRequest {
        mode: DeliveryMode::Transfer,
        source_domain: domain,
        destination_domain: domain,
        source_actor_generation: SENDER.generation,
        destination_actor_generation: RECEIVER.generation,
        ticket: u64::from(ticket),
        ticket_generation: 5,
        lease_may_suspend: false,
        pinned_lease_proven: false,
        scoped_lease_proven: false,
        allow_elision: false,
        source_observable_after_send: true,
        copy_identity_or_hooks_observable: true,
    };
    verify_compiler_transfer(
        &function,
        &census,
        &graph(domain, offset, generation),
        &request,
    )
    .unwrap()
}

fn authority(domain: u64) -> DomainAuthority {
    DomainAuthority::open(domain, RECEIVER, 3, &[(1, 2), (2, 2)]).unwrap()
}

#[test]
fn committed_transfer_invalidates_sender_then_accepts_receiver() {
    let domain = 1001;
    let registry = authority(domain);
    let keys = stamps(0, 1);
    registry.register_allocator_owned(SENDER, 1, &keys).unwrap();
    let mut permit = registry
        .prepare(1, SENDER, &proof(domain, 9, 0, 1))
        .unwrap();
    assert_eq!(registry.pending_count().unwrap(), 1);
    assert_eq!(registry.owner_of(keys[0]).unwrap(), Some((SENDER, 1)));
    let mut received = permit.commit().unwrap();
    let session = registry.receiver_session(RECEIVER).unwrap();
    assert_eq!(registry.owner_of(keys[0]).unwrap(), None);
    assert_eq!(permit.commit().unwrap_err(), Error::GrantState);
    assert_eq!(permit.abort(), Err(Error::GrantState));
    assert_eq!(
        registry.retire_destroyed(SENDER, 1, &keys),
        Err(Error::AllocationBusy)
    );
    received.accept(&session, 42).unwrap();
    assert_eq!(registry.owner_of(keys[0]).unwrap(), Some((RECEIVER, 42)));
    assert_eq!(registry.owner_of(keys[1]).unwrap(), Some((RECEIVER, 42)));
    assert_eq!(received.accept(&session, 42), Err(Error::GrantState));
    assert_eq!(registry.pending_count().unwrap(), 0);
    assert_eq!(
        registry
            .prepare(2, SENDER, &proof(domain, 10, 0, 1))
            .unwrap_err(),
        Error::OwnerMismatch
    );
}

#[test]
fn dropped_pending_permit_aborts_without_consuming_sender() {
    let domain = 1002;
    let registry = authority(domain);
    let keys = stamps(0, 1);
    registry.register_allocator_owned(SENDER, 1, &keys).unwrap();
    {
        let _permit = registry
            .prepare(1, SENDER, &proof(domain, 9, 0, 1))
            .unwrap();
        assert_eq!(registry.pending_count().unwrap(), 1);
        assert_eq!(
            registry.retire_destroyed(SENDER, 1, &keys),
            Err(Error::AllocationBusy)
        );
    }
    assert_eq!(registry.pending_count().unwrap(), 0);
    assert_eq!(registry.owner_of(keys[0]).unwrap(), Some((SENDER, 1)));
    let mut later = registry
        .prepare(2, SENDER, &proof(domain, 10, 0, 1))
        .unwrap();
    later.abort().unwrap();
    assert_eq!(later.abort(), Err(Error::GrantState));
}

#[test]
fn two_authority_handles_share_one_nonforgeable_transfer_ledger() {
    let domain = 1003;
    let a = authority(domain);
    let b = authority(domain);
    a.register_allocator_owned(SENDER, 1, &stamps(0, 1))
        .unwrap();
    let mut pending = a.prepare(1, SENDER, &proof(domain, 9, 0, 1)).unwrap();
    assert_eq!(
        b.prepare(2, SENDER, &proof(domain, 10, 0, 1)).unwrap_err(),
        Error::AllocationBusy
    );
    pending.abort().unwrap();
    let mut other = b.prepare(2, SENDER, &proof(domain, 10, 0, 1)).unwrap();
    let mut received = other.commit().unwrap();
    let session = a.receiver_session(RECEIVER).unwrap();
    received.accept(&session, 17).unwrap();
    assert_eq!(a.owner_of(stamps(0, 1)[0]).unwrap(), Some((RECEIVER, 17)));
}

#[test]
fn allocator_registration_is_atomic_and_rejects_duplicate_slots() {
    let domain = 1004;
    let registry = authority(domain);
    let keys = stamps(0, 1);
    let bad = vec![keys[0], keys[0]];
    assert_eq!(
        registry.register_allocator_owned(SENDER, 1, &bad),
        Err(Error::DuplicateAllocation)
    );
    assert_eq!(registry.owner_of(keys[0]).unwrap(), None);
    registry.register_allocator_owned(SENDER, 1, &keys).unwrap();
    assert_eq!(
        registry.register_allocator_owned(SENDER, 1, &keys),
        Err(Error::DuplicateAllocation)
    );
    assert_eq!(
        registry.register_allocator_owned(
            SENDER,
            1,
            &[AllocationStamp {
                id: 3,
                generation: 0
            }]
        ),
        Err(Error::InvalidAllocation)
    );
    assert_eq!(
        registry.register_allocator_owned(
            SENDER,
            0,
            &[AllocationStamp {
                id: 3,
                generation: 1
            }]
        ),
        Err(Error::InvalidOwner)
    );
}

#[test]
fn stale_allocation_generations_cannot_reenter_after_retirement() {
    let domain = 1005;
    let registry = authority(domain);
    let original = stamps(0, 7);
    registry
        .register_allocator_owned(SENDER, 1, &original)
        .unwrap();
    registry.retire_destroyed(SENDER, 1, &original).unwrap();
    assert_eq!(
        registry.register_allocator_owned(SENDER, 1, &original),
        Err(Error::StaleAllocation)
    );
    let newer = stamps(0, 8);
    registry
        .register_allocator_owned(SENDER, 1, &newer)
        .unwrap();
    assert_eq!(registry.owner_of(original[0]), Err(Error::StaleAllocation));
    assert_eq!(registry.owner_of(newer[0]).unwrap(), Some((SENDER, 1)));
    assert_eq!(
        registry
            .prepare(1, SENDER, &proof(domain, 9, 0, 7))
            .unwrap_err(),
        Error::StaleAllocation
    );
}

#[test]
fn missing_nested_allocation_makes_proof_inadmissible() {
    let domain = 1006;
    let registry = authority(domain);
    let original = stamps(0, 1);
    registry
        .register_allocator_owned(SENDER, 1, &original[..1])
        .unwrap();
    assert_eq!(
        registry
            .prepare(1, SENDER, &proof(domain, 9, 0, 1))
            .unwrap_err(),
        Error::IncompleteGraph
    );
    assert_eq!(registry.pending_count().unwrap(), 0);
    registry
        .register_allocator_owned(SENDER, 1, &original[1..])
        .unwrap();
    let mut pending = registry
        .prepare(1, SENDER, &proof(domain, 9, 0, 1))
        .unwrap();
    pending.abort().unwrap();
}

#[test]
fn wrong_actor_generation_or_wrong_owner_slot_rejected_before_escrow() {
    let domain = 1007;
    let registry = authority(domain);
    let original = stamps(0, 1);
    registry
        .register_allocator_owned(SENDER, 1, &original)
        .unwrap();
    let wrong_actor = ActorIdentity {
        id: SENDER.id,
        generation: SENDER.generation + 1,
    };
    assert_eq!(
        registry
            .prepare(1, wrong_actor, &proof(domain, 9, 0, 1))
            .unwrap_err(),
        Error::WrongActorGeneration
    );
    registry.retire_destroyed(SENDER, 1, &original).unwrap();
    registry
        .register_allocator_owned(SENDER, 7, &stamps(0, 2))
        .unwrap();
    assert_eq!(
        registry
            .prepare(1, SENDER, &proof(domain, 9, 0, 2))
            .unwrap_err(),
        Error::OwnerMismatch
    );
}

#[test]
fn global_registry_rejects_second_conflicting_actor_incarnation() {
    let domain = 1008;
    let registry = authority(domain);
    let changed = ActorIdentity {
        id: RECEIVER.id,
        generation: 13,
    };
    assert_eq!(
        DomainAuthority::open(domain, changed, 3, &[(1, 2), (2, 2)]).unwrap_err(),
        Error::AuthorityConflict
    );
    assert_eq!(
        DomainAuthority::open(domain, RECEIVER, 2, &[(1, 2), (2, 2)]).unwrap_err(),
        Error::AuthorityConflict
    );
    assert_eq!(
        DomainAuthority::open(domain, RECEIVER, 3, &[(1, 1), (2, 2)]).unwrap_err(),
        Error::AuthorityConflict
    );
    drop(registry);
    assert_eq!(
        DomainAuthority::open(domain, changed, 3, &[(1, 2), (2, 2)]).unwrap_err(),
        Error::AuthorityConflict
    );
}

#[test]
fn abandoned_committed_envelope_remains_quarantined_after_handles_drop() {
    let domain = 1009;
    let original_authority = authority(domain);
    original_authority
        .register_allocator_owned(SENDER, 1, &stamps(0, 1))
        .unwrap();
    let mut pending = original_authority
        .prepare(1, SENDER, &proof(domain, 9, 0, 1))
        .unwrap();
    let received = pending.commit().unwrap();
    drop(received);
    drop(pending);
    drop(original_authority);
    let resumed = authority(domain);
    assert_eq!(resumed.pending_count().unwrap(), 1);
    assert_eq!(resumed.owner_of(stamps(0, 1)[0]).unwrap(), None);
    assert_eq!(
        resumed.register_allocator_owned(SENDER, 1, &stamps(0, 2)),
        Err(Error::AllocationBusy)
    );
}

#[test]
fn local_and_global_admission_limit_do_not_consume_source() {
    let domain = 1010;
    let registry = DomainAuthority::open(domain, RECEIVER, 1, &[(1, 1), (2, 1)]).unwrap();
    let left = stamps(0, 1);
    let right = stamps(10, 1);
    registry.register_allocator_owned(SENDER, 1, &left).unwrap();
    registry
        .register_allocator_owned(SENDER, 1, &right)
        .unwrap();
    let mut first = registry
        .prepare(1, SENDER, &proof(domain, 9, 0, 1))
        .unwrap();
    assert_eq!(
        registry
            .prepare(2, SENDER, &proof(domain, 10, 10, 1))
            .unwrap_err(),
        Error::Broker(BrokerError::Delivery(DeliveryError::MailboxFull))
    );
    assert_eq!(registry.owner_of(right[0]).unwrap(), Some((SENDER, 1)));
    first.abort().unwrap();
    let mut second = registry
        .prepare(2, SENDER, &proof(domain, 10, 10, 1))
        .unwrap();
    second.abort().unwrap();
}

#[test]
fn simultaneous_mailmen_admit_at_most_one_transfer_of_a_graph() {
    let domain = 1011;
    let registry = authority(domain);
    registry
        .register_allocator_owned(SENDER, 1, &stamps(0, 1))
        .unwrap();
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for n in 0..8u32 {
        let worker = registry.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            let bound = proof(domain, n + 9, 0, 1);
            barrier.wait();
            // Keep reservation live long enough to let all contenders test.
            let pending = worker.prepare(1 + n % 2, SENDER, &bound);
            if let Ok(permit) = pending {
                barrier.wait();
                drop(permit);
                Ok(())
            } else {
                barrier.wait();
                pending.map(|_| ())
            }
        }));
    }
    barrier.wait();
    barrier.wait();
    let outcomes: Vec<_> = threads.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|item| item.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|item| **item == Err(Error::AllocationBusy))
            .count(),
        7
    );
    assert_eq!(registry.pending_count().unwrap(), 0);
    assert_eq!(
        registry.owner_of(stamps(0, 1)[0]).unwrap(),
        Some((SENDER, 1))
    );
}

#[test]
fn receiver_must_bind_nonzero_owner_slot_and_cannot_accept_twice() {
    let domain = 1012;
    let registry = authority(domain);
    registry
        .register_allocator_owned(SENDER, 1, &stamps(0, 1))
        .unwrap();
    let mut permit = registry
        .prepare(1, SENDER, &proof(domain, 9, 0, 1))
        .unwrap();
    let mut received = permit.commit().unwrap();
    let session = registry.receiver_session(RECEIVER).unwrap();
    assert_eq!(received.accept(&session, 0), Err(Error::InvalidOwner));
    assert_eq!(registry.owner_of(stamps(0, 1)[0]).unwrap(), None);
    received.accept(&session, 99).unwrap();
    assert_eq!(received.accept(&session, 99), Err(Error::GrantState));
    assert_eq!(
        registry.owner_of(stamps(0, 1)[0]).unwrap(),
        Some((RECEIVER, 99))
    );
}

#[test]
fn only_scheduler_bound_receiver_can_accept_committed_transfer() {
    let domain = 1013;
    let registry = authority(domain);
    registry.register_allocator_owned(SENDER, 1, &stamps(0, 1)).unwrap();
    let mut permit = registry.prepare(1, SENDER, &proof(domain, 9, 0, 1)).unwrap();
    let mut received = permit.commit().unwrap();

    let wrong_id = ActorIdentity { id: RECEIVER.id + 1, generation: RECEIVER.generation };
    assert_eq!(registry.receiver_session(wrong_id).unwrap_err(), Error::WrongReceiver);
    let wrong_generation = ActorIdentity { id: RECEIVER.id, generation: RECEIVER.generation + 1 };
    assert_eq!(registry.receiver_session(wrong_generation).unwrap_err(), Error::WrongReceiver);

    let foreign = authority(1014);
    let foreign_session = foreign.receiver_session(RECEIVER).unwrap();
    assert_eq!(received.accept(&foreign_session, 99), Err(Error::WrongReceiver));
    assert_eq!(registry.owner_of(stamps(0, 1)[0]).unwrap(), None);

    let actual = registry.receiver_session(RECEIVER).unwrap();
    received.accept(&actual, 99).unwrap();
    assert_eq!(registry.owner_of(stamps(0, 1)[0]).unwrap(), Some((RECEIVER, 99)));
    assert_eq!(received.accept(&actual, 99), Err(Error::GrantState));
}

#[test]
fn sender_cannot_reclaim_or_reassign_inflight_memory() {
    let domain = 1015;
    let registry = authority(domain);
    let allocation = stamps(0, 1);
    registry.register_allocator_owned(SENDER, 1, &allocation).unwrap();
    let mut permit = registry.prepare(1, SENDER, &proof(domain, 9, 0, 1)).unwrap();
    assert_eq!(
        registry.retire_destroyed(SENDER, 1, &allocation),
        Err(Error::AllocationBusy)
    );
    let mut received = permit.commit().unwrap();
    assert_eq!(
        registry.retire_destroyed(SENDER, 1, &allocation),
        Err(Error::AllocationBusy)
    );
    assert_eq!(
        registry.register_allocator_owned(SENDER, 2, &stamps(0, 2)),
        Err(Error::AllocationBusy)
    );
    assert_eq!(registry.owner_of(allocation[0]).unwrap(), None);
    received.accept(&registry.receiver_session(RECEIVER).unwrap(), 17).unwrap();
    assert_eq!(
        registry.retire_destroyed(SENDER, 1, &allocation),
        Err(Error::OwnerMismatch)
    );
}

#[test]
fn two_references_to_same_domain_have_identical_receiver_authority() {
    let domain = 1016;
    let sender_side = authority(domain);
    let receiver_side = authority(domain);
    sender_side.register_allocator_owned(SENDER, 1, &stamps(0, 1)).unwrap();
    let mut permit = sender_side.prepare(1, SENDER, &proof(domain, 9, 0, 1)).unwrap();
    let mut envelope = permit.commit().unwrap();
    let session = receiver_side.receiver_session(RECEIVER).unwrap();
    envelope.accept(&session, 18).unwrap();
    assert_eq!(
        sender_side.owner_of(stamps(0, 1)[0]).unwrap(),
        Some((RECEIVER, 18))
    );
}

#[test]
fn rejected_wrong_receiver_does_not_consume_envelope() {
    let domain = 1017;
    let registry = authority(domain);
    registry.register_allocator_owned(SENDER, 1, &stamps(0, 1)).unwrap();
    let mut permit = registry.prepare(1, SENDER, &proof(domain, 9, 0, 1)).unwrap();
    let mut envelope = permit.commit().unwrap();
    let foreign = authority(1018);
    assert_eq!(
        envelope.accept(&foreign.receiver_session(RECEIVER).unwrap(), 7),
        Err(Error::WrongReceiver)
    );
    assert_eq!(registry.pending_count().unwrap(), 1);
    envelope.accept(&registry.receiver_session(RECEIVER).unwrap(), 7).unwrap();
    assert_eq!(registry.pending_count().unwrap(), 0);
}
