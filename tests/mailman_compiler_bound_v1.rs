//! Executable Rust host model tests. Not actual AttoLang guest code or runtime
//! authentication. The census and graph are compiler-supplied claims.
use atto_borrow_checker::mailman_compiler_bound_v1::{
    verify_compiler_transfer, CompilerBoundTransfer, CompilerSendCensus, Error,
    SharedTransferBroker, SourceTransferSite, CONTRACT_VERSION,
};
use atto_borrow_checker::mailman_delivery_v1::{
    Allocation, DeliveryMode, DeliveryRequest, Error as DeliveryError, GraphInventory,
};
use atto_borrow_checker::mir_v1::{
    Effect, Instruction, MirBlock, MirFunction, Producer, CONTRACT_VERSION as MIR_VERSION,
};
use atto_borrow_checker::{Op, Traits};

fn graph(offset: u32, generation: u64) -> GraphInventory {
    let node = |id, references: Vec<u32>| Allocation {
        id: id + offset,
        owner_domain: 7,
        allocation_generation: generation,
        mutable: true,
        sendable: true,
        deep_copyable: true,
        frozen: false,
        sync: false,
        references: references.into_iter().map(|x| x + offset).collect(),
        escaped_aliases: 0,
        active_readers: 0,
        active_writer: false,
    };
    GraphInventory {
        root: 1 + offset,
        nodes: vec![
            node(1, vec![2, 2]),
            node(2, vec![1, 3]),
            node(3, vec![]),
        ],
        expected_reachable: vec![1 + offset, 2 + offset, 3 + offset],
    }
}

fn request(ticket: u64) -> DeliveryRequest {
    DeliveryRequest {
        mode: DeliveryMode::Transfer,
        source_domain: 7,
        destination_domain: 7,
        source_actor_generation: 11,
        destination_actor_generation: 12,
        ticket,
        ticket_generation: 5,
        lease_may_suspend: false,
        pinned_lease_proven: false,
        scoped_lease_proven: false,
        allow_elision: false,
        source_observable_after_send: true,
        copy_identity_or_hooks_observable: true,
    }
}

fn instruction(id: u64, effect: Effect, operation: Op) -> Instruction {
    Instruction {
        instruction_id: id,
        source_node_id: 100 + id,
        effect,
        operation,
    }
}

fn function(ticket: u32) -> MirFunction {
    MirFunction {
        version: MIR_VERSION.into(),
        producer: Producer {
            compiler_git_sha: "a".repeat(40),
            source_sha256: "b".repeat(64),
            source_unit_id: 2,
            function_id: 1,
        },
        entry: 0,
        expected_instruction_ids: (1..=7).collect(),
        blocks: vec![
            MirBlock {
                id: 0,
                instructions: vec![
                    instruction(1, Effect::Ownership, Op::Init {
                        owner: 1,
                        traits: Traits { is_copy: false, is_send: true },
                    }),
                    instruction(2, Effect::ActorBoundary, Op::ActorSendPrepare {
                        owner: 1, ticket,
                    }),
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

fn census(program: &MirFunction, ticket: u32) -> CompilerSendCensus {
    CompilerSendCensus {
        version: CONTRACT_VERSION.into(),
        producer: program.producer.clone(),
        source_transfer_sites: vec![SourceTransferSite {
            instruction_id: 2,
            source_node_id: 102,
            owner: 1,
            ticket,
        }],
    }
}

fn verify(ticket: u32, graph: &GraphInventory) -> Result<CompilerBoundTransfer, Error> {
    let program = function(ticket);
    verify_compiler_transfer(&program, &census(&program, ticket), graph, &request(ticket.into()))
}

#[test]
fn verifies_complete_typed_mir_and_opaque_graph_transfer() {
    let proven = verify(9, &graph(0, 1)).unwrap();
    assert_eq!(proven.source_node_id(), 102);
    assert_eq!(proven.owner(), 1);
    assert_eq!(proven.compiler_git_sha(), "a".repeat(40));
    assert_eq!(proven.source_sha256(), "b".repeat(64));
}

#[test]
fn rejects_missing_duplicate_mismatched_and_overbudget_source_sites() {
    let program = function(9);
    let mut census = census(&program, 9);
    census.source_transfer_sites.clear();
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::InvalidSite
    );
    census = census(&program, 9);
    census.source_transfer_sites.push(census.source_transfer_sites[0].clone());
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::DuplicateSite
    );
    census = census(&program, 9);
    census.source_transfer_sites[0].source_node_id = 999;
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::SendSiteMismatch
    );
    census = census(&program, 9);
    census.source_transfer_sites[0].ticket = 10;
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::SendSiteMismatch
    );
    census = census(&program, 9);
    census.source_transfer_sites[0].instruction_id = 300;
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::IncompleteCensus
    );
    census = census(&program, 9);
    census.source_transfer_sites[0].owner = 2;
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::SendSiteMismatch
    );
    census = census(&program, 9);
    census.source_transfer_sites[0].owner = 0;
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::InvalidSite
    );
    census = census(&program, 9);
    census.source_transfer_sites = (0..4097)
        .map(|i| SourceTransferSite {
            instruction_id: (i + 1) as u64,
            source_node_id: (i + 101) as u64,
            owner: 1,
            ticket: (i + 1) as u32,
        })
        .collect();
    assert_eq!(
        verify_compiler_transfer(&program, &census, &graph(0, 1), &request(9))
            .unwrap_err(),
        Error::InvalidSite
    );
}

#[test]
fn rejects_wrong_version_producer_and_unauthenticated_mir_claims() {
    let program = function(9);
    let mut c = census(&program, 9);
    c.version = "untrusted".into();
    assert_eq!(
        verify_compiler_transfer(&program, &c, &graph(0, 1), &request(9)).unwrap_err(),
        Error::CensusVersion
    );
    c = census(&program, 9);
    c.producer.source_sha256 = "c".repeat(64);
    assert_eq!(
        verify_compiler_transfer(&program, &c, &graph(0, 1), &request(9)).unwrap_err(),
        Error::ProducerMismatch
    );
    let mut invalid = program.clone();
    invalid.expected_instruction_ids.pop();
    assert!(matches!(
        verify_compiler_transfer(&invalid, &census(&invalid, 9), &graph(0, 1), &request(9)),
        Err(Error::MirInvalid(_))
    ));
    let mut wrong_effect = program.clone();
    wrong_effect.blocks[0].instructions[1].effect = Effect::Ownership;
    assert!(matches!(
        verify_compiler_transfer(
            &wrong_effect, &census(&wrong_effect, 9), &graph(0, 1), &request(9)),
        Err(Error::MirInvalid(_))
    ));
}

#[test]
fn missing_rollback_path_or_unmodeled_actor_operation_fails_closed() {
    let mut program = function(9);
    program.blocks[2].instructions.remove(0);
    program.blocks[2].instructions.remove(0);
    program.blocks[2].instructions.push(instruction(5, Effect::Control, Op::Return));
    program.expected_instruction_ids = (1..=5).collect();
    assert!(verify_compiler_transfer(
        &program, &census(&program, 9), &graph(0, 1), &request(9)
    ).is_err());

    let mut unsupported = function(9);
    unsupported.blocks[0].instructions.push(instruction(
        8, Effect::ActorBoundary, Op::ActorHopBorrow { owner: 1 },
    ));
    unsupported.expected_instruction_ids.push(8);
    assert!(verify_compiler_transfer(
        &unsupported, &census(&unsupported, 9), &graph(0, 1), &request(9)
    ).is_err());
}

#[test]
fn disallows_other_delivery_modes_and_wrong_graph_domains() {
    let program = function(9);
    let c = census(&program, 9);
    let mut r = request(9);
    for mode in [
        DeliveryMode::DeepCopy,
        DeliveryMode::ReadLease,
        DeliveryMode::WriteLease,
        DeliveryMode::FrozenShare,
    ] {
        r.mode = mode;
        assert_eq!(
            verify_compiler_transfer(&program, &c, &graph(0, 1), &r).unwrap_err(),
            Error::UnsupportedDeliveryMode
        );
    }
    r.mode = DeliveryMode::Transfer;
    r.destination_domain = 8;
    assert_eq!(
        verify_compiler_transfer(&program, &c, &graph(0, 1), &r).unwrap_err(),
        Error::WrongDomain
    );
    r.destination_domain = 7;
    r.ticket = u64::from(u32::MAX) + 1;
    assert_eq!(
        verify_compiler_transfer(&program, &c, &graph(0, 1), &r).unwrap_err(),
        Error::InvalidSite
    );
    r.ticket = 9;
    let mut bad_graph = graph(0, 1);
    bad_graph.nodes[1].escaped_aliases = 1;
    assert_eq!(
        verify_compiler_transfer(&program, &c, &bad_graph, &r).unwrap_err(),
        Error::Delivery(DeliveryError::OwnershipNotExclusive)
    );
}

#[test]
fn different_mailmen_cannot_transfer_same_owned_graph_concurrently() {
    let g = graph(0, 1);
    let a = verify(9, &g).unwrap();
    let b = verify(10, &g).unwrap();
    let mut broker = SharedTransferBroker::new(7, 12, 3, &[(1, 2), (2, 2)]).unwrap();
    broker.prepare(1, &a).unwrap();
    assert_eq!(
        broker.prepare(2, &b),
        Err(Error::Delivery(DeliveryError::LeaseConflict))
    );
    assert_eq!(broker.counts(1), Some((1, 0)));
    assert_eq!(broker.counts(2), Some((0, 0)));
    assert_eq!(broker.commit(2, 9, 5), Err(Error::WrongMailman));
    broker.abort(1, 9, 5).unwrap();
    assert_eq!(broker.counts(1), Some((0, 0)));
    broker.prepare(2, &b).unwrap();
    broker.commit(2, 10, 5).unwrap();
    assert_eq!(broker.counts(2), Some((0, 1)));
    broker.finish(2, 10, 5).unwrap();
    assert_eq!(broker.counts(2), Some((0, 0)));
    assert_eq!(
        broker.prepare(1, &a),
        Err(Error::Delivery(DeliveryError::DuplicateTicket))
    );
}

#[test]
fn committed_transfer_invalidates_all_mailmen_for_same_allocation_epoch() {
    let g = graph(0, 1);
    let a = verify(9, &g).unwrap();
    let b = verify(10, &g).unwrap();
    let mut broker = SharedTransferBroker::new(7, 12, 3, &[(1, 2), (2, 2)]).unwrap();
    broker.prepare(1, &a).unwrap();
    broker.commit(1, 9, 5).unwrap();
    broker.finish(1, 9, 5).unwrap();
    assert_eq!(
        broker.prepare(2, &b),
        Err(Error::Delivery(DeliveryError::OwnershipNotExclusive))
    );
    assert_eq!(broker.counts(2), Some((0, 0)));
    // Reallocation of the same slot with new compiler/runtime epoch is different.
    let fresh = verify(11, &graph(0, 2)).unwrap();
    broker.prepare(2, &fresh).unwrap();
    broker.abort(2, 11, 5).unwrap();
}

#[test]
fn wrong_mailman_cannot_settle_or_steal_ticket() {
    let a = verify(9, &graph(0, 1)).unwrap();
    let mut broker = SharedTransferBroker::new(7, 12, 2, &[(1, 1), (2, 1)]).unwrap();
    broker.prepare(1, &a).unwrap();
    assert_eq!(broker.abort(2, 9, 5), Err(Error::WrongMailman));
    assert_eq!(broker.commit(2, 9, 5), Err(Error::WrongMailman));
    assert_eq!(broker.finish(1, 9, 5), Err(Error::UnknownTicket));
    assert_eq!(broker.counts(1), Some((1, 0)));
    broker.commit(1, 9, 5).unwrap();
    assert_eq!(broker.abort(1, 9, 5), Err(Error::UnknownTicket));
    assert_eq!(broker.finish(2, 9, 5), Err(Error::WrongMailman));
    broker.finish(1, 9, 5).unwrap();
    assert_eq!(broker.finish(1, 9, 5), Err(Error::UnknownTicket));
}

#[test]
fn local_and_global_backpressure_preserves_all_ownership_on_rejection() {
    let a = verify(9, &graph(0, 1)).unwrap();
    let b = verify(10, &graph(10, 1)).unwrap();
    let c = verify(11, &graph(20, 1)).unwrap();
    let mut broker = SharedTransferBroker::new(7, 12, 2, &[(1, 1), (2, 2)]).unwrap();
    broker.prepare(1, &a).unwrap();
    assert_eq!(broker.prepare(1, &b), Err(Error::MailmanFull));
    assert_eq!(broker.counts(1), Some((1, 0)));
    broker.prepare(2, &b).unwrap();
    assert_eq!(
        broker.prepare(2, &c),
        Err(Error::Delivery(DeliveryError::MailboxFull))
    );
    broker.abort(1, 9, 5).unwrap();
    broker.prepare(2, &c).unwrap();
    broker.abort(2, 11, 5).unwrap();
    broker.abort(2, 10, 5).unwrap();
    assert_eq!(broker.counts(1), Some((0, 0)));
    assert_eq!(broker.counts(2), Some((0, 0)));
}

#[test]
fn invalid_broker_domain_epoch_and_mailman_ids_fail_closed() {
    for (domain, generation, capacity, mailmen) in [
        (0, 12, 2, vec![(1, 2)]),
        (7, 0, 2, vec![(1, 2)]),
        (7, 12, 0, vec![(1, 2)]),
        (7, 12, 2, vec![]),
        (7, 12, 2, vec![(0, 1)]),
        (7, 12, 2, vec![(1, 0)]),
        (7, 12, 2, vec![(1, 2), (1, 2)]),
    ] {
        assert!(matches!(
            SharedTransferBroker::new(domain, generation, capacity, &mailmen),
            Err(Error::InvalidBroker)
        ));
    }
    let proof = verify(9, &graph(0, 1)).unwrap();
    let mut broker = SharedTransferBroker::new(7, 12, 2, &[(1, 1)]).unwrap();
    assert_eq!(broker.prepare(2, &proof), Err(Error::InvalidMailman));
    let wrong_epoch = {
        let mut r = request(10);
        r.destination_actor_generation = 13;
        let program = function(10);
        verify_compiler_transfer(&program, &census(&program, 10), &graph(0, 1), &r).unwrap()
    };
    assert_eq!(
        broker.prepare(1, &wrong_epoch),
        Err(Error::Delivery(DeliveryError::StaleGeneration))
    );
    let wrong_domain = {
        let mut r = request(11);
        r.source_domain = 8;
        r.destination_domain = 8;
        let mut g = graph(0, 1);
        for node in &mut g.nodes { node.owner_domain = 8; }
        let program = function(11);
        verify_compiler_transfer(&program, &census(&program, 11), &g, &r).unwrap()
    };
    assert_eq!(broker.prepare(1, &wrong_domain), Err(Error::WrongDomain));
    assert_eq!(broker.counts(1), Some((0, 0)));
}
