//! MIR inventory/effect tests for the new capability event operations.
//! A correct event trace alone cannot certify backend storage or ABI.
use atto_borrow_checker::{
    mir_v1::{
        verify_mir, Effect, Instruction, MirBlock, MirError, MirFunction, Producer,
        CONTRACT_VERSION,
    },
    Op, Traits,
};

fn sample() -> MirFunction {
    let ops = vec![
        (
            Effect::Ownership,
            Op::Init {
                owner: 1,
                traits: Traits {
                    is_copy: false,
                    is_send: true,
                },
            },
        ),
        // Pin an independent owner so the published region has no
        // unresolved pinned-allocation transfer across actor domains.
        (
            Effect::Ownership,
            Op::Init {
                owner: 3,
                traits: Traits {
                    is_copy: false,
                    is_send: true,
                },
            },
        ),
        (
            Effect::Ownership,
            Op::Freeze {
                from: 1,
                into: 2,
                deep_proven: true,
            },
        ),
        (
            Effect::Ownership,
            Op::PinStorage {
                owner: 3,
                stable_address_proven: true,
            },
        ),
        (
            Effect::ActorBoundary,
            Op::PublishFrozen {
                owner: 2,
                region: 7,
                sync_proven: true,
            },
        ),
        (
            Effect::Ownership,
            Op::CreateWeak {
                region: 7,
                weak: 10,
                generation_fenced: true,
            },
        ),
        (
            Effect::Ownership,
            Op::ProbeWeak {
                weak: 10,
                generation_fenced: true,
            },
        ),
        (Effect::Control, Op::Return),
    ];
    MirFunction {
        version: CONTRACT_VERSION.to_owned(),
        producer: Producer {
            compiler_git_sha: "c".repeat(40),
            source_sha256: "d".repeat(64),
            source_unit_id: 7,
            function_id: 9,
        },
        entry: 0,
        expected_instruction_ids: (1..=ops.len() as u64).collect(),
        blocks: vec![MirBlock {
            id: 0,
            instructions: ops
                .into_iter()
                .enumerate()
                .map(|(i, (effect, operation))| Instruction {
                    instruction_id: i as u64 + 1,
                    source_node_id: i as u64 + 101,
                    effect,
                    operation,
                })
                .collect(),
            successors: vec![],
        }],
    }
}

#[test]
fn freeze_pin_publish_weak_has_valid_effect_inventory() {
    let proof = verify_mir(&sample()).unwrap();
    assert_eq!(proof.cleanup_by_exit[&0], vec![3]);
}

#[test]
fn a_weak_event_cannot_masquerade_as_actor_mail_admission() {
    let mut mir = sample();
    mir.blocks[0].instructions[5].effect = Effect::ActorBoundary;
    assert_eq!(
        verify_mir(&mir),
        Err(MirError::Invalid("E_MIR_EFFECT_MISMATCH"))
    );
}

#[test]
fn an_omitted_pinning_instruction_is_detected_by_inventory() {
    let mut mir = sample();
    mir.blocks[0].instructions.remove(3);
    assert_eq!(
        verify_mir(&mir),
        Err(MirError::Invalid("E_MIR_INCOMPLETE_INVENTORY"))
    );
}

#[test]
fn missing_deep_freeze_witness_rejects_semantically_even_if_inventory_passes() {
    let mut mir = sample();
    mir.blocks[0].instructions[2].operation = Op::Freeze {
        from: 1,
        into: 2,
        deep_proven: false,
    };
    assert!(matches!(verify_mir(&mir), Err(MirError::Unsafe(d))
        if d.code == "E_DEEP_FREEZE_PROOF_REQUIRED"));
}

#[test]
fn pinned_region_publication_requires_separate_backend_address_handoff_proof() {
    let mut mir = sample();
    // Publishing the pinned owner would transfer storage to a region that
    // may use a different allocator; only a typed address-stability handoff
    // can authorize this in a future MIR profile.
    mir.blocks[0].instructions[4].operation = Op::PublishFrozen {
        owner: 3,
        region: 7,
        sync_proven: true,
    };
    assert!(matches!(verify_mir(&mir), Err(MirError::Unsafe(d))
        if d.code == "E_PIN_BOUNDARY_TRANSFER"));
}
