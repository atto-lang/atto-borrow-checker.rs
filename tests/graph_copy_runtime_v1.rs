//! Tests of the bounded *semantic model*; these do not execute AttoLang guests.
use atto_borrow_checker::copy_graph_v1::{Error, Field, FieldKind, TypeDescriptor};
use atto_borrow_checker::graph_copy_runtime_v1::{
    Arena, GraphCopyContext, Node, Slot, MAX_CLONE_DEPTH, MAX_CLONE_FIELDS,
};

fn ty(id: u32, parent: Option<u32>, kinds: &[FieldKind]) -> TypeDescriptor {
    TypeDescriptor {
        id,
        parent,
        fields: kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| Field {
                id: i as u32 + 1,
                kind,
            })
            .collect(),
        deep_copy_witness: true,
        shallow_copy_witness: false,
        sendable: true,
    }
}
fn node(ty: u32, fields: Vec<Slot>) -> Node {
    Node {
        concrete_type: ty,
        fields,
    }
}
fn scalar(value: i64) -> Slot {
    Slot::Scalar(value)
}
fn child(id: usize) -> Slot {
    Slot::Mutable(Some(id))
}

#[test]
fn nested_mutable_graph_detaches_the_source() {
    let types = [
        ty(1, None, &[FieldKind::OwnedMutable(2)]),
        ty(2, None, &[FieldKind::Scalar]),
    ];
    let original = Arena {
        nodes: vec![node(1, vec![child(1)]), node(2, vec![scalar(42)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 10).unwrap();
    let copied = ctx.copy_root(0, 1, true).unwrap();
    drop(ctx);
    assert_eq!(copied, 0);
    assert_eq!(destination.nodes.len(), 2);
    destination.nodes[1].fields[0] = scalar(99);
    assert_eq!(original.nodes[1].fields[0], scalar(42));
}

#[test]
fn repeated_aliases_are_memoized_in_one_destination_graph() {
    let types = [
        ty(
            1,
            None,
            &[FieldKind::OwnedMutable(2), FieldKind::OwnedMutable(2)],
        ),
        ty(2, None, &[FieldKind::Scalar]),
    ];
    let original = Arena {
        nodes: vec![node(1, vec![child(1), child(1)]), node(2, vec![scalar(42)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 10).unwrap();
    ctx.copy_root(0, 1, false).unwrap();
    drop(ctx);
    assert_eq!(destination.nodes.len(), 2);
    assert_eq!(destination.nodes[0].fields, vec![child(1), child(1)]);
}

#[test]
fn cyclic_self_reference_is_memoized_before_recursion() {
    let types = [ty(1, None, &[FieldKind::OwnedMutable(1)])];
    let original = Arena {
        nodes: vec![node(1, vec![child(0)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 10).unwrap();
    ctx.copy_root(0, 1, false).unwrap();
    drop(ctx);
    assert_eq!(destination.nodes, vec![node(1, vec![child(0)])]);
}

#[test]
fn actor_fan_out_uses_independent_memo_and_destination_arenas() {
    let types = [
        ty(1, None, &[FieldKind::OwnedMutable(2)]),
        ty(2, None, &[FieldKind::Scalar]),
    ];
    let original = Arena {
        nodes: vec![node(1, vec![child(1)]), node(2, vec![scalar(42)])],
    };
    let mut first = Arena::default();
    let mut second = Arena::default();
    GraphCopyContext::new(&types, &original, &mut first, 8)
        .unwrap()
        .copy_root(0, 1, true)
        .unwrap();
    GraphCopyContext::new(&types, &original, &mut second, 8)
        .unwrap()
        .copy_root(0, 1, true)
        .unwrap();
    first.nodes[1].fields[0] = scalar(99);
    second.nodes[1].fields[0] = scalar(2);
    assert_eq!(original.nodes[1].fields[0], scalar(42));
    assert_eq!(first.nodes[1].fields[0], scalar(99));
    assert_eq!(second.nodes[1].fields[0], scalar(2));
}

#[test]
fn failed_copy_rolls_back_only_its_own_allocation() {
    let types = [
        ty(1, None, &[FieldKind::OwnedMutable(2)]),
        ty(2, None, &[FieldKind::Scalar]),
    ];
    let original = Arena {
        nodes: vec![node(1, vec![child(1)]), node(2, vec![scalar(42)])],
    };
    let admitted_before = node(2, vec![scalar(7)]);
    let mut destination = Arena {
        nodes: vec![admitted_before.clone()],
    };
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 1).unwrap();
    assert_eq!(ctx.copy_root(0, 1, true), Err(Error("E_COPY_GRAPH_BUDGET")));
    drop(ctx);
    assert_eq!(destination.nodes, vec![admitted_before]);
}

#[test]
fn missing_child_or_wrong_dynamic_type_is_rejected_atomically() {
    let types = [
        ty(1, None, &[FieldKind::OwnedMutable(2)]),
        ty(2, None, &[FieldKind::Scalar]),
    ];
    for original in [
        Arena {
            nodes: vec![node(1, vec![child(999)])],
        },
        Arena {
            nodes: vec![node(1, vec![child(1)]), node(1, vec![child(1)])],
        },
    ] {
        let mut destination = Arena::default();
        let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 10).unwrap();
        assert_eq!(ctx.copy_root(0, 1, false), Err(Error("E_COPY_LAYOUT")));
        drop(ctx);
        assert!(destination.nodes.is_empty());
    }
}

#[test]
fn all_inherited_private_field_slots_are_preserved() {
    let types = [
        ty(1, None, &[FieldKind::Scalar]),
        ty(2, Some(1), &[FieldKind::Scalar]),
    ];
    let original = Arena {
        nodes: vec![node(2, vec![scalar(40), scalar(2)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 4).unwrap();
    ctx.copy_root(0, 1, true).unwrap(); // Base-typed copy, dynamic Derived.
    drop(ctx);
    assert_eq!(
        destination.nodes,
        vec![node(2, vec![scalar(40), scalar(2)])]
    );
}

#[test]
fn non_sendable_nested_child_prevents_actor_copy_before_allocation() {
    let mut bad_child = ty(2, None, &[FieldKind::Scalar]);
    bad_child.sendable = false;
    let types = [ty(1, None, &[FieldKind::OwnedMutable(2)]), bad_child];
    let original = Arena {
        nodes: vec![node(1, vec![child(1)]), node(2, vec![scalar(2)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 8).unwrap();
    assert_eq!(ctx.copy_root(0, 1, true), Err(Error("E_COPY_SENDABLE")));
    drop(ctx);
    assert!(destination.nodes.is_empty());
}

#[test]
fn runtime_field_layout_mismatch_is_rejected() {
    let types = [ty(1, None, &[FieldKind::Scalar])];
    let original = Arena {
        nodes: vec![node(1, vec![Slot::Mutable(None)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 4).unwrap();
    assert_eq!(ctx.copy_root(0, 1, false), Err(Error("E_COPY_LAYOUT")));
    drop(ctx);
    assert!(destination.nodes.is_empty());
}

#[test]
fn frozen_references_preserve_token_identity_but_not_mutable_aliases() {
    let types = [ty(1, None, &[FieldKind::ImmutableShared])];
    let original = Arena {
        nodes: vec![node(1, vec![Slot::Frozen(42)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 4).unwrap();
    ctx.copy_root(0, 1, true).unwrap();
    drop(ctx);
    assert_eq!(destination.nodes, original.nodes);
}

#[test]
fn context_reuse_is_refused_after_success() {
    let types = [ty(1, None, &[FieldKind::Scalar])];
    let original = Arena {
        nodes: vec![node(1, vec![scalar(42)])],
    };
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 4).unwrap();
    ctx.copy_root(0, 1, false).unwrap();
    assert_eq!(
        ctx.copy_root(0, 1, false),
        Err(Error("E_COPY_CONTEXT_REUSE"))
    );
}

#[test]
fn deep_chain_hits_bound_and_rolls_back_without_stack_overflow() {
    let types = [ty(1, None, &[FieldKind::OwnedMutable(1)])];
    let mut original = Arena::default();
    for i in 0..(MAX_CLONE_DEPTH + 1) {
        original.push(node(
            1,
            vec![if i == MAX_CLONE_DEPTH {
                Slot::Mutable(None)
            } else {
                child(i + 1)
            }],
        ));
    }
    let mut destination = Arena::default();
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 1024).unwrap();
    assert_eq!(
        ctx.copy_root(0, 1, false),
        Err(Error("E_COPY_GRAPH_BUDGET"))
    );
    drop(ctx);
    assert!(destination.nodes.is_empty());
}

#[test]
fn aggregate_flattened_field_budget_is_atomic_and_context_can_retry() {
    // One descriptor reused by three nodes; the descriptor inventory fits,
    // but a deep copy must also bound the aggregate runtime field count.
    let width = MAX_CLONE_FIELDS / 2;
    let mut kinds = vec![FieldKind::Scalar; width];
    kinds[0] = FieldKind::OwnedMutable(1);
    let types = [ty(1, None, &kinds)];
    let mut original = Arena::default();
    for next in [Some(1), Some(2), None] {
        let mut fields = vec![scalar(42); width];
        fields[0] = Slot::Mutable(next);
        original.push(node(1, fields));
    }
    let existing = node(1, vec![]);
    let mut destination = Arena {
        nodes: vec![existing.clone()],
    };
    let mut ctx = GraphCopyContext::new(&types, &original, &mut destination, 4).unwrap();
    assert_eq!(
        ctx.copy_root(0, 1, false),
        Err(Error("E_COPY_GRAPH_BUDGET"))
    );
    // Exactly at the field limit: retry must not retain the failed copy's
    // field charges, memo entries, or shell allocations.
    assert_eq!(ctx.copy_root(1, 1, false).unwrap(), 1);
    drop(ctx);
    assert_eq!(destination.nodes.len(), 3);
    assert_eq!(destination.nodes[0], existing);
    assert_eq!(destination.nodes[1].fields[0], child(2));
    assert_eq!(destination.nodes[2].fields[0], Slot::Mutable(None));
}

#[test]
fn repeated_aliases_do_not_charge_the_same_runtime_node_twice() {
    let width = MAX_CLONE_FIELDS - 2;
    let types = [
        ty(
            1,
            None,
            &[FieldKind::OwnedMutable(2), FieldKind::OwnedMutable(2)],
        ),
        ty(2, None, &vec![FieldKind::Scalar; width]),
    ];
    let original = Arena {
        nodes: vec![
            node(1, vec![child(1), child(1)]),
            node(2, vec![scalar(42); width]),
        ],
    };
    let mut destination = Arena::default();
    GraphCopyContext::new(&types, &original, &mut destination, 4)
        .unwrap()
        .copy_root(0, 1, false)
        .unwrap();
    assert_eq!(destination.nodes.len(), 2);
    assert_eq!(destination.nodes[0].fields, vec![child(1), child(1)]);
    assert_eq!(destination.nodes[1].fields.len(), width);
}
