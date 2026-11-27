//! Bounded **reference model**, not a linked AttoLang guest or a generic
//! production heap copier. Provides an executable semantic oracle for AOT
//! graph-cloning code generation and actor-isolated allocation domains.
//!
//! This deliberately does no dynamic reflection: the field type, slot count,
//! deep-copy witness and Sendable gate come from the canonical closed-world
//! TypeDescriptor inventory, independently admitted by copy_graph_v1.
//!
//! Generated backends must replace this Vec-based model with statically
//! compiled layouts and destination-heap allocators, preserving its memo,
//! transactional cleanup and failure semantics exactly.

use std::collections::BTreeMap;

use crate::copy_graph_v1::{
    admit_copy, CopyMode, CopyRequest, Error, FieldKind, TypeDescriptor, TypeId,
};

/// Reference-only node index inside exactly one Arena.
pub type NodeId = usize;
pub const MAX_CLONE_NODES: usize = 1024;
pub const MAX_CLONE_DEPTH: usize = 128;
/// Bound aggregate flattened runtime field visits, not just descriptor fields.
pub const MAX_CLONE_FIELDS: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    Scalar(i64),
    /// Runtime identity of an owned/mutable descendant inside the source
    /// arena. None is a null pointer, not a graph node.
    Mutable(Option<NodeId>),
    /// A verified nonmutable, globally stable reference; never mutable data.
    Frozen(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub concrete_type: TypeId,
    /// Ordered full field inventory, including superclass/private slots.
    pub fields: Vec<Slot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Arena {
    pub nodes: Vec<Node>,
}

impl Arena {
    pub fn push(&mut self, node: Node) -> NodeId {
        let idx = self.nodes.len();
        self.nodes.push(node);
        idx
    }
}

/// A top-level copy gets a fresh context. Never share it among actor sends;
/// no static/runtime-global identity cache is permitted.
pub struct GraphCopyContext<'a> {
    descriptors: &'a [TypeDescriptor],
    types: BTreeMap<TypeId, &'a TypeDescriptor>,
    source: &'a Arena,
    destination: &'a mut Arena,
    memo: BTreeMap<NodeId, NodeId>,
    max_nodes: usize,
    appended: usize,
    fields_visited: usize,
}

impl<'a> GraphCopyContext<'a> {
    /// Descriptors must be compiler-authenticated. This reference model
    /// cannot itself prove the frontend's declared inventory is complete.
    pub fn new(
        types: &'a [TypeDescriptor],
        source: &'a Arena,
        destination: &'a mut Arena,
        max_nodes: usize,
    ) -> Result<Self, Error> {
        if max_nodes == 0 || max_nodes > MAX_CLONE_NODES {
            return Err(Error("E_COPY_GRAPH_BUDGET"));
        }
        if types.is_empty() || types.len() > crate::copy_graph_v1::MAX_COPY_TYPES {
            return Err(Error("E_COPY_GRAPH_BUDGET"));
        }
        let mut by_type = BTreeMap::new();
        for ty in types {
            if ty.id == 0 || by_type.insert(ty.id, ty).is_some() {
                return Err(Error("E_COPY_LAYOUT"));
            }
        }
        Ok(Self {
            descriptors: types,
            types: by_type,
            source,
            destination,
            memo: BTreeMap::new(),
            max_nodes,
            appended: 0,
            fields_visited: 0,
        })
    }

    /// Publish a complete detached destination graph or leave the destination
    /// arena unchanged. Failed copies never destroy prior accepted payloads.
    /// This caller owns a fresh memo per top-level invocation.
    pub fn copy_root(
        &mut self,
        root: NodeId,
        static_type: TypeId,
        actor_send: bool,
    ) -> Result<NodeId, Error> {
        if self.appended != 0 || !self.memo.is_empty() {
            return Err(Error("E_COPY_CONTEXT_REUSE"));
        }
        let concrete = self
            .source
            .nodes
            .get(root)
            .ok_or(Error("E_COPY_LAYOUT"))?
            .concrete_type;
        admit_copy(
            self.descriptors,
            CopyRequest {
                concrete_type: concrete,
                static_type,
                mode: CopyMode::Deep,
                actor_send,
            },
        )?;
        // Validate graph metadata against the admitted descriptors before
        // attempting allocation. A malicious caller cannot simply assert an
        // actor-Sendable witness to bypass actual type graph traversal.
        let checkpoint = self.destination.nodes.len();
        match self.clone_node(root, 0) {
            Ok(node) => Ok(node),
            Err(err) => {
                self.destination.nodes.truncate(checkpoint);
                self.memo.clear();
                self.appended = 0;
                self.fields_visited = 0;
                Err(err)
            }
        }
    }

    fn clone_node(&mut self, source_id: NodeId, depth: usize) -> Result<NodeId, Error> {
        if let Some(&copied) = self.memo.get(&source_id) {
            return Ok(copied);
        }
        if self.appended >= self.max_nodes || depth >= MAX_CLONE_DEPTH {
            return Err(Error("E_COPY_GRAPH_BUDGET"));
        }
        let src = self
            .source
            .nodes
            .get(source_id)
            .ok_or(Error("E_COPY_LAYOUT"))?;
        let type_id = src.concrete_type;
        // The source node must contain the COMPLETE flattened concrete field
        // inventory, including private/inherited base fields in base-first
        // order. Copy the verified layout before recursive &mut self calls.
        let mut layouts = Vec::new();
        let mut cur = Some(type_id);
        let mut ancestors = Vec::new();
        while let Some(id) = cur {
            if ancestors.contains(&id) || ancestors.len() >= crate::copy_graph_v1::MAX_COPY_TYPES {
                return Err(Error("E_COPY_LAYOUT"));
            }
            ancestors.push(id);
            cur = self
                .types
                .get(&id)
                .ok_or(Error("E_COPY_AOT_WITNESS"))?
                .parent;
        }
        // Charge the complete flattened inventory before allocating/cloning
        // its slots. Repeated aliases hit the memo before reaching this path.
        let field_count = ancestors.iter().try_fold(0usize, |total, id| {
            total
                .checked_add(self.types[id].fields.len())
                .ok_or(Error("E_COPY_GRAPH_BUDGET"))
        })?;
        if src.fields.len() != field_count {
            return Err(Error("E_COPY_LAYOUT"));
        }
        let next = self
            .fields_visited
            .checked_add(field_count)
            .ok_or(Error("E_COPY_GRAPH_BUDGET"))?;
        if next > MAX_CLONE_FIELDS {
            return Err(Error("E_COPY_GRAPH_BUDGET"));
        }
        self.fields_visited = next;
        for id in ancestors.into_iter().rev() {
            layouts.extend(self.types[&id].fields.iter().cloned());
        }
        let fields = src.fields.clone();
        // Constructor-free clone shell, tracked before visiting descendants.
        // This ordering is essential for repeated references and cycles.
        let dst_id = self.destination.nodes.len();
        self.destination.nodes.push(Node {
            concrete_type: type_id,
            fields: Vec::new(),
        });
        self.appended += 1;
        self.memo.insert(source_id, dst_id);

        let mut cloned = Vec::with_capacity(fields.len());
        for (value, field) in fields.iter().zip(&layouts) {
            let result = match (value, field.kind) {
                (Slot::Scalar(v), FieldKind::Scalar) => Slot::Scalar(*v),
                (Slot::Frozen(id), FieldKind::ImmutableShared) => Slot::Frozen(*id),
                (Slot::Mutable(None), FieldKind::OwnedMutable(_) | FieldKind::SharedMutable(_)) => {
                    Slot::Mutable(None)
                }
                (
                    Slot::Mutable(Some(child)),
                    FieldKind::OwnedMutable(expected) | FieldKind::SharedMutable(expected),
                ) => {
                    let actual = self
                        .source
                        .nodes
                        .get(*child)
                        .ok_or(Error("E_COPY_LAYOUT"))?
                        .concrete_type;
                    if actual != expected {
                        return Err(Error("E_COPY_LAYOUT"));
                    }
                    Slot::Mutable(Some(self.clone_node(*child, depth + 1)?))
                }
                (_, FieldKind::Borrowed) => return Err(Error("E_COPY_VIEW")),
                (_, FieldKind::Resource) => return Err(Error("E_COPY_FORBIDDEN")),
                (_, FieldKind::Unresolved) => return Err(Error("E_COPY_UNPROVEN")),
                _ => return Err(Error("E_COPY_LAYOUT")),
            };
            cloned.push(result);
        }
        self.destination.nodes[dst_id].fields = cloned;
        Ok(dst_id)
    }
}
