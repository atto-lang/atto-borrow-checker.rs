//! Independent, bounded state-machine oracle for affine checked handles.
//! No raw pointers, allocated guest heap, transport or physical reclamation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_MODEL: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    InvalidIdentity,
    Exhausted,
    ForeignModel,
    WrongActor,
    StaleGeneration,
    InvalidHandle,
    LiveViews,
    InvalidView,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleOp { Ref, Deref, Unref }

pub fn handle_alias(spelling: &str) -> Option<HandleOp> {
    match spelling {
        "ref!" | "rt ref" => Some(HandleOp::Ref),
        "deref!" | "rt deref" => Some(HandleOp::Deref),
        "unref!" | "rt unref" => Some(HandleOp::Unref),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key { model: u64, actor: u64, generation: u64, allocation: u64 }

#[derive(Debug)]
pub struct Owned { key: Key, active: bool }
#[derive(Debug)]
pub struct Handle { key: Key, active: bool }
#[derive(Debug)]
pub struct ReadView { key: Key, lease: u64, active: bool }

#[derive(Debug)]
struct Slot { borrowed_as_handle: bool, readers: BTreeSet<u64> }

#[derive(Debug)]
pub struct CheckedHandleModel {
    model: u64,
    actor: u64,
    generation: u64,
    next_allocation: u64,
    next_lease: u64,
    slots: BTreeMap<u64, Slot>,
}

impl CheckedHandleModel {
    pub fn new(actor: u64, generation: u64) -> Result<Self, HandleError> {
        if actor == 0 || generation == 0 { return Err(HandleError::InvalidIdentity); }
        let model = NEXT_MODEL.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |n| n.checked_add(1)).map_err(|_| HandleError::Exhausted)?;
        Ok(Self { model, actor, generation, next_allocation: 1, next_lease: 1,
            slots: BTreeMap::new() })
    }

    pub fn mint_owner(&mut self) -> Result<Owned, HandleError> {
        let id = self.next_allocation;
        let next = id.checked_add(1).ok_or(HandleError::Exhausted)?;
        self.slots.insert(id, Slot { borrowed_as_handle: false, readers: BTreeSet::new() });
        self.next_allocation = next;
        Ok(Owned { key: Key { model: self.model, actor: self.actor,
            generation: self.generation, allocation: id }, active: true })
    }

    fn verify(&self, key: Key) -> Result<(), HandleError> {
        if key.model != self.model { return Err(HandleError::ForeignModel); }
        if key.actor != self.actor { return Err(HandleError::WrongActor); }
        if key.generation != self.generation { return Err(HandleError::StaleGeneration); }
        if !self.slots.contains_key(&key.allocation) { return Err(HandleError::InvalidHandle); }
        Ok(())
    }

    pub fn ref_owned(&mut self, owned: &mut Owned) -> Result<Handle, HandleError> {
        if !owned.active { return Err(HandleError::InvalidHandle); }
        self.verify(owned.key)?;
        let slot = self.slots.get_mut(&owned.key.allocation).ok_or(HandleError::InvalidHandle)?;
        if slot.borrowed_as_handle || !slot.readers.is_empty() {
            return Err(HandleError::InvalidHandle);
        }
        slot.borrowed_as_handle = true;
        owned.active = false;
        Ok(Handle { key: owned.key, active: true })
    }

    pub fn deref(&mut self, handle: &Handle) -> Result<ReadView, HandleError> {
        if !handle.active { return Err(HandleError::InvalidHandle); }
        self.verify(handle.key)?;
        let next = self.next_lease.checked_add(1).ok_or(HandleError::Exhausted)?;
        let slot = self.slots.get_mut(&handle.key.allocation).ok_or(HandleError::InvalidHandle)?;
        if !slot.borrowed_as_handle { return Err(HandleError::InvalidHandle); }
        slot.readers.insert(self.next_lease);
        let lease = self.next_lease;
        self.next_lease = next;
        Ok(ReadView { key: handle.key, lease, active: true })
    }

    pub fn release_view(&mut self, view: &mut ReadView) -> Result<(), HandleError> {
        if !view.active { return Err(HandleError::InvalidView); }
        self.verify(view.key)?;
        let slot = self.slots.get_mut(&view.key.allocation).ok_or(HandleError::InvalidView)?;
        if !slot.borrowed_as_handle || !slot.readers.remove(&view.lease) {
            return Err(HandleError::InvalidView);
        }
        view.active = false;
        Ok(())
    }

    pub fn unref(&mut self, handle: &mut Handle) -> Result<Owned, HandleError> {
        if !handle.active { return Err(HandleError::InvalidHandle); }
        self.verify(handle.key)?;
        let slot = self.slots.get_mut(&handle.key.allocation).ok_or(HandleError::InvalidHandle)?;
        if !slot.borrowed_as_handle { return Err(HandleError::InvalidHandle); }
        if !slot.readers.is_empty() { return Err(HandleError::LiveViews); }
        slot.borrowed_as_handle = false;
        handle.active = false;
        Ok(Owned { key: handle.key, active: true })
    }

    /// Revoke the entire incarnation; no prior generation may be used again.
    pub fn advance_generation(&mut self, next: u64) -> Result<(), HandleError> {
        if next <= self.generation { return Err(HandleError::StaleGeneration); }
        self.generation = next;
        self.slots.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bang_operators_and_legacy_aliases_map_identically() {
        for (a, b, op) in [("ref!", "rt ref", HandleOp::Ref),
            ("deref!", "rt deref", HandleOp::Deref),
            ("unref!", "rt unref", HandleOp::Unref)] {
            assert_eq!(handle_alias(a), Some(op));
            assert_eq!(handle_alias(b), Some(op));
        }
        assert_eq!(handle_alias("borrow!"), None);
        assert_eq!(handle_alias("rt raw_deref"), None);
    }

    #[test]
    fn affine_lifecycle_and_view_retirement() {
        let mut model = CheckedHandleModel::new(7, 1).unwrap();
        let mut owner = model.mint_owner().unwrap();
        let mut handle = model.ref_owned(&mut owner).unwrap();
        assert_eq!(model.ref_owned(&mut owner).unwrap_err(), HandleError::InvalidHandle);
        let mut view1 = model.deref(&handle).unwrap();
        let mut view2 = model.deref(&handle).unwrap();
        assert_eq!(model.unref(&mut handle).unwrap_err(), HandleError::LiveViews);
        model.release_view(&mut view1).unwrap();
        assert_eq!(model.release_view(&mut view1).unwrap_err(), HandleError::InvalidView);
        assert_eq!(model.unref(&mut handle).unwrap_err(), HandleError::LiveViews);
        model.release_view(&mut view2).unwrap();
        let mut recovered = model.unref(&mut handle).unwrap();
        assert_eq!(model.deref(&handle).unwrap_err(), HandleError::InvalidHandle);
        assert_eq!(model.unref(&mut handle).unwrap_err(), HandleError::InvalidHandle);
        let _next = model.ref_owned(&mut recovered).unwrap();
    }

    #[test]
    fn wrong_actor_model_and_generation_fail_closed() {
        let mut first = CheckedHandleModel::new(7, 1).unwrap();
        let mut second = CheckedHandleModel::new(8, 1).unwrap();
        let mut owner = first.mint_owner().unwrap();
        let handle = first.ref_owned(&mut owner).unwrap();
        assert_eq!(second.deref(&handle).unwrap_err(), HandleError::ForeignModel);
        first.advance_generation(2).unwrap();
        assert_eq!(first.deref(&handle).unwrap_err(), HandleError::StaleGeneration);
        assert_eq!(first.advance_generation(2).unwrap_err(), HandleError::StaleGeneration);
        assert_eq!(CheckedHandleModel::new(0, 1).unwrap_err(), HandleError::InvalidIdentity);
    }
}
