//! Bounded, actor-owned byte frame arena (trusted Rust reference).
//!
//! Handles contain 32-bit arena-relative offsets, not machine pointers.
//! This is physical storage with deterministic zeroization, but it is NOT an
//! Atto guest call stack, a native stack guard, a borrow-checker proof, or
//! permission to resume a continuation on another carrier. Compiler and
//! runtime adapters must independently authenticate actor/generation/frame.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_STACK_BYTES: u32 = 64 * 1024;
pub const MAX_STACK_FRAMES: usize = 64;
const MAX_ALIGNMENT: u32 = 4096;
// Unique across every arena constructed within this process. A durable
// supervisor epoch is still required across runtime restarts.
static NEXT_ARENA_INSTANCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackError {
    InvalidConfiguration,
    InvalidFrame,
    Exhausted,
    Faulted,
    Retired,
    ForeignActor,
    StaleGeneration,
    UnknownFrame,
    NotTopFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef32 {
    instance: u64,
    actor: u64,
    generation: u64,
    serial: u64,
    offset: u32,
    len: u32,
}

impl FrameRef32 {
    /// Offset in this actor's stack arena, not an absolute address.
    pub fn offset(self) -> u32 {
        self.offset
    }

    pub fn len(self) -> u32 {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

#[derive(Debug)]
struct LiveFrame {
    handle: FrameRef32,
    previous_used: u32,
}

/// A single actor's bounded frame storage. A new actor incarnation needs
/// a fresh arena; the old one is permanently retired on STOP/hot-upgrade.
///
/// Every read/write requires exclusive trusted-host access to this arena.
/// Returning an owned result from the closure cannot export a safe Rust
/// reference to the frame. FFI and guest codegen require separate proofs.
pub struct ActorStackArena {
    instance: u64,
    actor: u64,
    generation: u64,
    bytes: Box<[u8]>,
    used: u32,
    frame_limit: usize,
    next_serial: u64,
    frames: Vec<LiveFrame>,
    faulted: bool,
    retired: bool,
}

impl std::fmt::Debug for ActorStackArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorStackArena")
            .field("actor", &self.actor)
            .field("generation", &self.generation)
            .field("capacity_bytes", &self.bytes.len())
            .field("active_frames", &self.frames.len())
            .field("faulted", &self.faulted)
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

impl ActorStackArena {
    pub fn new(actor: u64, generation: u64) -> Result<Self, StackError> {
        Self::with_limits(actor, generation, MAX_STACK_BYTES, MAX_STACK_FRAMES)
    }

    /// Reserve byte zero as an invalid/null guest offset.
    /// Configurable smaller budgets enable exact boundary and mutation tests.
    pub fn with_limits(
        actor: u64,
        generation: u64,
        byte_limit: u32,
        frame_limit: usize,
    ) -> Result<Self, StackError> {
        if actor == 0
            || generation == 0
            || !(2..=MAX_STACK_BYTES).contains(&byte_limit)
            || !(1..=MAX_STACK_FRAMES).contains(&frame_limit)
        {
            return Err(StackError::InvalidConfiguration);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_limit as usize)
            .map_err(|_| StackError::Exhausted)?;
        bytes.resize(byte_limit as usize, 0);
        // No dynamic metadata allocations when an actor pushes a live frame.
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(frame_limit)
            .map_err(|_| StackError::Exhausted)?;
        let instance = NEXT_ARENA_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| StackError::Exhausted)?;
        Ok(Self {
            instance,
            actor,
            generation,
            bytes: bytes.into_boxed_slice(),
            used: 1,
            frame_limit,
            next_serial: 1,
            frames,
            faulted: false,
            retired: false,
        })
    }

    fn check_live(&self) -> Result<(), StackError> {
        if self.retired {
            Err(StackError::Retired)
        } else if self.faulted {
            Err(StackError::Faulted)
        } else {
            Ok(())
        }
    }

    /// Allocate one frame. A budget or ID exhaustion permanently faults only
    /// this actor arena; the supervisor must retire and replace it.
    pub fn push(&mut self, len: u32, alignment: u32) -> Result<FrameRef32, StackError> {
        self.check_live()?;
        if len == 0
            || alignment == 0
            || !alignment.is_power_of_two()
            || alignment > MAX_ALIGNMENT
        {
            return Err(StackError::InvalidFrame);
        }
        if self.frames.len() >= self.frame_limit {
            self.faulted = true;
            return Err(StackError::Exhausted);
        }
        let Some(padded) = self.used.checked_add(alignment - 1) else {
            self.faulted = true;
            return Err(StackError::Exhausted);
        };
        let start = padded & !(alignment - 1);
        let Some(end) = start.checked_add(len) else {
            self.faulted = true;
            return Err(StackError::Exhausted);
        };
        if end > self.bytes.len() as u32 {
            self.faulted = true;
            return Err(StackError::Exhausted);
        }
        let Some(next_serial) = self.next_serial.checked_add(1) else {
            self.faulted = true;
            return Err(StackError::Exhausted);
        };
        let handle = FrameRef32 {
            instance: self.instance,
            actor: self.actor,
            generation: self.generation,
            serial: self.next_serial,
            offset: start,
            len,
        };
        self.next_serial = next_serial;
        self.frames.push(LiveFrame {
            handle,
            previous_used: self.used,
        });
        self.used = end;
        Ok(handle)
    }

    fn authenticated_range(&self, handle: FrameRef32) -> Result<Range<usize>, StackError> {
        self.check_live()?;
        if handle.instance != self.instance {
            return Err(StackError::UnknownFrame);
        }
        if handle.actor != self.actor {
            return Err(StackError::ForeignActor);
        }
        if handle.generation != self.generation {
            return Err(StackError::StaleGeneration);
        }
        if !self.frames.iter().any(|frame| frame.handle == handle) {
            return Err(StackError::UnknownFrame);
        }
        let end = handle
            .offset
            .checked_add(handle.len)
            .ok_or(StackError::UnknownFrame)?;
        if handle.offset == 0 || end > self.used {
            return Err(StackError::UnknownFrame);
        }
        Ok(handle.offset as usize..end as usize)
    }

    /// Pure scoped read. The trusted caller has to prove physical actor
    /// admission before entering this reference interface.
    pub fn with_read<R>(
        &mut self,
        handle: FrameRef32,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, StackError> {
        let range = self.authenticated_range(handle)?;
        Ok(operation(&self.bytes[range]))
    }

    /// Exclusive scoped write: does not publish raw frame memory.
    pub fn with_write<R>(
        &mut self,
        handle: FrameRef32,
        operation: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, StackError> {
        let range = self.authenticated_range(handle)?;
        Ok(operation(&mut self.bytes[range]))
    }

    /// LIFO destruction, including padding bytes; retired handle IDs never
    /// become valid again even if a future frame reuses the same u32 offset.
    pub fn pop(&mut self, handle: FrameRef32) -> Result<(), StackError> {
        self.authenticated_range(handle)?;
        if self.frames.last().map(|frame| frame.handle) != Some(handle) {
            return Err(StackError::NotTopFrame);
        }
        let top = self.frames.pop().ok_or(StackError::UnknownFrame)?;
        self.bytes[top.previous_used as usize..self.used as usize].fill(0);
        self.used = top.previous_used;
        Ok(())
    }

    /// STOP/hot-upgrade: no new frame access after retirement. A new actor
    /// incarnation must construct a separate arena after proving the old
    /// continuation execution is quiescent.
    pub fn retire(&mut self, next_generation: u64) -> Result<(), StackError> {
        if self.retired {
            return Err(StackError::Retired);
        }
        if next_generation <= self.generation {
            return Err(StackError::StaleGeneration);
        }
        self.bytes.fill(0);
        self.frames.clear();
        self.used = 1;
        self.generation = next_generation;
        self.retired = true;
        Ok(())
    }

    pub fn is_faulted(&self) -> bool {
        self.faulted
    }

    pub fn is_retired(&self) -> bool {
        self.retired
    }

    pub fn active_frames(&self) -> usize {
        self.frames.len()
    }

    pub fn capacity_bytes(&self) -> u32 {
        self.bytes.len() as u32
    }
}