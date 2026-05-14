//! Loopback device and queue contracts.
//!
//! The loopback path is a deterministic, fixed-capacity host-mode device
//! boundary. It validates capability rights, packet metadata, loopback-only
//! addressing, and trace/redaction invariants before queueing packets.

use crate::packet::PacketBuffer;
use crate::{
    validate_network_label, NetworkError, NetworkResult, NetworkRights, TraceContext,
    NETWORK_RIGHT_LOOPBACK, NETWORK_RIGHT_RECEIVE, NETWORK_RIGHT_SEND,
};

/// Built-in loopback device label.
pub const LOOPBACK_DEVICE_LABEL: &str = "loopback0";

/// Maximum loopback device label length.
pub const MAX_LOOPBACK_LABEL_LEN: usize = 64;

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> LoopbackDescriptor<'a> {
    /// Creates a loopback descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Loopback device lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackState {
    /// Device is not accepting packets.
    Down = 1,
    /// Device is accepting packets.
    Up = 2,
    /// Device faulted.
    Faulted = 3,
    /// Device is sealed against further mutation.
    Sealed = 4,
}

impl LoopbackState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Up => "up",
            Self::Faulted => "faulted",
            Self::Sealed => "sealed",
        }
    }

    /// Returns `true` when packet I/O is allowed.
    pub const fn allows_io(self) -> bool {
        matches!(self, Self::Up)
    }
}

/// Loopback queue statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LoopbackStats {
    /// Packets accepted by the queue.
    pub packets_sent: u64,
    /// Packets removed from the queue.
    pub packets_received: u64,
    /// Payload bytes accepted by the queue.
    pub bytes_sent: u64,
    /// Payload bytes removed from the queue.
    pub bytes_received: u64,
    /// Packets dropped because the queue was full or unavailable.
    pub drops: u64,
}

/// Fixed-capacity loopback packet queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackQueue<'a, const N: usize> {
    state: LoopbackState,
    slots: [Option<PacketBuffer<'a>>; N],
    head: usize,
    len: usize,
    stats: LoopbackStats,
}

impl<'a, const N: usize> LoopbackQueue<'a, N> {
    /// Creates an empty loopback queue in the `Up` state.
    pub const fn new() -> Self {
        Self {
            state: LoopbackState::Up,
            slots: [None; N],
            head: 0,
            len: 0,
            stats: LoopbackStats {
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                drops: 0,
            },
        }
    }

    /// Creates an empty loopback queue in the `Down` state.
    pub const fn down() -> Self {
        Self {
            state: LoopbackState::Down,
            slots: [None; N],
            head: 0,
            len: 0,
            stats: LoopbackStats {
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                drops: 0,
            },
        }
    }

    /// Returns queue state.
    pub const fn state(&self) -> LoopbackState {
        self.state
    }

    /// Returns active packet count.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns queue capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns queue statistics.
    pub const fn stats(&self) -> LoopbackStats {
        self.stats
    }

    /// Returns all backing slots.
    pub const fn slots(&self) -> &[Option<PacketBuffer<'a>>; N] {
        &self.slots
    }

    /// Brings the queue up.
    pub fn bring_up(&mut self, rights: NetworkRights) -> NetworkResult<()> {
        rights.require(NetworkRights(NETWORK_RIGHT_LOOPBACK))?;
        if matches!(self.state, LoopbackState::Sealed) {
            return Err(NetworkError::Sealed);
        }
        self.state = LoopbackState::Up;
        Ok(())
    }

    /// Seals the queue against further I/O.
    pub fn seal(&mut self, rights: NetworkRights) -> NetworkResult<()> {
        rights.require(NetworkRights(NETWORK_RIGHT_LOOPBACK))?;
        self.state = LoopbackState::Sealed;
        Ok(())
    }

    /// Enqueues a loopback packet.
    pub fn enqueue(
        &mut self,
        rights: NetworkRights,
        packet: PacketBuffer<'a>,
    ) -> NetworkResult<()> {
        rights.require(NetworkRights(NETWORK_RIGHT_SEND | NETWORK_RIGHT_LOOPBACK))?;
        if !self.state.allows_io() {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return match self.state {
                LoopbackState::Sealed => Err(NetworkError::Sealed),
                LoopbackState::Faulted => Err(NetworkError::DeviceUnavailable),
                LoopbackState::Down => Err(NetworkError::DeviceUnavailable),
                LoopbackState::Up => Err(NetworkError::Internal),
            };
        }
        packet.validate()?;
        if !packet.source.is_loopback() || !packet.destination.is_loopback() {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return Err(NetworkError::LoopbackOnly);
        }
        if self.len == N {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return Err(NetworkError::CapacityExceeded);
        }
        if N == 0 {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return Err(NetworkError::CapacityExceeded);
        }
        let tail = (self.head + self.len) % N;
        self.slots[tail] = Some(packet);
        self.len += 1;
        self.stats.packets_sent = self.stats.packets_sent.saturating_add(1);
        self.stats.bytes_sent = self
            .stats
            .bytes_sent
            .saturating_add(packet.payload_len as u64);
        Ok(())
    }

    /// Dequeues one loopback packet.
    pub fn dequeue(&mut self, rights: NetworkRights) -> NetworkResult<PacketBuffer<'a>> {
        rights.require(NetworkRights(
            NETWORK_RIGHT_RECEIVE | NETWORK_RIGHT_LOOPBACK,
        ))?;
        if !self.state.allows_io() {
            return match self.state {
                LoopbackState::Sealed => Err(NetworkError::Sealed),
                LoopbackState::Faulted => Err(NetworkError::DeviceUnavailable),
                LoopbackState::Down => Err(NetworkError::DeviceUnavailable),
                LoopbackState::Up => Err(NetworkError::Internal),
            };
        }
        if self.len == 0 || N == 0 {
            return Err(NetworkError::PacketUnavailable);
        }
        let packet = self.slots[self.head]
            .take()
            .ok_or(NetworkError::PacketUnavailable)?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        self.stats.packets_received = self.stats.packets_received.saturating_add(1);
        self.stats.bytes_received = self
            .stats
            .bytes_received
            .saturating_add(packet.payload_len as u64);
        Ok(packet)
    }
}

impl<'a, const N: usize> Default for LoopbackQueue<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Host-mode loopback device wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackDevice<'a, const N: usize> {
    /// Device label.
    pub label: &'a str,
    /// Packet queue.
    pub queue: LoopbackQueue<'a, N>,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a, const N: usize> LoopbackDevice<'a, N> {
    /// Creates a loopback device.
    pub const fn new(label: &'a str) -> Self {
        Self {
            label,
            queue: LoopbackQueue::new(),
            trace: TraceContext::EMPTY,
        }
    }

    /// Creates the built-in loopback device.
    pub const fn builtin() -> Self {
        Self::new(LOOPBACK_DEVICE_LABEL)
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Validates device metadata.
    pub fn validate(&self) -> NetworkResult<()> {
        validate_network_label(self.label, MAX_LOOPBACK_LABEL_LEN)?;
        self.trace.validate()
    }

    /// Sends a packet through the device queue.
    pub fn send(&mut self, rights: NetworkRights, packet: PacketBuffer<'a>) -> NetworkResult<()> {
        self.validate()?;
        self.queue.enqueue(rights, packet)
    }

    /// Receives a packet from the device queue.
    pub fn receive(&mut self, rights: NetworkRights) -> NetworkResult<PacketBuffer<'a>> {
        self.validate()?;
        self.queue.dequeue(rights)
    }
}
