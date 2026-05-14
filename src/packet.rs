//! Packet buffer, address, protocol, and flag contracts.
//!
//! Packet buffers are borrowed, bounded, and classified. Validation rejects
//! malformed addresses, reserved flag bits, oversized payloads, invalid trace
//! metadata, and secret payloads that lack encryption metadata.

use crate::{
    validate_network_label, validate_redaction, DataClass, NetworkError, NetworkResult,
    RedactionState, TraceContext,
};

/// Packet schema version owned by this crate.
pub const PACKET_SCHEMA_VERSION: &str = "alani.network.packet.v1";

/// Invalid packet identifier.
pub const INVALID_PACKET_ID: u64 = 0;

/// Maximum packet payload length for host-mode skeleton buffers.
pub const MAX_PACKET_PAYLOAD_LEN: usize = 4096;

/// Maximum address or packet metadata label length.
pub const MAX_PACKET_LABEL_LEN: usize = 128;

/// Maximum packet classification tags reserved for future schema expansion.
pub const MAX_PACKET_TAGS: usize = 8;

/// Maximum frame size including skeleton transport metadata.
pub const MAX_FRAME_LEN: usize = MAX_PACKET_PAYLOAD_LEN + 128;

/// Maximum scheduling priority accepted by packet metadata.
pub const MAX_PACKET_PRIORITY: u8 = 7;

/// Packet should be delivered to all local peers.
pub const PACKET_FLAG_BROADCAST: u32 = 1 << 0;
/// Packet is part of a multicast-style delivery path.
pub const PACKET_FLAG_MULTICAST: u32 = 1 << 1;
/// Packet belongs to a reliable transport.
pub const PACKET_FLAG_RELIABLE: u32 = 1 << 2;
/// Packet is one fragment of a larger frame.
pub const PACKET_FLAG_FRAGMENTED: u32 = 1 << 3;
/// Packet carries control-plane metadata.
pub const PACKET_FLAG_CONTROL: u32 = 1 << 4;
/// Packet send or receive must emit audit evidence.
pub const PACKET_FLAG_AUDIT_REQUIRED: u32 = 1 << 5;
/// Packet payload is encrypted by the caller or future transport adapter.
pub const PACKET_FLAG_ENCRYPTED: u32 = 1 << 6;
/// Packet metadata includes checksum coverage.
pub const PACKET_FLAG_CHECKSUMMED: u32 = 1 << 7;

/// Packet flags known by this crate version.
pub const PACKET_KNOWN_FLAGS: u32 = PACKET_FLAG_BROADCAST
    | PACKET_FLAG_MULTICAST
    | PACKET_FLAG_RELIABLE
    | PACKET_FLAG_FRAGMENTED
    | PACKET_FLAG_CONTROL
    | PACKET_FLAG_AUDIT_REQUIRED
    | PACKET_FLAG_ENCRYPTED
    | PACKET_FLAG_CHECKSUMMED;

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> PacketDescriptor<'a> {
    /// Creates a packet descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Stable packet identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketId(pub u64);

impl PacketId {
    /// Invalid packet identifier.
    pub const INVALID: Self = Self(INVALID_PACKET_ID);

    /// Creates a packet identifier.
    pub const fn new(value: u64) -> NetworkResult<Self> {
        if value == INVALID_PACKET_ID {
            Err(NetworkError::InvalidPacket)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the raw identifier value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Validates the identifier.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.0 == INVALID_PACKET_ID {
            Err(NetworkError::InvalidPacket)
        } else {
            Ok(())
        }
    }
}

/// Address family for simulated network endpoints.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressKind {
    /// Loopback endpoint.
    Loopback = 1,
    /// IPv4-style endpoint.
    Ipv4 = 2,
    /// IPv6-style endpoint.
    Ipv6 = 3,
    /// Link-local or simulated device-local endpoint.
    LinkLocal = 4,
    /// Named service endpoint.
    Service = 5,
}

impl AddressKind {
    /// Stable address kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::LinkLocal => "link_local",
            Self::Service => "service",
        }
    }

    /// Returns `true` for loopback endpoints.
    pub const fn is_loopback(self) -> bool {
        matches!(self, Self::Loopback)
    }

    /// Returns `true` when a nonzero port is required.
    pub const fn requires_port(self) -> bool {
        matches!(
            self,
            Self::Loopback | Self::Ipv4 | Self::Ipv6 | Self::Service
        )
    }
}

/// Borrowed network address metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkAddress<'a> {
    /// Address family.
    pub kind: AddressKind,
    /// Address or service label.
    pub label: &'a str,
    /// Transport port when applicable.
    pub port: u16,
}

impl<'a> NetworkAddress<'a> {
    /// Creates a network address.
    pub const fn new(kind: AddressKind, label: &'a str, port: u16) -> Self {
        Self { kind, label, port }
    }

    /// Creates a loopback address.
    pub const fn loopback(port: u16) -> Self {
        Self {
            kind: AddressKind::Loopback,
            label: "loopback",
            port,
        }
    }

    /// Returns `true` when the address is loopback.
    pub const fn is_loopback(self) -> bool {
        self.kind.is_loopback()
    }

    /// Validates address metadata.
    pub fn validate(self) -> NetworkResult<()> {
        validate_network_label(self.label, MAX_PACKET_LABEL_LEN)?;
        if self.kind.requires_port() && self.port == 0 {
            return Err(NetworkError::InvalidAddress);
        }
        Ok(())
    }
}

/// Packet protocol carried by a packet buffer.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketProtocol {
    /// Loopback transport.
    Loopback = 1,
    /// IPv4 packet.
    Ipv4 = 2,
    /// IPv6 packet.
    Ipv6 = 3,
    /// UDP datagram.
    Udp = 4,
    /// TCP segment.
    Tcp = 5,
    /// ICMP control packet.
    Icmp = 6,
    /// Alani control-plane packet.
    Control = 7,
}

impl PacketProtocol {
    /// Stable protocol label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Icmp => "icmp",
            Self::Control => "control",
        }
    }

    /// Returns `true` when this protocol is restricted to loopback addresses.
    pub const fn is_loopback_only(self) -> bool {
        matches!(self, Self::Loopback)
    }

    /// Returns `true` when this protocol carries control-plane metadata.
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Control | Self::Icmp)
    }
}

/// Packet flag bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketFlags(pub u32);

impl PacketFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Broadcast delivery.
    pub const BROADCAST: Self = Self(PACKET_FLAG_BROADCAST);
    /// Multicast delivery.
    pub const MULTICAST: Self = Self(PACKET_FLAG_MULTICAST);
    /// Reliable transport.
    pub const RELIABLE: Self = Self(PACKET_FLAG_RELIABLE);
    /// Fragmented frame.
    pub const FRAGMENTED: Self = Self(PACKET_FLAG_FRAGMENTED);
    /// Control-plane packet.
    pub const CONTROL: Self = Self(PACKET_FLAG_CONTROL);
    /// Audit evidence required.
    pub const AUDIT_REQUIRED: Self = Self(PACKET_FLAG_AUDIT_REQUIRED);
    /// Encrypted payload.
    pub const ENCRYPTED: Self = Self(PACKET_FLAG_ENCRYPTED);
    /// Checksum coverage present.
    pub const CHECKSUMMED: Self = Self(PACKET_FLAG_CHECKSUMMED);

    /// Creates packet flags from raw bits.
    pub const fn from_bits(bits: u32) -> NetworkResult<Self> {
        if bits & !PACKET_KNOWN_FLAGS != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if all requested flags are set.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Combines two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates reserved bits.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.0 & !PACKET_KNOWN_FLAGS != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Borrowed packet buffer envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketBuffer<'a> {
    /// Stable packet identifier.
    pub id: PacketId,
    /// Source endpoint.
    pub source: NetworkAddress<'a>,
    /// Destination endpoint.
    pub destination: NetworkAddress<'a>,
    /// Packet protocol.
    pub protocol: PacketProtocol,
    /// Borrowed payload bytes.
    pub payload: &'a [u8],
    /// Logical payload length.
    pub payload_len: usize,
    /// Capacity promised by the owner of the payload backing storage.
    pub capacity: usize,
    /// Packet flags.
    pub flags: PacketFlags,
    /// Scheduling priority in the range `0..=MAX_PACKET_PRIORITY`.
    pub priority: u8,
    /// Transport sequence number when available.
    pub sequence: u64,
    /// Payload data classification.
    pub data_class: DataClass,
    /// Redaction state for diagnostic exports.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> PacketBuffer<'a> {
    /// Creates a packet buffer over borrowed payload bytes.
    pub const fn new(
        id: PacketId,
        source: NetworkAddress<'a>,
        destination: NetworkAddress<'a>,
        protocol: PacketProtocol,
        payload: &'a [u8],
    ) -> Self {
        Self {
            id,
            source,
            destination,
            protocol,
            payload,
            payload_len: payload.len(),
            capacity: payload.len(),
            flags: PacketFlags::EMPTY,
            priority: 0,
            sequence: 0,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets the payload capacity metadata.
    pub const fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Sets packet flags.
    pub const fn with_flags(mut self, flags: PacketFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets packet priority.
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the transport sequence number.
    pub const fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self
    }

    /// Sets data classification and redaction state.
    pub const fn with_classification(
        mut self,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns `true` when this packet requires durable audit evidence.
    pub const fn requires_audit(self) -> bool {
        self.flags.contains(PacketFlags::AUDIT_REQUIRED)
            || matches!(self.data_class, DataClass::Sensitive | DataClass::Secret)
    }

    /// Validates packet metadata.
    pub fn validate(self) -> NetworkResult<()> {
        self.id.validate()?;
        self.source.validate()?;
        self.destination.validate()?;
        self.flags.validate()?;
        if self.payload_len != self.payload.len() || self.payload_len > self.capacity {
            return Err(NetworkError::InvalidPacket);
        }
        if self.payload_len > MAX_PACKET_PAYLOAD_LEN || self.capacity > MAX_PACKET_PAYLOAD_LEN {
            return Err(NetworkError::PayloadTooLarge);
        }
        if self.priority > MAX_PACKET_PRIORITY {
            return Err(NetworkError::InvalidPacket);
        }
        if self.protocol.is_loopback_only()
            && (!self.source.is_loopback() || !self.destination.is_loopback())
        {
            return Err(NetworkError::LoopbackOnly);
        }
        if self.protocol.is_control() && !self.flags.contains(PacketFlags::CONTROL) {
            return Err(NetworkError::InvalidPacket);
        }
        if matches!(self.data_class, DataClass::Secret)
            && !self.flags.contains(PacketFlags::ENCRYPTED)
        {
            return Err(NetworkError::EncryptionRequired);
        }
        validate_redaction(self.data_class, self.redaction)?;
        self.trace.validate()
    }
}

/// Packet queue counters for host-mode tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketQueueStats {
    /// Packets accepted by the queue.
    pub packets_queued: u64,
    /// Packets removed from the queue.
    pub packets_dequeued: u64,
    /// Payload bytes accepted by the queue.
    pub bytes_queued: u64,
    /// Payload bytes removed from the queue.
    pub bytes_dequeued: u64,
    /// Packets dropped because the queue was full.
    pub drops: u64,
}

/// Fixed-capacity packet FIFO used by transport adapters and tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketQueue<'a, const N: usize> {
    slots: [Option<PacketBuffer<'a>>; N],
    head: usize,
    len: usize,
    stats: PacketQueueStats,
}

impl<'a, const N: usize> PacketQueue<'a, N> {
    /// Creates an empty packet queue.
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            head: 0,
            len: 0,
            stats: PacketQueueStats {
                packets_queued: 0,
                packets_dequeued: 0,
                bytes_queued: 0,
                bytes_dequeued: 0,
                drops: 0,
            },
        }
    }

    /// Returns active packet count.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no packets are queued.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns queue capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns queue statistics.
    pub const fn stats(&self) -> PacketQueueStats {
        self.stats
    }

    /// Returns all backing slots.
    pub const fn slots(&self) -> &[Option<PacketBuffer<'a>>; N] {
        &self.slots
    }

    /// Returns the next packet without removing it.
    pub fn peek(&self) -> Option<&PacketBuffer<'a>> {
        if self.len == 0 || N == 0 {
            None
        } else {
            self.slots[self.head].as_ref()
        }
    }

    /// Enqueues a packet after validation.
    pub fn push(&mut self, packet: PacketBuffer<'a>) -> NetworkResult<()> {
        packet.validate()?;
        if self.len == N || N == 0 {
            self.stats.drops = self.stats.drops.saturating_add(1);
            return Err(NetworkError::CapacityExceeded);
        }
        let tail = (self.head + self.len) % N;
        self.slots[tail] = Some(packet);
        self.len += 1;
        self.stats.packets_queued = self.stats.packets_queued.saturating_add(1);
        self.stats.bytes_queued = self
            .stats
            .bytes_queued
            .saturating_add(packet.payload_len as u64);
        Ok(())
    }

    /// Removes the next packet.
    pub fn pop(&mut self) -> NetworkResult<PacketBuffer<'a>> {
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
        self.stats.packets_dequeued = self.stats.packets_dequeued.saturating_add(1);
        self.stats.bytes_dequeued = self
            .stats
            .bytes_dequeued
            .saturating_add(packet.payload_len as u64);
        Ok(packet)
    }
}

impl<'a, const N: usize> Default for PacketQueue<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
