//! Protocol adapter descriptors and fixed-capacity registry contracts.
//!
//! Protocol adapters declare transport semantics, maximum payload size,
//! required capabilities, and redaction behavior. The registry is deliberately
//! fixed-capacity so host-mode tests and future kernel callers can use it
//! without allocation.

use crate::packet::{PacketBuffer, PacketFlags, PacketProtocol, MAX_PACKET_PAYLOAD_LEN};
use crate::{
    validate_network_label, validate_redaction, DataClass, NetworkError, NetworkResult,
    RedactionState,
};

/// Protocol schema version owned by this crate.
pub const PROTOCOL_SCHEMA_VERSION: &str = "alani.network.protocol.v1";

/// Maximum protocol adapter name length.
pub const MAX_PROTOCOL_NAME_LEN: usize = 96;

/// Maximum protocol adapter version label length.
pub const MAX_PROTOCOL_VERSION_LEN: usize = 64;

/// Capability bit for datagram transports.
pub const PROTOCOL_CAP_DATAGRAM: u64 = 1 << 0;
/// Capability bit for stream transports.
pub const PROTOCOL_CAP_STREAM: u64 = 1 << 1;
/// Capability bit for reliable delivery.
pub const PROTOCOL_CAP_RELIABLE: u64 = 1 << 2;
/// Capability bit for ordered delivery.
pub const PROTOCOL_CAP_ORDERED: u64 = 1 << 3;
/// Capability bit for checksum coverage.
pub const PROTOCOL_CAP_CHECKSUM: u64 = 1 << 4;
/// Capability bit restricting the adapter to loopback paths.
pub const PROTOCOL_CAP_LOOPBACK_ONLY: u64 = 1 << 5;
/// Capability bit requiring encryption metadata for protected payloads.
pub const PROTOCOL_CAP_ENCRYPTION_REQUIRED: u64 = 1 << 6;
/// Capability bit for control-plane transport.
pub const PROTOCOL_CAP_CONTROL: u64 = 1 << 7;
/// Capability bit for raw packet transport.
pub const PROTOCOL_CAP_RAW: u64 = 1 << 8;

/// Protocol capabilities known by this crate version.
pub const KNOWN_PROTOCOL_CAPABILITIES: u64 = PROTOCOL_CAP_DATAGRAM
    | PROTOCOL_CAP_STREAM
    | PROTOCOL_CAP_RELIABLE
    | PROTOCOL_CAP_ORDERED
    | PROTOCOL_CAP_CHECKSUM
    | PROTOCOL_CAP_LOOPBACK_ONLY
    | PROTOCOL_CAP_ENCRYPTION_REQUIRED
    | PROTOCOL_CAP_CONTROL
    | PROTOCOL_CAP_RAW;

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> ProtocolDescriptor<'a> {
    /// Creates a protocol descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Transport protocol exposed through sockets and adapters.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    /// Loopback-only datagram transport.
    Loopback = 1,
    /// User Datagram Protocol.
    Udp = 2,
    /// Transmission Control Protocol.
    Tcp = 3,
    /// ICMP control protocol.
    Icmp = 4,
    /// Raw packet protocol.
    Raw = 5,
    /// Alani control-plane protocol.
    Control = 6,
}

impl TransportProtocol {
    /// Stable protocol label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Icmp => "icmp",
            Self::Raw => "raw",
            Self::Control => "control",
        }
    }

    /// Packet protocol used by this transport.
    pub const fn packet_protocol(self) -> PacketProtocol {
        match self {
            Self::Loopback => PacketProtocol::Loopback,
            Self::Udp => PacketProtocol::Udp,
            Self::Tcp => PacketProtocol::Tcp,
            Self::Icmp => PacketProtocol::Icmp,
            Self::Raw => PacketProtocol::Ipv4,
            Self::Control => PacketProtocol::Control,
        }
    }

    /// Returns `true` when this transport accepts the packet protocol.
    pub const fn accepts_packet_protocol(self, protocol: PacketProtocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Loopback, PacketProtocol::Loopback)
                | (Self::Udp, PacketProtocol::Udp)
                | (Self::Tcp, PacketProtocol::Tcp)
                | (Self::Icmp, PacketProtocol::Icmp)
                | (Self::Raw, PacketProtocol::Ipv4)
                | (Self::Raw, PacketProtocol::Ipv6)
                | (Self::Control, PacketProtocol::Control)
        )
    }

    /// Returns `true` when a default port is required for adapter metadata.
    pub const fn requires_port(self) -> bool {
        matches!(self, Self::Loopback | Self::Udp | Self::Tcp | Self::Control)
    }

    /// Conservative default port for skeleton adapters.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Loopback => 1,
            Self::Udp => 9,
            Self::Tcp => 9,
            Self::Icmp | Self::Raw => 0,
            Self::Control => 1,
        }
    }

    /// Default capabilities implied by the transport.
    pub const fn default_capabilities(self) -> ProtocolCapabilities {
        match self {
            Self::Loopback => ProtocolCapabilities(
                PROTOCOL_CAP_DATAGRAM | PROTOCOL_CAP_LOOPBACK_ONLY | PROTOCOL_CAP_CHECKSUM,
            ),
            Self::Udp => ProtocolCapabilities(PROTOCOL_CAP_DATAGRAM | PROTOCOL_CAP_CHECKSUM),
            Self::Tcp => ProtocolCapabilities(
                PROTOCOL_CAP_STREAM
                    | PROTOCOL_CAP_RELIABLE
                    | PROTOCOL_CAP_ORDERED
                    | PROTOCOL_CAP_CHECKSUM,
            ),
            Self::Icmp => ProtocolCapabilities(PROTOCOL_CAP_DATAGRAM | PROTOCOL_CAP_CONTROL),
            Self::Raw => ProtocolCapabilities(PROTOCOL_CAP_DATAGRAM | PROTOCOL_CAP_RAW),
            Self::Control => ProtocolCapabilities(
                PROTOCOL_CAP_DATAGRAM | PROTOCOL_CAP_CONTROL | PROTOCOL_CAP_LOOPBACK_ONLY,
            ),
        }
    }
}

/// Protocol adapter lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolState {
    /// Adapter is declared but not selectable by default.
    Draft = 1,
    /// Adapter is selectable.
    Enabled = 2,
    /// Adapter is disabled by policy or configuration.
    Disabled = 3,
    /// Adapter remains for compatibility but should not be selected.
    Deprecated = 4,
}

impl ProtocolState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Deprecated => "deprecated",
        }
    }

    /// Returns `true` when callers may select the adapter.
    pub const fn allows_selection(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Protocol capability bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProtocolCapabilities(pub u64);

impl ProtocolCapabilities {
    /// No capabilities.
    pub const EMPTY: Self = Self(0);
    /// Datagram transport capability.
    pub const DATAGRAM: Self = Self(PROTOCOL_CAP_DATAGRAM);
    /// Stream transport capability.
    pub const STREAM: Self = Self(PROTOCOL_CAP_STREAM);
    /// Reliable delivery capability.
    pub const RELIABLE: Self = Self(PROTOCOL_CAP_RELIABLE);
    /// Ordered delivery capability.
    pub const ORDERED: Self = Self(PROTOCOL_CAP_ORDERED);
    /// Checksum capability.
    pub const CHECKSUM: Self = Self(PROTOCOL_CAP_CHECKSUM);
    /// Loopback-only capability.
    pub const LOOPBACK_ONLY: Self = Self(PROTOCOL_CAP_LOOPBACK_ONLY);
    /// Encryption-required capability.
    pub const ENCRYPTION_REQUIRED: Self = Self(PROTOCOL_CAP_ENCRYPTION_REQUIRED);
    /// Control-plane capability.
    pub const CONTROL: Self = Self(PROTOCOL_CAP_CONTROL);
    /// Raw packet capability.
    pub const RAW: Self = Self(PROTOCOL_CAP_RAW);

    /// Creates capabilities from raw bits after rejecting unknown bits.
    pub const fn from_bits(bits: u64) -> NetworkResult<Self> {
        if bits & !KNOWN_PROTOCOL_CAPABILITIES != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw capability bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all requested capabilities are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Combines two capability sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates reserved capability bits.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.0 & !KNOWN_PROTOCOL_CAPABILITIES != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Protocol adapter metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolAdapter<'a> {
    /// Adapter name.
    pub name: &'a str,
    /// Adapter version label.
    pub version: &'a str,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Adapter lifecycle state.
    pub state: ProtocolState,
    /// Declared capabilities.
    pub capabilities: ProtocolCapabilities,
    /// Maximum payload accepted by this adapter.
    pub max_payload_len: usize,
    /// Default port when the protocol uses ports.
    pub default_port: u16,
    /// Metadata classification.
    pub data_class: DataClass,
    /// Metadata redaction state.
    pub redaction: RedactionState,
}

impl<'a> ProtocolAdapter<'a> {
    /// Creates protocol adapter metadata.
    pub const fn new(name: &'a str, version: &'a str, protocol: TransportProtocol) -> Self {
        Self {
            name,
            version,
            protocol,
            state: ProtocolState::Draft,
            capabilities: protocol.default_capabilities(),
            max_payload_len: MAX_PACKET_PAYLOAD_LEN,
            default_port: protocol.default_port(),
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets lifecycle state.
    pub const fn with_state(mut self, state: ProtocolState) -> Self {
        self.state = state;
        self
    }

    /// Sets capabilities.
    pub const fn with_capabilities(mut self, capabilities: ProtocolCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets maximum payload length.
    pub const fn with_max_payload_len(mut self, max_payload_len: usize) -> Self {
        self.max_payload_len = max_payload_len;
        self
    }

    /// Sets default port.
    pub const fn with_default_port(mut self, default_port: u16) -> Self {
        self.default_port = default_port;
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

    /// Returns `true` when the adapter can be selected.
    pub const fn is_selectable(self) -> bool {
        self.state.allows_selection()
    }

    /// Validates adapter metadata.
    pub fn validate(self) -> NetworkResult<()> {
        validate_network_label(self.name, MAX_PROTOCOL_NAME_LEN)?;
        validate_network_label(self.version, MAX_PROTOCOL_VERSION_LEN)?;
        self.capabilities.validate()?;
        if self.max_payload_len == 0 || self.max_payload_len > MAX_PACKET_PAYLOAD_LEN {
            return Err(NetworkError::InvalidProtocol);
        }
        if self.protocol.requires_port() && self.default_port == 0 {
            return Err(NetworkError::InvalidProtocol);
        }
        if matches!(
            self.protocol,
            TransportProtocol::Loopback | TransportProtocol::Control
        ) && !self
            .capabilities
            .contains(ProtocolCapabilities::LOOPBACK_ONLY)
        {
            return Err(NetworkError::InvalidProtocol);
        }
        if matches!(self.protocol, TransportProtocol::Raw)
            && !self.capabilities.contains(ProtocolCapabilities::RAW)
        {
            return Err(NetworkError::InvalidProtocol);
        }
        validate_redaction(self.data_class, self.redaction)
    }

    /// Validates whether a packet may be handled by this adapter.
    pub fn validate_packet(self, packet: PacketBuffer<'_>) -> NetworkResult<()> {
        self.validate()?;
        packet.validate()?;
        if !self.protocol.accepts_packet_protocol(packet.protocol) {
            return Err(NetworkError::InvalidProtocol);
        }
        if packet.payload_len > self.max_payload_len {
            return Err(NetworkError::PayloadTooLarge);
        }
        if self
            .capabilities
            .contains(ProtocolCapabilities::LOOPBACK_ONLY)
            && (!packet.source.is_loopback() || !packet.destination.is_loopback())
        {
            return Err(NetworkError::LoopbackOnly);
        }
        if self
            .capabilities
            .contains(ProtocolCapabilities::ENCRYPTION_REQUIRED)
            && !packet.flags.contains(PacketFlags::ENCRYPTED)
        {
            return Err(NetworkError::EncryptionRequired);
        }
        Ok(())
    }
}

/// Fixed-capacity protocol adapter registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolRegistry<'a, const N: usize> {
    adapters: [Option<ProtocolAdapter<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> ProtocolRegistry<'a, N> {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            adapters: [None; N],
            len: 0,
        }
    }

    /// Returns active adapter count.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no adapters are registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns all backing slots.
    pub const fn slots(&self) -> &[Option<ProtocolAdapter<'a>>; N] {
        &self.adapters
    }

    /// Registers a protocol adapter.
    pub fn register(&mut self, adapter: ProtocolAdapter<'a>) -> NetworkResult<()> {
        adapter.validate()?;
        if self
            .adapters
            .iter()
            .flatten()
            .any(|existing| existing.name == adapter.name || existing.protocol == adapter.protocol)
        {
            return Err(NetworkError::DuplicateProtocol);
        }
        let slot = self
            .adapters
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(NetworkError::CapacityExceeded)?;
        *slot = Some(adapter);
        self.len += 1;
        Ok(())
    }

    /// Finds an adapter by name.
    pub fn find(&self, name: &str) -> NetworkResult<ProtocolAdapter<'a>> {
        validate_network_label(name, MAX_PROTOCOL_NAME_LEN)?;
        self.adapters
            .iter()
            .flatten()
            .find(|adapter| adapter.name == name)
            .copied()
            .ok_or(NetworkError::ProtocolNotFound)
    }

    /// Selects an enabled adapter for a transport protocol.
    pub fn select(&self, protocol: TransportProtocol) -> NetworkResult<ProtocolAdapter<'a>> {
        self.adapters
            .iter()
            .flatten()
            .find(|adapter| adapter.protocol == protocol && adapter.is_selectable())
            .copied()
            .ok_or(NetworkError::ProtocolNotFound)
    }

    /// Selects an enabled adapter that can handle the packet.
    pub fn select_for_packet(
        &self,
        packet: PacketBuffer<'_>,
    ) -> NetworkResult<ProtocolAdapter<'a>> {
        packet.validate()?;
        for adapter in self.adapters.iter().flatten() {
            if adapter.is_selectable() && adapter.protocol.accepts_packet_protocol(packet.protocol)
            {
                adapter.validate_packet(packet)?;
                return Ok(*adapter);
            }
        }
        Err(NetworkError::ProtocolNotFound)
    }
}

impl<'a, const N: usize> Default for ProtocolRegistry<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
