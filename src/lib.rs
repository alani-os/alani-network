#![cfg_attr(not(feature = "std"), no_std)]

//! Network stack boundary contracts for Alani.
//!
//! `alani-network` is a Post-MVK boundary for loopback devices, packet buffers,
//! sockets, protocol adapters, and future transport services. The crate stays
//! dependency-free and `no_std` compatible while ABI, device, protocol, policy,
//! and observability crates stabilize their public APIs.

pub mod loopback;
pub mod packet;
pub mod protocol;
pub mod socket;

pub use loopback::{
    LoopbackDescriptor, LoopbackDevice, LoopbackQueue, LoopbackState, LoopbackStats,
    LOOPBACK_DEVICE_LABEL,
};
pub use packet::{
    AddressKind, NetworkAddress, PacketBuffer, PacketDescriptor, PacketFlags, PacketId,
    PacketProtocol, PacketQueue, PacketQueueStats, INVALID_PACKET_ID, MAX_FRAME_LEN,
    MAX_PACKET_LABEL_LEN, MAX_PACKET_PAYLOAD_LEN, MAX_PACKET_PRIORITY, MAX_PACKET_TAGS,
    PACKET_FLAG_AUDIT_REQUIRED, PACKET_FLAG_BROADCAST, PACKET_FLAG_CHECKSUMMED,
    PACKET_FLAG_CONTROL, PACKET_FLAG_ENCRYPTED, PACKET_FLAG_FRAGMENTED, PACKET_FLAG_MULTICAST,
    PACKET_FLAG_RELIABLE, PACKET_KNOWN_FLAGS, PACKET_SCHEMA_VERSION,
};
pub use protocol::{
    ProtocolAdapter, ProtocolCapabilities, ProtocolDescriptor, ProtocolRegistry, ProtocolState,
    TransportProtocol, KNOWN_PROTOCOL_CAPABILITIES, MAX_PROTOCOL_NAME_LEN,
    MAX_PROTOCOL_VERSION_LEN, PROTOCOL_CAP_CHECKSUM, PROTOCOL_CAP_CONTROL, PROTOCOL_CAP_DATAGRAM,
    PROTOCOL_CAP_ENCRYPTION_REQUIRED, PROTOCOL_CAP_LOOPBACK_ONLY, PROTOCOL_CAP_ORDERED,
    PROTOCOL_CAP_RAW, PROTOCOL_CAP_RELIABLE, PROTOCOL_CAP_STREAM, PROTOCOL_SCHEMA_VERSION,
};
pub use socket::{
    SocketDescriptor, SocketEndpoint, SocketFlags, SocketHandle, SocketId, SocketOperation,
    SocketOptions, SocketRequest, SocketState, SocketStats, SocketTable, SocketTableDescriptor,
    SocketType, INVALID_SOCKET_ID, MAX_SOCKET_BACKLOG, MAX_SOCKET_BUFFER_LEN, MAX_SOCKET_OWNER_LEN,
    SOCKET_FLAG_AUDIT_REQUIRED, SOCKET_FLAG_ENCRYPTED, SOCKET_FLAG_LISTEN,
    SOCKET_FLAG_LOOPBACK_ONLY, SOCKET_FLAG_NONBLOCK, SOCKET_FLAG_PRIVILEGED, SOCKET_KNOWN_FLAGS,
    SOCKET_SCHEMA_VERSION,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-network";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["packet", "socket", "loopback", "protocol"];

/// Feature bit for packet buffers and address descriptors.
pub const NETWORK_FEATURE_PACKET_BUFFERS: u64 = 1 << 0;
/// Feature bit for socket handles and operation envelopes.
pub const NETWORK_FEATURE_SOCKETS: u64 = 1 << 1;
/// Feature bit for loopback device queues.
pub const NETWORK_FEATURE_LOOPBACK: u64 = 1 << 2;
/// Feature bit for protocol adapters and registries.
pub const NETWORK_FEATURE_PROTOCOL_ADAPTERS: u64 = 1 << 3;
/// Feature bit for capability-aware request validation.
pub const NETWORK_FEATURE_POLICY_GATES: u64 = 1 << 4;
/// Feature bit for trace-context propagation.
pub const NETWORK_FEATURE_TRACE_CONTEXT: u64 = 1 << 5;
/// Feature bit for data classification and redaction validation.
pub const NETWORK_FEATURE_REDACTION: u64 = 1 << 6;
/// Feature bit for generic fixed-capacity packet queues.
pub const NETWORK_FEATURE_PACKET_QUEUES: u64 = 1 << 7;
/// Feature bit for socket table registration and endpoint conflict checks.
pub const NETWORK_FEATURE_SOCKET_TABLE: u64 = 1 << 8;

/// All network feature bits known by this crate version.
pub const NETWORK_KNOWN_FEATURES: u64 = NETWORK_FEATURE_PACKET_BUFFERS
    | NETWORK_FEATURE_SOCKETS
    | NETWORK_FEATURE_LOOPBACK
    | NETWORK_FEATURE_PROTOCOL_ADAPTERS
    | NETWORK_FEATURE_POLICY_GATES
    | NETWORK_FEATURE_TRACE_CONTEXT
    | NETWORK_FEATURE_REDACTION
    | NETWORK_FEATURE_PACKET_QUEUES
    | NETWORK_FEATURE_SOCKET_TABLE;

/// Caller may inspect network metadata.
pub const NETWORK_RIGHT_READ: u64 = 1 << 0;
/// Caller may send packets.
pub const NETWORK_RIGHT_SEND: u64 = 1 << 1;
/// Caller may receive packets.
pub const NETWORK_RIGHT_RECEIVE: u64 = 1 << 2;
/// Caller may bind local endpoints.
pub const NETWORK_RIGHT_BIND: u64 = 1 << 3;
/// Caller may listen for inbound connections.
pub const NETWORK_RIGHT_LISTEN: u64 = 1 << 4;
/// Caller may connect to a peer endpoint.
pub const NETWORK_RIGHT_CONNECT: u64 = 1 << 5;
/// Caller may configure sockets or protocol adapters.
pub const NETWORK_RIGHT_CONFIGURE: u64 = 1 << 6;
/// Caller may build raw packet or simulated link-layer envelopes.
pub const NETWORK_RIGHT_RAW_PACKET: u64 = 1 << 7;
/// Caller may use loopback-only device paths.
pub const NETWORK_RIGHT_LOOPBACK: u64 = 1 << 8;
/// Caller may emit or preserve durable audit evidence.
pub const NETWORK_RIGHT_AUDIT: u64 = 1 << 9;
/// Caller has administrative network authority.
pub const NETWORK_RIGHT_ADMIN: u64 = 1 << 10;

/// All network rights known by this crate version.
pub const NETWORK_KNOWN_RIGHTS: u64 = NETWORK_RIGHT_READ
    | NETWORK_RIGHT_SEND
    | NETWORK_RIGHT_RECEIVE
    | NETWORK_RIGHT_BIND
    | NETWORK_RIGHT_LISTEN
    | NETWORK_RIGHT_CONNECT
    | NETWORK_RIGHT_CONFIGURE
    | NETWORK_RIGHT_RAW_PACKET
    | NETWORK_RIGHT_LOOPBACK
    | NETWORK_RIGHT_AUDIT
    | NETWORK_RIGHT_ADMIN;

/// Trace flag indicating the event was sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace flag indicating debug metadata may be attached by a trusted sink.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Trace flag indicating the network operation crossed a transport boundary.
pub const TRACE_FLAG_REMOTE: u32 = 1 << 2;
/// Trace flag indicating audit evidence must be preserved.
pub const TRACE_FLAG_AUDIT_REQUIRED: u32 = 1 << 3;
/// Trace flags known by this crate version.
pub const TRACE_KNOWN_FLAGS: u32 =
    TRACE_FLAG_SAMPLED | TRACE_FLAG_DEBUG | TRACE_FLAG_REMOTE | TRACE_FLAG_AUDIT_REQUIRED;

/// Result alias for network validation and host-mode operations.
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Error taxonomy for packets, sockets, protocol adapters, and loopback paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    /// A required field was empty or omitted.
    MissingField,
    /// A bounded field exceeded its documented maximum length.
    FieldTooLong,
    /// A label contained a disallowed character.
    InvalidLabel,
    /// Unknown feature, capability, flag, or rights bits were supplied.
    ReservedBits,
    /// Network address metadata failed validation.
    InvalidAddress,
    /// Packet identifier, payload, or metadata failed validation.
    InvalidPacket,
    /// Packet payload exceeded the documented buffer bound.
    PayloadTooLarge,
    /// Protocol adapter metadata failed validation.
    InvalidProtocol,
    /// Protocol adapter already exists in a registry.
    DuplicateProtocol,
    /// Requested protocol adapter was not found.
    ProtocolNotFound,
    /// Socket identifier, state, endpoint, or option metadata failed validation.
    InvalidSocket,
    /// Socket identifier already exists in a table.
    DuplicateSocket,
    /// Requested socket was not found.
    SocketNotFound,
    /// Endpoint is already bound by an active socket.
    EndpointInUse,
    /// Socket is already closed.
    SocketClosed,
    /// Caller lacks required network authority.
    AccessDenied,
    /// Operation attempted to use a read-only target.
    ReadOnly,
    /// Operation attempted to use a sealed target.
    Sealed,
    /// Simulated network device is unavailable.
    DeviceUnavailable,
    /// Fixed-capacity collection is full.
    CapacityExceeded,
    /// No packet is available for the requested receive path.
    PacketUnavailable,
    /// Operation requires loopback-only endpoints.
    LoopbackOnly,
    /// Trace context was malformed.
    InvalidTrace,
    /// Redaction state is incompatible with the data class.
    InvalidRedaction,
    /// Secret or protected data requires encryption metadata.
    EncryptionRequired,
    /// Internal invariant failed.
    Internal,
}

impl NetworkError {
    /// Stable reason label for diagnostics and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::InvalidLabel => "invalid_label",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidAddress => "invalid_address",
            Self::InvalidPacket => "invalid_packet",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidProtocol => "invalid_protocol",
            Self::DuplicateProtocol => "duplicate_protocol",
            Self::ProtocolNotFound => "protocol_not_found",
            Self::InvalidSocket => "invalid_socket",
            Self::DuplicateSocket => "duplicate_socket",
            Self::SocketNotFound => "socket_not_found",
            Self::EndpointInUse => "endpoint_in_use",
            Self::SocketClosed => "socket_closed",
            Self::AccessDenied => "access_denied",
            Self::ReadOnly => "read_only",
            Self::Sealed => "sealed",
            Self::DeviceUnavailable => "device_unavailable",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::PacketUnavailable => "packet_unavailable",
            Self::LoopbackOnly => "loopback_only",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidRedaction => "invalid_redaction",
            Self::EncryptionRequired => "encryption_required",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when this error represents a fail-closed trust boundary.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::InvalidPacket
                | Self::PayloadTooLarge
                | Self::InvalidProtocol
                | Self::InvalidSocket
                | Self::EndpointInUse
                | Self::AccessDenied
                | Self::ReadOnly
                | Self::Sealed
                | Self::LoopbackOnly
                | Self::InvalidRedaction
                | Self::EncryptionRequired
        )
    }
}

/// Data sensitivity classification for network metadata and payloads.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DataClass {
    /// Public metadata or payload.
    Public = 0,
    /// Operational metadata suitable for trusted operators.
    Operational = 1,
    /// Sensitive metadata or payload requiring redaction before export.
    Sensitive = 2,
    /// Secret metadata or payload that must not be exported raw.
    Secret = 3,
}

impl DataClass {
    /// Returns `true` when data with this class must be redacted before export.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }

    /// Stable data class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }
}

/// Redaction state applied to diagnostics and network envelopes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// Public fields only.
    Public = 0,
    /// Operational metadata only.
    Operational = 1,
    /// Sensitive fields were redacted.
    SensitiveRedacted = 2,
    /// Secret fields were redacted.
    SecretRedacted = 3,
    /// Sensitive fields are present and must not be exported broadly.
    UnredactedSensitive = 4,
}

impl RedactionState {
    /// Stable redaction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::SensitiveRedacted => "sensitive_redacted",
            Self::SecretRedacted => "secret_redacted",
            Self::UnredactedSensitive => "unredacted_sensitive",
        }
    }
}

/// Stable trace context copied from observability/syscall layers when present.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace identifier shared across component boundaries.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
}

impl TraceContext {
    /// Empty trace context used when no trace is available.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };

    /// Creates a root trace context.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED,
        }
    }

    /// Creates a child trace context preserving the trace identifier.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
        }
    }

    /// Returns `true` when both trace and span identifiers are present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates trace metadata.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(NetworkError::ReservedBits);
        }
        if self.trace_id == 0 && self.span_id == 0 && self.parent_span_id == 0 {
            return Ok(());
        }
        if self.trace_id == 0 || self.span_id == 0 {
            return Err(NetworkError::InvalidTrace);
        }
        if self.parent_span_id != 0 && self.parent_span_id == self.span_id {
            return Err(NetworkError::InvalidTrace);
        }
        Ok(())
    }
}

/// Network authority bitmap.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetworkRights(pub u64);

impl NetworkRights {
    /// No authority.
    pub const NONE: Self = Self(0);
    /// Read metadata.
    pub const READ: Self = Self(NETWORK_RIGHT_READ);
    /// Send packets.
    pub const SEND: Self = Self(NETWORK_RIGHT_SEND);
    /// Receive packets.
    pub const RECEIVE: Self = Self(NETWORK_RIGHT_RECEIVE);
    /// Bind local endpoints.
    pub const BIND: Self = Self(NETWORK_RIGHT_BIND);
    /// Listen for inbound connections.
    pub const LISTEN: Self = Self(NETWORK_RIGHT_LISTEN);
    /// Connect to peers.
    pub const CONNECT: Self = Self(NETWORK_RIGHT_CONNECT);
    /// Configure sockets or protocol adapters.
    pub const CONFIGURE: Self = Self(NETWORK_RIGHT_CONFIGURE);
    /// Build raw packet envelopes.
    pub const RAW_PACKET: Self = Self(NETWORK_RIGHT_RAW_PACKET);
    /// Use loopback-only paths.
    pub const LOOPBACK: Self = Self(NETWORK_RIGHT_LOOPBACK);
    /// Emit audit evidence.
    pub const AUDIT: Self = Self(NETWORK_RIGHT_AUDIT);
    /// Administrative network authority.
    pub const ADMIN: Self = Self(NETWORK_RIGHT_ADMIN);
    /// Full authority for host-mode administrative tests.
    pub const ADMINISTRATOR: Self = Self(NETWORK_KNOWN_RIGHTS);

    /// Creates rights from raw bits after rejecting unknown bits.
    pub const fn from_bits(bits: u64) -> NetworkResult<Self> {
        if bits & !NETWORK_KNOWN_RIGHTS != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw rights bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Returns the union of two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates reserved bits.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.0 & !NETWORK_KNOWN_RIGHTS != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(())
        }
    }

    /// Fails closed when required rights are absent.
    pub const fn require(self, required: Self) -> NetworkResult<()> {
        if self.0 & !NETWORK_KNOWN_RIGHTS != 0 || required.0 & !NETWORK_KNOWN_RIGHTS != 0 {
            return Err(NetworkError::ReservedBits);
        }
        if self.contains(required) {
            Ok(())
        } else {
            Err(NetworkError::AccessDenied)
        }
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Compact root view of the network crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Rights bitmap recognized by this crate version.
    pub rights: u64,
    /// Packet schema version.
    pub packet_schema: &'static str,
    /// Socket schema version.
    pub socket_schema: &'static str,
    /// Protocol schema version.
    pub protocol_schema: &'static str,
}

impl NetworkCatalog {
    /// Current network catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        features: NETWORK_KNOWN_FEATURES,
        rights: NETWORK_KNOWN_RIGHTS,
        packet_schema: PACKET_SCHEMA_VERSION,
        socket_schema: SOCKET_SCHEMA_VERSION,
        protocol_schema: PROTOCOL_SCHEMA_VERSION,
    };

    /// Returns the current network catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Validates catalog metadata.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.repository.is_empty()
            || self.version.is_empty()
            || self.packet_schema.is_empty()
            || self.socket_schema.is_empty()
            || self.protocol_schema.is_empty()
        {
            return Err(NetworkError::MissingField);
        }
        if self.features & !NETWORK_KNOWN_FEATURES != 0 || self.rights & !NETWORK_KNOWN_RIGHTS != 0
        {
            return Err(NetworkError::ReservedBits);
        }
        Ok(())
    }
}

/// Current network catalog.
pub const NETWORK_CATALOG: NetworkCatalog = NetworkCatalog::CURRENT;

/// Returns the current network catalog.
pub const fn network_catalog() -> NetworkCatalog {
    NetworkCatalog::CURRENT
}

/// Validates redaction state for a data class.
pub const fn validate_redaction(
    data_class: DataClass,
    redaction: RedactionState,
) -> NetworkResult<()> {
    match data_class {
        DataClass::Public => {
            if matches!(redaction, RedactionState::Public) {
                Ok(())
            } else {
                Err(NetworkError::InvalidRedaction)
            }
        }
        DataClass::Operational => {
            if matches!(redaction, RedactionState::Operational) {
                Ok(())
            } else {
                Err(NetworkError::InvalidRedaction)
            }
        }
        DataClass::Sensitive => {
            if matches!(
                redaction,
                RedactionState::SensitiveRedacted | RedactionState::SecretRedacted
            ) {
                Ok(())
            } else {
                Err(NetworkError::InvalidRedaction)
            }
        }
        DataClass::Secret => {
            if matches!(redaction, RedactionState::SecretRedacted) {
                Ok(())
            } else {
                Err(NetworkError::InvalidRedaction)
            }
        }
    }
}

/// Validates a stable network label.
pub fn validate_network_label(label: &str, max_len: usize) -> NetworkResult<()> {
    if label.is_empty() {
        return Err(NetworkError::MissingField);
    }
    if label.len() > max_len {
        return Err(NetworkError::FieldTooLong);
    }
    if !label.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/' | b'@')
    }) {
        return Err(NetworkError::InvalidLabel);
    }
    Ok(())
}
