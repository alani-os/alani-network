//! Socket handles, endpoints, options, and operation envelopes.
//!
//! Socket requests are capability checked and trace-aware. The skeleton keeps
//! transport state explicit so future runtime and kernel callers can validate
//! trust-boundary metadata before any packet or device operation occurs.

use crate::packet::{NetworkAddress, PacketBuffer};
use crate::protocol::TransportProtocol;
use crate::{
    validate_network_label, NetworkError, NetworkResult, NetworkRights, TraceContext,
    NETWORK_RIGHT_AUDIT, NETWORK_RIGHT_BIND, NETWORK_RIGHT_CONFIGURE, NETWORK_RIGHT_CONNECT,
    NETWORK_RIGHT_LISTEN, NETWORK_RIGHT_RAW_PACKET, NETWORK_RIGHT_RECEIVE, NETWORK_RIGHT_SEND,
};

/// Socket schema version owned by this crate.
pub const SOCKET_SCHEMA_VERSION: &str = "alani.network.socket.v1";

/// Invalid socket identifier.
pub const INVALID_SOCKET_ID: u64 = 0;

/// Maximum socket owner/principal label length.
pub const MAX_SOCKET_OWNER_LEN: usize = 128;

/// Maximum receive or send buffer length in socket options.
pub const MAX_SOCKET_BUFFER_LEN: usize = 64 * 1024;

/// Maximum listen backlog in socket options.
pub const MAX_SOCKET_BACKLOG: u16 = 1024;

/// Nonblocking socket flag.
pub const SOCKET_FLAG_NONBLOCK: u32 = 1 << 0;
/// Socket is listening for inbound connections.
pub const SOCKET_FLAG_LISTEN: u32 = 1 << 1;
/// Socket must only use loopback endpoints.
pub const SOCKET_FLAG_LOOPBACK_ONLY: u32 = 1 << 2;
/// Socket operations must emit audit evidence.
pub const SOCKET_FLAG_AUDIT_REQUIRED: u32 = 1 << 3;
/// Socket transport is encrypted by caller or future adapter.
pub const SOCKET_FLAG_ENCRYPTED: u32 = 1 << 4;
/// Socket is privileged and should be policy gated.
pub const SOCKET_FLAG_PRIVILEGED: u32 = 1 << 5;

/// Socket flags known by this crate version.
pub const SOCKET_KNOWN_FLAGS: u32 = SOCKET_FLAG_NONBLOCK
    | SOCKET_FLAG_LISTEN
    | SOCKET_FLAG_LOOPBACK_ONLY
    | SOCKET_FLAG_AUDIT_REQUIRED
    | SOCKET_FLAG_ENCRYPTED
    | SOCKET_FLAG_PRIVILEGED;

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> SocketDescriptor<'a> {
    /// Creates a socket descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Stable socket identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketId(pub u64);

impl SocketId {
    /// Invalid socket identifier.
    pub const INVALID: Self = Self(INVALID_SOCKET_ID);

    /// Creates a socket identifier.
    pub const fn new(value: u64) -> NetworkResult<Self> {
        if value == INVALID_SOCKET_ID {
            Err(NetworkError::InvalidSocket)
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
        if self.0 == INVALID_SOCKET_ID {
            Err(NetworkError::InvalidSocket)
        } else {
            Ok(())
        }
    }
}

/// Socket type.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketType {
    /// Datagram socket.
    Datagram = 1,
    /// Stream socket.
    Stream = 2,
    /// Raw packet socket.
    Raw = 3,
    /// Control-plane socket.
    Control = 4,
}

impl SocketType {
    /// Stable socket type label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Datagram => "datagram",
            Self::Stream => "stream",
            Self::Raw => "raw",
            Self::Control => "control",
        }
    }

    /// Returns `true` when this socket type can carry the protocol.
    pub const fn supports(self, protocol: TransportProtocol) -> bool {
        matches!(
            (self, protocol),
            (Self::Datagram, TransportProtocol::Loopback)
                | (Self::Datagram, TransportProtocol::Udp)
                | (Self::Datagram, TransportProtocol::Icmp)
                | (Self::Stream, TransportProtocol::Tcp)
                | (Self::Raw, TransportProtocol::Raw)
                | (Self::Control, TransportProtocol::Control)
        )
    }
}

/// Socket lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketState {
    /// Socket has been created but not bound.
    Created = 1,
    /// Socket has a local endpoint.
    Bound = 2,
    /// Socket is listening for inbound peers.
    Listening = 3,
    /// Socket has a peer endpoint.
    Connected = 4,
    /// Socket is closing.
    Closing = 5,
    /// Socket is closed.
    Closed = 6,
    /// Socket faulted.
    Faulted = 7,
}

impl SocketState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Bound => "bound",
            Self::Listening => "listening",
            Self::Connected => "connected",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Faulted => "faulted",
        }
    }

    /// Returns `true` when bind is allowed.
    pub const fn allows_bind(self) -> bool {
        matches!(self, Self::Created)
    }

    /// Returns `true` when listen is allowed.
    pub const fn allows_listen(self) -> bool {
        matches!(self, Self::Bound)
    }

    /// Returns `true` when connect is allowed.
    pub const fn allows_connect(self) -> bool {
        matches!(self, Self::Bound)
    }

    /// Returns `true` when send or receive is allowed.
    pub const fn allows_io(self) -> bool {
        matches!(self, Self::Bound | Self::Listening | Self::Connected)
    }
}

/// Socket flag bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketFlags(pub u32);

impl SocketFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Nonblocking operation.
    pub const NONBLOCK: Self = Self(SOCKET_FLAG_NONBLOCK);
    /// Listening state flag.
    pub const LISTEN: Self = Self(SOCKET_FLAG_LISTEN);
    /// Loopback-only socket.
    pub const LOOPBACK_ONLY: Self = Self(SOCKET_FLAG_LOOPBACK_ONLY);
    /// Audit evidence required.
    pub const AUDIT_REQUIRED: Self = Self(SOCKET_FLAG_AUDIT_REQUIRED);
    /// Encrypted transport metadata.
    pub const ENCRYPTED: Self = Self(SOCKET_FLAG_ENCRYPTED);
    /// Privileged socket metadata.
    pub const PRIVILEGED: Self = Self(SOCKET_FLAG_PRIVILEGED);

    /// Creates socket flags from raw bits.
    pub const fn from_bits(bits: u32) -> NetworkResult<Self> {
        if bits & !SOCKET_KNOWN_FLAGS != 0 {
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
        if self.0 & !SOCKET_KNOWN_FLAGS != 0 {
            Err(NetworkError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Socket endpoint binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketEndpoint<'a> {
    /// Endpoint address.
    pub address: NetworkAddress<'a>,
    /// Transport protocol.
    pub protocol: TransportProtocol,
}

impl<'a> SocketEndpoint<'a> {
    /// Creates a socket endpoint.
    pub const fn new(address: NetworkAddress<'a>, protocol: TransportProtocol) -> Self {
        Self { address, protocol }
    }

    /// Creates a loopback endpoint.
    pub const fn loopback(port: u16) -> Self {
        Self {
            address: NetworkAddress::loopback(port),
            protocol: TransportProtocol::Loopback,
        }
    }

    /// Returns `true` when this endpoint is loopback.
    pub const fn is_loopback(self) -> bool {
        self.address.is_loopback()
    }

    /// Validates endpoint metadata.
    pub fn validate(self) -> NetworkResult<()> {
        self.address.validate()?;
        if matches!(
            self.protocol,
            TransportProtocol::Loopback | TransportProtocol::Control
        ) && !self.address.is_loopback()
        {
            return Err(NetworkError::LoopbackOnly);
        }
        Ok(())
    }
}

/// Socket buffer and transport options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketOptions {
    /// Receive buffer capacity.
    pub recv_capacity: usize,
    /// Send buffer capacity.
    pub send_capacity: usize,
    /// Time to live or hop limit.
    pub ttl: u8,
    /// Listen backlog.
    pub backlog: u16,
}

impl SocketOptions {
    /// Conservative default socket options.
    pub const DEFAULT: Self = Self {
        recv_capacity: 4096,
        send_capacity: 4096,
        ttl: 64,
        backlog: 0,
    };

    /// Creates socket options.
    pub const fn new(recv_capacity: usize, send_capacity: usize) -> Self {
        Self {
            recv_capacity,
            send_capacity,
            ttl: 64,
            backlog: 0,
        }
    }

    /// Sets TTL or hop limit.
    pub const fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets listen backlog.
    pub const fn with_backlog(mut self, backlog: u16) -> Self {
        self.backlog = backlog;
        self
    }

    /// Validates socket option metadata.
    pub const fn validate(self) -> NetworkResult<()> {
        if self.recv_capacity == 0
            || self.send_capacity == 0
            || self.recv_capacity > MAX_SOCKET_BUFFER_LEN
            || self.send_capacity > MAX_SOCKET_BUFFER_LEN
        {
            return Err(NetworkError::InvalidSocket);
        }
        if self.ttl == 0 || self.backlog > MAX_SOCKET_BACKLOG {
            return Err(NetworkError::InvalidSocket);
        }
        Ok(())
    }
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Socket handle returned by a future kernel/runtime allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketHandle<'a> {
    /// Socket identifier.
    pub id: SocketId,
    /// Owning principal or service label.
    pub owner: &'a str,
    /// Socket type.
    pub socket_type: SocketType,
    /// Lifecycle state.
    pub state: SocketState,
    /// Local endpoint when bound.
    pub endpoint: Option<SocketEndpoint<'a>>,
    /// Peer endpoint when connected.
    pub peer: Option<SocketEndpoint<'a>>,
    /// Socket flags.
    pub flags: SocketFlags,
    /// Rights granted to the handle.
    pub rights: NetworkRights,
    /// Socket options.
    pub options: SocketOptions,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> SocketHandle<'a> {
    /// Creates a socket handle.
    pub const fn new(
        id: SocketId,
        owner: &'a str,
        socket_type: SocketType,
        rights: NetworkRights,
    ) -> Self {
        Self {
            id,
            owner,
            socket_type,
            state: SocketState::Created,
            endpoint: None,
            peer: None,
            flags: SocketFlags::EMPTY,
            rights,
            options: SocketOptions::DEFAULT,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets socket flags.
    pub const fn with_flags(mut self, flags: SocketFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Sets socket options.
    pub const fn with_options(mut self, options: SocketOptions) -> Self {
        self.options = options;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns `true` when the socket can perform I/O.
    pub const fn is_open(self) -> bool {
        self.state.allows_io()
    }

    /// Binds a local endpoint.
    pub fn bind(&mut self, endpoint: SocketEndpoint<'a>) -> NetworkResult<()> {
        self.validate()?;
        if !self.state.allows_bind() {
            return Err(NetworkError::InvalidSocket);
        }
        self.rights.require(NetworkRights(NETWORK_RIGHT_BIND))?;
        endpoint.validate()?;
        if self.flags.contains(SocketFlags::LOOPBACK_ONLY) && !endpoint.is_loopback() {
            return Err(NetworkError::LoopbackOnly);
        }
        if !self.socket_type.supports(endpoint.protocol) {
            return Err(NetworkError::InvalidSocket);
        }
        self.endpoint = Some(endpoint);
        self.state = SocketState::Bound;
        Ok(())
    }

    /// Marks a bound socket as listening.
    pub fn listen(&mut self, backlog: u16) -> NetworkResult<()> {
        self.validate()?;
        if !self.state.allows_listen() {
            return Err(NetworkError::InvalidSocket);
        }
        self.rights.require(NetworkRights(NETWORK_RIGHT_LISTEN))?;
        if backlog == 0 || backlog > MAX_SOCKET_BACKLOG {
            return Err(NetworkError::InvalidSocket);
        }
        self.options.backlog = backlog;
        self.flags = self.flags.union(SocketFlags::LISTEN);
        self.state = SocketState::Listening;
        Ok(())
    }

    /// Connects a bound socket to a peer endpoint.
    pub fn connect(&mut self, peer: SocketEndpoint<'a>) -> NetworkResult<()> {
        self.validate()?;
        if !self.state.allows_connect() {
            return Err(NetworkError::InvalidSocket);
        }
        self.rights.require(NetworkRights(NETWORK_RIGHT_CONNECT))?;
        peer.validate()?;
        if self.flags.contains(SocketFlags::LOOPBACK_ONLY) && !peer.is_loopback() {
            return Err(NetworkError::LoopbackOnly);
        }
        if !self.socket_type.supports(peer.protocol) {
            return Err(NetworkError::InvalidSocket);
        }
        self.peer = Some(peer);
        self.state = SocketState::Connected;
        Ok(())
    }

    /// Closes the socket.
    pub fn close(&mut self) -> NetworkResult<()> {
        if matches!(self.state, SocketState::Closed) {
            return Err(NetworkError::SocketClosed);
        }
        self.state = SocketState::Closed;
        Ok(())
    }

    /// Validates socket handle metadata.
    pub fn validate(self) -> NetworkResult<()> {
        self.id.validate()?;
        validate_network_label(self.owner, MAX_SOCKET_OWNER_LEN)?;
        self.flags.validate()?;
        self.rights.validate()?;
        self.options.validate()?;
        self.trace.validate()?;
        if let Some(endpoint) = self.endpoint {
            endpoint.validate()?;
            if !self.socket_type.supports(endpoint.protocol) {
                return Err(NetworkError::InvalidSocket);
            }
        }
        if let Some(peer) = self.peer {
            peer.validate()?;
            if !self.socket_type.supports(peer.protocol) {
                return Err(NetworkError::InvalidSocket);
            }
        }
        if matches!(self.state, SocketState::Bound | SocketState::Listening)
            && self.endpoint.is_none()
        {
            return Err(NetworkError::InvalidSocket);
        }
        if matches!(self.state, SocketState::Connected)
            && (self.endpoint.is_none() || self.peer.is_none())
        {
            return Err(NetworkError::InvalidSocket);
        }
        if self.flags.contains(SocketFlags::LOOPBACK_ONLY) {
            if let Some(endpoint) = self.endpoint {
                if !endpoint.is_loopback() {
                    return Err(NetworkError::LoopbackOnly);
                }
            }
            if let Some(peer) = self.peer {
                if !peer.is_loopback() {
                    return Err(NetworkError::LoopbackOnly);
                }
            }
        }
        Ok(())
    }
}

/// Socket operation envelope kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOperation {
    /// Create a socket.
    Create = 1,
    /// Bind a local endpoint.
    Bind = 2,
    /// Listen for inbound peers.
    Listen = 3,
    /// Accept a peer.
    Accept = 4,
    /// Connect to a peer.
    Connect = 5,
    /// Send a packet.
    Send = 6,
    /// Receive a packet.
    Receive = 7,
    /// Close the socket.
    Close = 8,
    /// Shut down part of the transport.
    Shutdown = 9,
    /// Configure socket options.
    Configure = 10,
    /// Use raw packet transport.
    RawPacket = 11,
}

impl SocketOperation {
    /// Stable operation label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Accept => "accept",
            Self::Connect => "connect",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Close => "close",
            Self::Shutdown => "shutdown",
            Self::Configure => "configure",
            Self::RawPacket => "raw_packet",
        }
    }

    /// Required rights for this operation.
    pub const fn required_rights(self) -> NetworkRights {
        match self {
            Self::Create => NetworkRights::READ,
            Self::Bind => NetworkRights(NETWORK_RIGHT_BIND),
            Self::Listen => NetworkRights(NETWORK_RIGHT_LISTEN),
            Self::Accept => NetworkRights(NETWORK_RIGHT_RECEIVE),
            Self::Connect => NetworkRights(NETWORK_RIGHT_CONNECT),
            Self::Send => NetworkRights(NETWORK_RIGHT_SEND),
            Self::Receive => NetworkRights(NETWORK_RIGHT_RECEIVE),
            Self::Close => NetworkRights::READ,
            Self::Shutdown => NetworkRights(NETWORK_RIGHT_CONNECT),
            Self::Configure => NetworkRights(NETWORK_RIGHT_CONFIGURE),
            Self::RawPacket => NetworkRights(NETWORK_RIGHT_RAW_PACKET),
        }
    }

    /// Returns `true` when audit evidence should normally be emitted.
    pub const fn is_audit_relevant(self) -> bool {
        matches!(
            self,
            Self::Bind
                | Self::Listen
                | Self::Accept
                | Self::Connect
                | Self::Configure
                | Self::RawPacket
        )
    }
}

/// Socket request validated before execution by a future transport backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketRequest<'a> {
    /// Requested operation.
    pub operation: SocketOperation,
    /// Socket handle.
    pub socket: SocketHandle<'a>,
    /// Optional packet for send/raw operations.
    pub packet: Option<PacketBuffer<'a>>,
    /// Rights offered by the caller.
    pub rights: NetworkRights,
    /// Request trace context.
    pub trace: TraceContext,
}

impl<'a> SocketRequest<'a> {
    /// Creates a socket request.
    pub const fn new(
        operation: SocketOperation,
        socket: SocketHandle<'a>,
        rights: NetworkRights,
    ) -> Self {
        Self {
            operation,
            socket,
            packet: None,
            rights,
            trace: TraceContext::EMPTY,
        }
    }

    /// Attaches a packet.
    pub const fn with_packet(mut self, packet: PacketBuffer<'a>) -> Self {
        self.packet = Some(packet);
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns `true` when the request should emit durable audit evidence.
    pub const fn requires_audit(self) -> bool {
        self.operation.is_audit_relevant()
            || self.socket.flags.contains(SocketFlags::AUDIT_REQUIRED)
            || match self.packet {
                Some(packet) => packet.requires_audit(),
                None => false,
            }
    }

    /// Validates request metadata and capability gates.
    pub fn validate(self) -> NetworkResult<()> {
        self.socket.validate()?;
        self.trace.validate()?;
        self.rights.require(self.operation.required_rights())?;
        self.socket
            .rights
            .require(self.operation.required_rights())?;
        if self.requires_audit() {
            self.rights.require(NetworkRights(NETWORK_RIGHT_AUDIT))?;
        }
        if matches!(
            self.socket.state,
            SocketState::Closed | SocketState::Faulted
        ) && !matches!(self.operation, SocketOperation::Close)
        {
            return Err(NetworkError::SocketClosed);
        }
        match self.operation {
            SocketOperation::Send | SocketOperation::RawPacket => {
                let packet = self.packet.ok_or(NetworkError::InvalidPacket)?;
                packet.validate()?;
                if !self.socket.state.allows_io() {
                    return Err(NetworkError::InvalidSocket);
                }
                if self.socket.flags.contains(SocketFlags::LOOPBACK_ONLY)
                    && (!packet.source.is_loopback() || !packet.destination.is_loopback())
                {
                    return Err(NetworkError::LoopbackOnly);
                }
                if matches!(self.operation, SocketOperation::RawPacket) {
                    self.rights
                        .require(NetworkRights(NETWORK_RIGHT_RAW_PACKET))?;
                }
            }
            SocketOperation::Receive => {
                if !self.socket.state.allows_io() {
                    return Err(NetworkError::InvalidSocket);
                }
            }
            SocketOperation::Bind => {
                if !self.socket.state.allows_bind() {
                    return Err(NetworkError::InvalidSocket);
                }
            }
            SocketOperation::Listen => {
                if !self.socket.state.allows_listen() {
                    return Err(NetworkError::InvalidSocket);
                }
            }
            SocketOperation::Connect => {
                if !self.socket.state.allows_connect() {
                    return Err(NetworkError::InvalidSocket);
                }
            }
            SocketOperation::Accept
            | SocketOperation::Create
            | SocketOperation::Close
            | SocketOperation::Shutdown
            | SocketOperation::Configure => {}
        }
        Ok(())
    }
}

/// Socket table module descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketTableDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> SocketTableDescriptor<'a> {
    /// Creates a socket table descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Socket table counters for diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketStats {
    /// Active socket handles.
    pub active: usize,
    /// Handles inserted into the table.
    pub inserted: u64,
    /// Handles removed from the table.
    pub removed: u64,
    /// Endpoint conflict attempts.
    pub endpoint_conflicts: u64,
}

/// Fixed-capacity socket handle table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketTable<'a, const N: usize> {
    sockets: [Option<SocketHandle<'a>>; N],
    len: usize,
    stats: SocketStats,
}

impl<'a, const N: usize> SocketTable<'a, N> {
    /// Creates an empty socket table.
    pub const fn new() -> Self {
        Self {
            sockets: [None; N],
            len: 0,
            stats: SocketStats {
                active: 0,
                inserted: 0,
                removed: 0,
                endpoint_conflicts: 0,
            },
        }
    }

    /// Returns active socket count.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no sockets are registered.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns table capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns table statistics.
    pub const fn stats(&self) -> SocketStats {
        self.stats
    }

    /// Returns all backing slots.
    pub const fn slots(&self) -> &[Option<SocketHandle<'a>>; N] {
        &self.sockets
    }

    /// Inserts a socket handle after validation and conflict checks.
    pub fn insert(&mut self, handle: SocketHandle<'a>) -> NetworkResult<()> {
        handle.validate()?;
        if self
            .sockets
            .iter()
            .flatten()
            .any(|existing| existing.id == handle.id)
        {
            return Err(NetworkError::DuplicateSocket);
        }
        if self.endpoint_conflict(handle) {
            self.stats.endpoint_conflicts = self.stats.endpoint_conflicts.saturating_add(1);
            return Err(NetworkError::EndpointInUse);
        }
        let slot = self
            .sockets
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(NetworkError::CapacityExceeded)?;
        *slot = Some(handle);
        self.len += 1;
        self.stats.active = self.len;
        self.stats.inserted = self.stats.inserted.saturating_add(1);
        Ok(())
    }

    /// Returns a socket by identifier.
    pub fn get(&self, id: SocketId) -> NetworkResult<SocketHandle<'a>> {
        id.validate()?;
        self.sockets
            .iter()
            .flatten()
            .find(|handle| handle.id == id)
            .copied()
            .ok_or(NetworkError::SocketNotFound)
    }

    /// Returns a mutable socket by identifier.
    pub fn get_mut(&mut self, id: SocketId) -> NetworkResult<&mut SocketHandle<'a>> {
        id.validate()?;
        self.sockets
            .iter_mut()
            .flatten()
            .find(|handle| handle.id == id)
            .ok_or(NetworkError::SocketNotFound)
    }

    /// Removes a socket by identifier.
    pub fn remove(&mut self, id: SocketId) -> NetworkResult<SocketHandle<'a>> {
        id.validate()?;
        let index = self
            .sockets
            .iter()
            .position(|slot| matches!(slot, Some(handle) if handle.id == id))
            .ok_or(NetworkError::SocketNotFound)?;
        let handle = self.sockets[index]
            .take()
            .ok_or(NetworkError::SocketNotFound)?;
        self.len -= 1;
        self.stats.active = self.len;
        self.stats.removed = self.stats.removed.saturating_add(1);
        Ok(handle)
    }

    /// Finds an active socket bound to an endpoint.
    pub fn find_by_endpoint(
        &self,
        endpoint: SocketEndpoint<'_>,
    ) -> NetworkResult<SocketHandle<'a>> {
        endpoint.validate()?;
        self.sockets
            .iter()
            .flatten()
            .find(|handle| {
                !matches!(handle.state, SocketState::Closed | SocketState::Faulted)
                    && matches!(handle.endpoint, Some(bound) if bound == endpoint)
            })
            .copied()
            .ok_or(NetworkError::SocketNotFound)
    }

    fn endpoint_conflict(&self, candidate: SocketHandle<'_>) -> bool {
        if matches!(candidate.state, SocketState::Closed | SocketState::Faulted) {
            return false;
        }
        let Some(endpoint) = candidate.endpoint else {
            return false;
        };
        self.sockets.iter().flatten().any(|existing| {
            !matches!(existing.state, SocketState::Closed | SocketState::Faulted)
                && matches!(existing.endpoint, Some(bound) if bound == endpoint)
        })
    }
}

impl<'a, const N: usize> Default for SocketTable<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}
