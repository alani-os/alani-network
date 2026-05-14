use alani_network::{
    network_catalog, validate_redaction, AddressKind, DataClass, LoopbackQueue, NetworkAddress,
    NetworkError, NetworkRights, PacketBuffer, PacketFlags, PacketId, PacketProtocol, PacketQueue,
    ProtocolAdapter, ProtocolCapabilities, ProtocolRegistry, ProtocolState, RedactionState,
    SocketEndpoint, SocketFlags, SocketHandle, SocketId, SocketOperation, SocketRequest,
    SocketTable, SocketType, TraceContext, TransportProtocol, NETWORK_KNOWN_FEATURES,
    NETWORK_RIGHT_AUDIT, NETWORK_RIGHT_BIND, NETWORK_RIGHT_CONNECT, NETWORK_RIGHT_LISTEN,
    NETWORK_RIGHT_LOOPBACK, NETWORK_RIGHT_READ, NETWORK_RIGHT_RECEIVE, NETWORK_RIGHT_SEND,
};

fn loopback_packet<'a>(id: u64, payload: &'a [u8]) -> PacketBuffer<'a> {
    PacketBuffer::new(
        PacketId::new(id).expect("valid packet id"),
        NetworkAddress::loopback(7),
        NetworkAddress::loopback(8),
        PacketProtocol::Loopback,
        payload,
    )
}

#[test]
fn repository_identity_and_catalog_are_stable() {
    assert_eq!(alani_network::repository_name(), "alani-network");
    assert_eq!(
        alani_network::module_names(),
        &["packet", "socket", "loopback", "protocol"]
    );

    let catalog = network_catalog();
    assert_eq!(catalog.features & NETWORK_KNOWN_FEATURES, catalog.features);
    assert_eq!(catalog.validate(), Ok(()));
    assert_eq!(
        alani_network::component_info().status,
        alani_network::ComponentStatus::Experimental
    );
}

#[test]
fn packet_validation_rejects_reserved_flags_and_unencrypted_secret_payloads() {
    let payload = b"hello";
    let packet = loopback_packet(1, payload);
    assert_eq!(packet.validate(), Ok(()));

    let reserved_flags = PacketFlags::from_bits(1 << 31).expect_err("reserved packet flag");
    assert_eq!(reserved_flags, NetworkError::ReservedBits);

    let secret = packet.with_classification(DataClass::Secret, RedactionState::SecretRedacted);
    assert_eq!(secret.validate(), Err(NetworkError::EncryptionRequired));

    let encrypted = secret.with_flags(PacketFlags::CONTROL.union(PacketFlags::ENCRYPTED));
    assert_eq!(encrypted.validate(), Ok(()));
}

#[test]
fn address_and_redaction_validation_fail_closed() {
    let bad_label = NetworkAddress::new(AddressKind::Service, "bad label", 9);
    assert_eq!(bad_label.validate(), Err(NetworkError::InvalidLabel));

    assert_eq!(
        validate_redaction(DataClass::Sensitive, RedactionState::UnredactedSensitive),
        Err(NetworkError::InvalidRedaction)
    );

    let malformed_trace = TraceContext {
        trace_id: 1,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };
    assert_eq!(malformed_trace.validate(), Err(NetworkError::InvalidTrace));
}

#[test]
fn protocol_registry_selects_only_enabled_adapters() {
    let mut registry: ProtocolRegistry<'_, 2> = ProtocolRegistry::new();
    let loopback = ProtocolAdapter::new("loopback", "0.1.0", TransportProtocol::Loopback)
        .with_state(ProtocolState::Enabled);
    registry.register(loopback).expect("loopback adapter");

    assert_eq!(
        registry
            .select(TransportProtocol::Loopback)
            .expect("selected"),
        loopback
    );
    assert_eq!(
        registry.register(loopback),
        Err(NetworkError::DuplicateProtocol)
    );

    let disabled = ProtocolAdapter::new("udp", "0.1.0", TransportProtocol::Udp)
        .with_state(ProtocolState::Disabled);
    registry
        .register(disabled)
        .expect("disabled adapter records");
    assert_eq!(
        registry.select(TransportProtocol::Udp),
        Err(NetworkError::ProtocolNotFound)
    );
}

#[test]
fn protocol_adapter_validation_rejects_missing_loopback_capability() {
    let adapter = ProtocolAdapter::new("control", "0.1.0", TransportProtocol::Control)
        .with_capabilities(ProtocolCapabilities::CONTROL);
    assert_eq!(adapter.validate(), Err(NetworkError::InvalidProtocol));
}

#[test]
fn protocol_adapter_validates_packet_compatibility() {
    let packet = PacketBuffer::new(
        PacketId::new(40).expect("valid packet id"),
        NetworkAddress::new(AddressKind::Ipv4, "127.0.0.1", 7000),
        NetworkAddress::new(AddressKind::Ipv4, "127.0.0.1", 7001),
        PacketProtocol::Udp,
        b"payload",
    );
    let adapter = ProtocolAdapter::new("udp", "0.1.0", TransportProtocol::Udp)
        .with_state(ProtocolState::Enabled);
    assert_eq!(adapter.validate_packet(packet), Ok(()));

    let too_small = adapter.with_max_payload_len(2);
    assert_eq!(
        too_small.validate_packet(packet),
        Err(NetworkError::PayloadTooLarge)
    );

    let encrypted_required = adapter.with_capabilities(
        adapter
            .capabilities
            .union(ProtocolCapabilities::ENCRYPTION_REQUIRED),
    );
    assert_eq!(
        encrypted_required.validate_packet(packet),
        Err(NetworkError::EncryptionRequired)
    );

    let mut registry: ProtocolRegistry<'_, 1> = ProtocolRegistry::new();
    registry.register(adapter).expect("udp adapter");
    assert_eq!(registry.select_for_packet(packet), Ok(adapter));
}

#[test]
fn socket_lifecycle_and_request_rights_are_checked() {
    let rights = NetworkRights(
        NETWORK_RIGHT_READ
            | NETWORK_RIGHT_BIND
            | NETWORK_RIGHT_CONNECT
            | NETWORK_RIGHT_SEND
            | NETWORK_RIGHT_RECEIVE
            | NETWORK_RIGHT_AUDIT,
    );
    let mut socket = SocketHandle::new(
        SocketId::new(10).expect("valid socket id"),
        "service:init",
        SocketType::Datagram,
        rights,
    )
    .with_flags(SocketFlags::LOOPBACK_ONLY);

    socket
        .bind(SocketEndpoint::loopback(7000))
        .expect("bind loopback");
    socket
        .connect(SocketEndpoint::loopback(7001))
        .expect("connect loopback");

    let packet = loopback_packet(2, b"payload").with_flags(PacketFlags::AUDIT_REQUIRED);
    let send = SocketRequest::new(SocketOperation::Send, socket, rights).with_packet(packet);
    assert_eq!(send.validate(), Ok(()));

    let no_audit = NetworkRights(NETWORK_RIGHT_READ | NETWORK_RIGHT_SEND);
    assert_eq!(
        SocketRequest::new(SocketOperation::Send, socket, no_audit)
            .with_packet(packet)
            .validate(),
        Err(NetworkError::AccessDenied)
    );
}

#[test]
fn socket_listen_requires_listen_right() {
    let mut socket = SocketHandle::new(
        SocketId::new(11).expect("valid socket id"),
        "service:listener",
        SocketType::Datagram,
        NetworkRights(NETWORK_RIGHT_READ | NETWORK_RIGHT_BIND),
    );
    socket
        .bind(SocketEndpoint::loopback(7002))
        .expect("bind loopback");
    assert_eq!(socket.listen(8), Err(NetworkError::AccessDenied));

    let mut allowed = SocketHandle::new(
        SocketId::new(12).expect("valid socket id"),
        "service:listener",
        SocketType::Datagram,
        NetworkRights(NETWORK_RIGHT_READ | NETWORK_RIGHT_BIND | NETWORK_RIGHT_LISTEN),
    );
    allowed
        .bind(SocketEndpoint::loopback(7003))
        .expect("bind loopback");
    assert_eq!(allowed.listen(8), Ok(()));
}

#[test]
fn socket_table_prevents_duplicate_ids_and_endpoint_conflicts() {
    let rights = NetworkRights(NETWORK_RIGHT_READ | NETWORK_RIGHT_BIND);
    let mut first = SocketHandle::new(
        SocketId::new(50).expect("valid socket id"),
        "service:first",
        SocketType::Datagram,
        rights,
    );
    first
        .bind(SocketEndpoint::loopback(7100))
        .expect("bind first");

    let mut second = SocketHandle::new(
        SocketId::new(51).expect("valid socket id"),
        "service:second",
        SocketType::Datagram,
        rights,
    );
    second
        .bind(SocketEndpoint::loopback(7100))
        .expect("bind second");

    let mut table: SocketTable<'_, 1> = SocketTable::new();
    assert_eq!(table.insert(first), Ok(()));
    assert_eq!(table.insert(first), Err(NetworkError::DuplicateSocket));
    assert_eq!(table.insert(second), Err(NetworkError::EndpointInUse));
    assert_eq!(table.stats().endpoint_conflicts, 1);
    assert_eq!(
        table.find_by_endpoint(SocketEndpoint::loopback(7100)),
        Ok(first)
    );
    assert_eq!(table.remove(first.id), Ok(first));
    assert_eq!(table.get(first.id), Err(NetworkError::SocketNotFound));
}

#[test]
fn packet_queue_tracks_fifo_stats_and_capacity() {
    let mut queue: PacketQueue<'_, 1> = PacketQueue::new();
    let first = loopback_packet(60, b"first");
    let second = loopback_packet(61, b"second");

    assert_eq!(queue.push(first), Ok(()));
    assert_eq!(queue.peek().map(|packet| packet.id.get()), Some(60));
    assert_eq!(queue.push(second), Err(NetworkError::CapacityExceeded));
    assert_eq!(queue.stats().drops, 1);

    let popped = queue.pop().expect("queued packet");
    assert_eq!(popped.id.get(), 60);
    assert_eq!(queue.pop(), Err(NetworkError::PacketUnavailable));
    assert_eq!(queue.stats().packets_queued, 1);
    assert_eq!(queue.stats().packets_dequeued, 1);
}

#[test]
fn loopback_queue_enforces_rights_capacity_and_fifo_order() {
    let payload = b"ping";
    let rights = NetworkRights(NETWORK_RIGHT_SEND | NETWORK_RIGHT_RECEIVE | NETWORK_RIGHT_LOOPBACK);
    let mut queue: LoopbackQueue<'_, 1> = LoopbackQueue::new();

    let packet = loopback_packet(20, payload);
    assert_eq!(queue.enqueue(rights, packet), Ok(()));
    assert_eq!(
        queue.enqueue(rights, loopback_packet(21, payload)),
        Err(NetworkError::CapacityExceeded)
    );
    assert_eq!(queue.stats().drops, 1);

    let received = queue.dequeue(rights).expect("received packet");
    assert_eq!(received.id.get(), 20);
    assert_eq!(queue.dequeue(rights), Err(NetworkError::PacketUnavailable));
    assert_eq!(queue.stats().packets_sent, 1);
    assert_eq!(queue.stats().packets_received, 1);

    let missing_loopback = NetworkRights(NETWORK_RIGHT_SEND | NETWORK_RIGHT_RECEIVE);
    assert_eq!(
        queue.enqueue(missing_loopback, loopback_packet(22, payload)),
        Err(NetworkError::AccessDenied)
    );
}

#[test]
fn loopback_queue_rejects_non_loopback_packets() {
    let rights = NetworkRights(NETWORK_RIGHT_SEND | NETWORK_RIGHT_RECEIVE | NETWORK_RIGHT_LOOPBACK);
    let mut queue: LoopbackQueue<'_, 2> = LoopbackQueue::new();
    let packet = PacketBuffer::new(
        PacketId::new(30).expect("valid packet id"),
        NetworkAddress::new(AddressKind::Ipv4, "127.0.0.1", 7),
        NetworkAddress::loopback(8),
        PacketProtocol::Udp,
        b"payload",
    );

    assert_eq!(
        queue.enqueue(rights, packet),
        Err(NetworkError::LoopbackOnly)
    );
    assert_eq!(queue.stats().drops, 1);
}
