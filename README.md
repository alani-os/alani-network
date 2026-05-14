# alani-network

Network stack boundary for loopback, sockets, packet buffers, protocol adapters, and future transport services.

| Field | Value |
|---|---|
| Tier | Post-MVK boundary |
| Owner | Networking team |
| Aliases | None |
| Architectural dependencies | `alani-abi`, `alani-devices`, `alani-protocol`, `alani-policy`, `alani-observability` |

## Scope

This crate is a dependency-free Rust 2021 skeleton for the Post-MVK networking boundary described by `alani-spec/docs/repositories/alani-network.md`.

It currently defines:

- Packet buffers, packet queues, network addresses, packet protocol labels, packet flags, payload bounds, trace context propagation, and redaction checks.
- Socket identifiers, endpoints, options, lifecycle states, operation envelopes, fixed-capacity socket tables, and capability-gated request validation.
- Loopback queue and device contracts with fixed-capacity FIFO behavior for host-mode simulation.
- Protocol adapter descriptors, packet compatibility checks, and a fixed-capacity registry for future transport implementations.

The crate keeps sibling dependencies in Cargo metadata only. Public APIs are versioned through schema labels and the root `NetworkCatalog`.

## Security And Observability

Network operations fail closed on reserved bits, malformed trace context, invalid redaction state, missing capabilities, loopback boundary violations, and secret payloads without encryption metadata. Audit-relevant socket and packet paths expose `requires_audit` helpers so future `alani-audit` and `alani-observability` integrations can preserve durable evidence.

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

Keep public API changes synchronized with `docs/repositories/alani-network.md`, Doc 42, Doc 43, and Doc 63.
