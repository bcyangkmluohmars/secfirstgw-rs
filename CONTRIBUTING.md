# Contributing to secfirstgw-rs

Thanks for your interest. We take contributions seriously — and security even more so.

## Ground Rules

1. **Read [CLAUDE.md](CLAUDE.md) first.** It's not just for AI agents. Every rule applies to humans too.
2. **Read [SECURITY-DESIGN.md](SECURITY-DESIGN.md).** Understand the philosophy before writing code.
3. **Security is not negotiable.** If your change weakens security for convenience, it will be rejected.

## Getting Started

```bash
git clone https://github.com/bcyangkmluohmars/secfirstgw-rs.git
cd secfirstgw-rs
cargo build --workspace
cargo test --workspace
```

### Docker

```bash
docker compose up --build
```

## Before You Code

- **Check existing issues** — someone might already be on it.
- **Open an issue first** for anything non-trivial. Discuss the approach before writing 500 lines.
- **One PR, one concern.** Don't mix a bugfix with a feature with a refactor.

## Code Standards

### Rust

- Edition 2024, stable toolchain
- `cargo fmt` — no exceptions
- `cargo clippy -- -D warnings` — must pass
- `cargo test --workspace` — must pass
- No `unsafe` without `// SAFETY:` justification
- No `unwrap()` in library code
- All secrets through `SecureBox<T>`
- All user input validated at the boundary with newtypes

### Frontend (web/)

- React + TypeScript, strict mode
- Tailwind CSS, no inline styles
- `npm run build` must succeed with zero warnings

### Commits

```
feat: add WireGuard peer management API
fix: prevent zone bypass on VLAN reassignment  
sec: enforce mTLS cert pinning on device adoption
refactor: extract key derivation into sfgw-crypto
docs: update zone matrix diagram
test: add E2EE replay attack prevention tests
```

Use `sec:` for any security-relevant change. This makes audit trails trivial.

## Pull Requests

### Requirements

- [ ] `cargo fmt && cargo clippy -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] New code has tests
- [ ] Security-relevant changes have `sec:` commit prefix
- [ ] No hardcoded values that should be configurable
- [ ] Works with IPv4 and IPv6
- [ ] Error messages don't leak internals
- [ ] Updated relevant docs/README if applicable

### Review Process

- All PRs require at least one review
- Security-critical PRs (`sec:` prefix) require maintainer review
- We may ask for changes. Don't take it personally — we're protecting users.

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Email: security@bcyangkmluohmars.dev (or use the method specified in [SECURITY.md](SECURITY.md) if it exists)

We take responsible disclosure seriously. We respond within 48 hours. We credit researchers.

We will never mark a valid finding as "Informational."

## CLA

Contributions require signing the [Individual Contributor License Agreement](https://gist.github.com/CLAassistant/bd1ea8ec8aa0357414e8). This enables dual-licensing (AGPL + Commercial). You retain copyright of your contribution.

A CLA Assistant bot will prompt first-time contributors automatically on their PR.

## Architecture

```
crates/
├── sfgw-cli        → Binary entry point
├── sfgw-api         → axum HTTP API + E2EE middleware
├── sfgw-fw          → Firewall (nftables, zone matrix)
├── sfgw-net         → Network interfaces, VLANs, routing
├── sfgw-vpn         → WireGuard via boringtun
├── sfgw-dns         → DNS/DHCP config generation
├── sfgw-db          → SQLite encrypted storage
├── sfgw-crypto      → SecureBox, hybrid PQ crypto
├── sfgw-adopt       → Device adoption, mTLS CA
├── sfgw-ids         → Intrusion detection
├── sfgw-log         → Forward-secret logging
├── sfgw-hal         → Hardware abstraction
├── sfgw-lcd         → LCD display (bare metal)
├── sfgw-nas         → SMB3/NFS
└── sfgw-controller  → Service orchestration
web/                 → React + TypeScript dashboard
```

Each crate has a single responsibility. Don't blur the lines. See CLAUDE.md for what each crate does and does NOT do.

## What We're Looking For

- **Personalities** — we're always looking for new personalities. If your firewall messages make us laugh, they're in. See `crates/sfgw-personality/src/messages.rs` for the format.
- **IDS signatures** — new detection patterns for ARP spoofing, DNS tunneling, VLAN hopping
- **Platform support** — new HAL backends for hardware we don't have
- **Protocol implementations** — RADIUS, 802.1X, LLDP
- **Performance** — profiling, optimization, benchmarks
- **Tests** — especially fuzzing and property-based tests on crypto/network code
- **Documentation** — architecture diagrams, deployment guides, API docs

## What We Won't Accept

- Telemetry or phone-home functionality
- Closed-source dependencies
- Weakening of any security guarantee for convenience
- `TrustAllCerts`, `NoopHostnameVerifier`, or equivalent in any form
- Features that only work on IPv4

## Code of Conduct

Be professional. Be constructive. Attack code, not people. We're building something that protects networks — let's protect each other too.
