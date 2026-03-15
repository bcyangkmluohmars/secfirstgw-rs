# CLAUDE.md — Coding Directives for secfirstgw-rs

> This file is law. Every AI agent and human contributor follows these rules. No exceptions.

## Project Identity

**secfirstgw-rs** — A security-first gateway firmware in Rust. Single binary, minimal attack surface, zero trust.

Architecture: Cargo workspace with 15 crates (`crates/sfgw-*`). Web UI in `web/`. Docker deployment.

## The Prime Directive

**Security is not a feature. It's the architecture.**

Every line of code you write must answer: "What happens if an attacker controls this input?" If you can't answer that, don't write the line.

## Rust Rules

### MUST

- `#![deny(unsafe_code)]` in every crate — no exceptions without a `// SAFETY:` comment reviewed by maintainer
- All errors handled explicitly — use `thiserror` for library crates, `anyhow` for application code (`sfgw-cli`)
- All secrets in `SecureBox<T>` (from `sfgw-crypto::secure_mem`) — zeroize on drop, mlock'd, guard pages
- All user input validated at the boundary — parse, don't validate. Use newtypes (`Port`, `Ipv4Addr`, `MacAddr`, `ZoneName`)
- All database queries parameterized — no string interpolation in SQL, ever
- All network listeners bind to specific interfaces/zones — never `0.0.0.0` or `::` without zone policy check
- Dual-stack (IPv4 + IPv6) everywhere — no IPv4-only code paths
- `#[must_use]` on functions that return security-relevant results
- Tests for every public API — unit tests in module, integration tests in `tests/`

### MUST NOT

- No `unwrap()` or `expect()` in library code — only in tests or with `// INVARIANT:` comment explaining why it can't fail
- No hardcoded secrets, keys, passwords, tokens — not even for testing. Use env vars or config files
- No `println!()` — use `tracing::{info, warn, error, debug, trace}` exclusively
- No `std::process::Command` for crypto operations — use Rust crypto libraries
- No `TrustAll` / `danger_accept_invalid_certs` — ever. Not even in tests. Bring up a proper test CA.
- No string-based path manipulation — use `std::path::Path` / `PathBuf` and canonicalize
- No `sleep()` in production code — use tokio timers, channels, or condition variables
- No raw SQL strings — use parameterized queries through `sfgw-db` abstractions
- No `.clone()` on secrets — move semantics or references only
- No temporary files with secrets — if needed, use memfd or tmpfs with restricted permissions

### PREFER

- `&str` over `String` in function signatures where ownership isn't needed
- Enums over stringly-typed values — `Zone::Guest` not `"guest"`
- Builder pattern for complex config structs
- `impl Into<T>` for ergonomic APIs
- Early returns for validation — keep the happy path unindented
- `const fn` where possible
- Inline documentation with `///` on all public items

## Crypto Rules

- **Hybrid only** — X25519 + ML-KEM for key exchange, Ed25519 + ML-DSA for signing. Both must pass.
- **AES-256-GCM** or **ChaCha20-Poly1305** — no CBC, no ECB, no unauthenticated encryption
- **No MD5, no SHA-1** — SHA-256 minimum, prefer SHA-384/512 or BLAKE3
- **No custom crypto** — use `ring`, `aes-gcm`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `fips203`, `fips204`
- **Nonces must be unique** — use random nonces (96-bit) or monotonic counters, never reuse
- **Key derivation** — Argon2id for passwords, HKDF-SHA256 for key expansion
- **Zeroize everything** — every key, nonce, plaintext buffer must implement `Zeroize` and be dropped explicitly

## Network Rules

- **Zone-aware binding** — every listener checks zone policy before accepting connections
- **Default deny** — no traffic flows unless explicitly allowed in zone matrix
- **No XFF trust** — `X-Forwarded-For` is untrusted input, always use socket peer address
- **TLS 1.3 only** — `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256`, nothing else
- **No plaintext HTTP** on any port except `:80` → 301 redirect to `:443`
- **mTLS for devices** — all managed devices authenticate with client certificates pinned at adoption
- **Rate limiting** — every endpoint exposed to users must have rate limiting. No exceptions.

## API Rules

- **E2EE envelope** — all protected routes wrapped in X25519 ECDH + AES-256-GCM envelope via middleware
- **Session binding** — tokens bound to TLS session + IP + device fingerprint + envelope key
- **No CORS wildcards** — explicit origin allowlist, properly anchored regex with escaped dots
- **CSRF not needed** — E2EE envelope provides equivalent protection
- **JSON only** — no XML, no YAML, no form-encoded on API endpoints
- **Semantic HTTP status codes** — 401 for auth, 403 for authz, 422 for validation, 429 for rate limit
- **No information leakage** — error responses never expose internals, stack traces, or config details

## Database Rules

- **SQLite only** — embedded, encrypted at rest, no network port
- **Parameterized queries** — always `?` placeholders, never string format
- **Migrations** — versioned, forward-only, in `sfgw-db/migrations/`
- **No ORM** — raw SQL through thin abstraction layer is fine. Keep it simple.

## Logging Rules

- **Never log secrets** — no keys, tokens, passwords, session IDs in any log level
- **Structured logging** — use `tracing` spans and fields, not string interpolation
- **Forward-secret** — daily key rotation, old keys deleted after export (via `sfgw-log`)
- **Log levels**: `error` = needs attention now, `warn` = something's off, `info` = state changes, `debug` = developer detail, `trace` = packet-level

## Frontend Rules (web/)

- **React + TypeScript** — strict mode, no `any` types
- **No inline styles** — Tailwind CSS only
- **No external CDN** — all assets bundled, no third-party scripts
- **E2EE client** — `api.ts` handles envelope encryption/decryption transparently
- **Token in localStorage** — envelope key renegotiated on every session init
- **401 → redirect to /login** — automatic, no manual token management

## Git Rules

- **Conventional commits** — `feat:`, `fix:`, `sec:`, `refactor:`, `docs:`, `test:`, `ci:`
- **`sec:` prefix** for any security-relevant change — makes audit trail easy
- **No secrets in git history** — ever. Not even in tests. Not even reverted.
- **Signed commits** preferred

## Crate Responsibilities

| Crate | Does | Does NOT |
|-------|------|----------|
| `sfgw-cli` | Binary entry point, arg parsing, service orchestration | Business logic |
| `sfgw-fw` | nftables rules, zone matrix, WAN failover | Packet inspection |
| `sfgw-net` | Interface management, VLAN config, routing | Firewall rules |
| `sfgw-vpn` | WireGuard tunnels via boringtun, peer management | Key storage (uses sfgw-crypto) |
| `sfgw-dns` | dnsmasq config generation, DHCP | Direct DNS serving |
| `sfgw-api` | axum routes, auth, E2EE middleware, rate limiting | Database queries (uses sfgw-db) |
| `sfgw-db` | SQLite access, migrations, encrypted storage | HTTP, network |
| `sfgw-crypto` | SecureBox, key derivation, hybrid PQ crypto | Anything non-crypto |
| `sfgw-adopt` | Device adoption, mTLS CA, inform protocol | Device monitoring |
| `sfgw-ids` | ARP/DHCP/DNS/VLAN monitoring, alert correlation | Blocking (notifies sfgw-fw) |
| `sfgw-log` | Forward-secret log encryption, export | Log aggregation |
| `sfgw-hal` | Hardware abstraction, platform detection | Business logic |
| `sfgw-display` | Display abstraction (HD44780 LCD, framebuffer touchscreen), auto-detect | Any non-display logic |
| `sfgw-nas` | SMB3/NFS file sharing | Anything non-NAS |
| `sfgw-controller` | High-level orchestration, service lifecycle | Low-level implementation |

## Development Workflow

### Target Device
- **UDM-Pro** on Management network at `10.0.0.1`
- Only SSH and Web UI exposed — nothing else
- Deploy scripts handle everything. Do NOT manually SSH to debug deploy issues.

### Deploy (Development)
```bash
# THE workflow. Code change → deploy. That's it.
scripts/dev-deploy.sh <IP>
# Example: scripts/dev-deploy.sh 10.0.0.1
```

### Database Changes (Schema / Seed / Migration)
**If you changed anything in `sfgw-db/migrations/` or seed data:**
1. Delete the DB on the device: `ssh root@10.0.0.1 rm /data/sfgw/sfgw.db`
   Then `scripts/dev-deploy.sh 10.0.0.1` — it recreates and seeds automatically
2. **DO NOT** manually inspect the DB trying to figure out why old data looks wrong
3. **DO NOT** try manual SSH deploys
4. **JUST:** delete DB → `scripts/dev-deploy.sh <IP>` → done.

### After Context Compaction
If you lost context and don't know the project state:
1. Read this file (you're doing it)
2. Check `git log --oneline -20` for recent changes
3. Check `git diff --stat HEAD~5` to see what's been touched
4. Run the deploy script — it's idempotent
5. **DO NOT** start debugging from scratch. The tooling works. Trust it.

## The Anti-Ubiquiti Checklist

Before every PR, ask:

- [ ] Would this code survive a whitebox firmware audit?
- [ ] Are there any hardcoded values that should be configurable?
- [ ] Does this endpoint work correctly with IPv6-only?
- [ ] Is this reachable from zones that shouldn't access it?
- [ ] Does the error message leak implementation details?
- [ ] Would `replace("../", "")` be a valid description of my input sanitization? (If yes, start over.)
