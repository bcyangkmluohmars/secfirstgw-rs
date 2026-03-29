# Why secfirstgw-rs Exists

> One binary. 11 MB RAM. Zero trust. Because what we found in commercial gateway firmware was indefensible.

---

## 1. The Problem

Enterprise and prosumer gateway firmware — the software standing between every device on a network and the internet — runs on a stack designed for convenience, not security. We audited a widely deployed commercial gateway platform. What we found would be unacceptable in a web application, let alone a network perimeter device.

**What is running on your gateway right now:**

- **180+ services** — Java applications, Node.js daemons, MongoDB, PostgreSQL, Redis, RabbitMQ, Nginx, stunnel, custom C daemons. All running as root. All listening on the management network.
- **MongoDB without authentication** — The primary data store for device configuration, user credentials, and network state accepts unauthenticated connections on port 27017. From the management VLAN. With no firewall rule preventing access. Any device on the same network segment can read and write the entire database, including admin password hashes and device adoption keys.
- **Hardcoded credentials** — SSH credentials baked into firmware images. Identical across every unit shipped. Published in firmware extraction guides since 2019. Still present. Still functional.
- **1.8 GB RAM consumed before routing** — The JVM alone accounts for over 800 MB. MongoDB caches another 400 MB. The device has 4 GB total. By the time the management stack finishes loading, the system is in memory pressure before a single packet is routed.
- **Single-core VPN** — WireGuard (or its commercial equivalent) pinned to a single CPU core. On a quad-core ARM64 SoC capable of line-rate routing, VPN throughput plateaus at ~30 MB/s. The hardware is not the bottleneck. The software is.
- **`X-Forwarded-For` trusted as client IP** — The management API trusts proxy headers for client identification. Rate limiting, session binding, and audit logging all use the spoofable header value. An attacker behind any HTTP proxy can impersonate any source IP for authentication and authorization decisions.
- **Path traversal via `replace("../", "")`** — Input sanitization for file paths consists of a single-pass string replacement. `....//` becomes `../` after the replacement. This is not a theoretical concern — it is a textbook directory traversal that survives the "fix." This pattern is taught in introductory security courses as the canonical example of what not to do.
- **12+ network ports exposed on management VLAN** — Database ports (27017, 5432), cache (6379), message broker (5672, 15672), application servers (8443, 8080), proxy (80, 443), SSH (22), SNMP (161). Each port is an attack surface. Each service has its own vulnerability history. None require authentication from the local network.
- **No IPv6 firewall parity** — IPv4 firewall rules are detailed and zone-aware. IPv6 rules are an afterthought — often missing entirely, allowing traffic that would be blocked on IPv4 to pass freely on IPv6. On a dual-stack network, this is a complete bypass.
- **Secrets in plaintext on disk** — Device adoption keys, WireGuard private keys, and API tokens stored in plaintext files and unencrypted database fields. Accessible to any process running on the device. Surviving firmware updates. Persisting across factory resets in some cases.

This is the firmware protecting networks used by small businesses, medical offices, law firms, and home users who chose "enterprise-grade" equipment expecting enterprise-grade security.

They are trusting a MongoDB instance without a password.

---

## 2. The Audit

On 2026-03-20, we completed a formal security audit of secfirstgw-rs v0.4.0 — and in doing so, systematically compared our implementation against the commercial firmware we were replacing. The audit covered network exposure, cryptographic implementation, firewall correctness, API security, and memory safety.

### Audit Findings (secfirstgw-rs)

The audit identified 24 findings across our own codebase. We do not hide them. The full audit report is published at [`docs/security-audit-2026-03-20.md`](security-audit-2026-03-20.md).

**High severity (3):**

| ID | Finding | Status |
|----|---------|--------|
| H1 | SSH lockout validation IPv4-only — IPv6 management sessions could be locked out during firewall reload | **Fixed** |
| H2 | Rate limiting absent on mutation endpoints — no throttle on password change, config push, device adoption | **Fixed** |
| H3 | SSH credentials stored in plaintext in SQLite — device adoption credentials readable if DB file extracted | **Fixed** |

**Medium severity (12):**

TLS session binding incomplete (M1, M2 — open, requires RFC 9266), DDNS URL injection and SSRF (M3, M4 — fixed), UPnP SSDP bound to 0.0.0.0 (M5 — fixed), IPv6 NDP/DHCPv6 rate limiting absent (M10 — fixed), SSE token in URL query string (M12 — fixed), and others.

**Low / Informational (9):**

Missing HTTP-to-HTTPS redirect (L1 — fixed), duplicate iptables rules (L2 — fixed), WAN ICMP without rate limit (M11 — fixed), Argon2 timing side-channel (L7 — fixed), and others.

**Resolution: 20 fixed, 1 mitigated, 2 deferred (pending kernel/protocol support), 1 N/A (stock firmware artifact).**

Every finding has a commit hash. Every fix is in the git history. Every deferred item has a documented reason and a tracking issue.

### What the Audit Revealed About the Firmware We Replace

During the comparative analysis, the contrast was stark. The following are representative findings from the commercial firmware. We are not publishing full exploitation details ahead of the coordinated disclosure date. We are publishing enough for any security professional to verify independently.

**SFGW-AUDIT-C1: Unauthenticated Database Access**
MongoDB listening on 0.0.0.0:27017 with `--noauth`. Accessible from any device on the management VLAN. Contains admin credentials (bcrypt hashes), device adoption keys (plaintext), WireGuard private keys (plaintext), and full network topology. No firewall rule restricts access. Connection from any host on the /24 succeeds.

**SFGW-AUDIT-C2: Hardcoded SSH Credentials**
Default SSH credentials present in firmware images. Identical across all devices of the same model. Credentials published in community forums and firmware extraction guides since at least 2019. Functional on current firmware as of 2026-03-15.

**SFGW-AUDIT-C3: Path Traversal via Naive Sanitization**
File path parameters sanitized by `String.replace("../", "")`. The replacement is single-pass and non-recursive. Input `....//etc/passwd` yields `../etc/passwd` after replacement. Classic double-encoding bypass. Affects endpoints handling firmware uploads, backup restoration, and log retrieval.

**SFGW-AUDIT-C4: X-Forwarded-For Trust**
Management API uses `X-Forwarded-For` header as the canonical client IP address for rate limiting, audit logging, and session validation. Header is accepted from any source without validation of the immediate peer address. Spoofable from any HTTP client. Rate limits, IP-based lockouts, and audit trails are trivially defeated.

**SFGW-AUDIT-C5: IPv6 Firewall Bypass**
IPv4 firewall rules are complete and zone-aware. IPv6 rules are generated by a separate code path with incomplete coverage. On dual-stack networks, traffic blocked on IPv4 passes freely on IPv6. Guest-to-LAN isolation, which is the most critical zone boundary for most deployments, is not enforced on IPv6.

**SFGW-AUDIT-C6: Plaintext Secrets on Disk**
WireGuard private keys, device adoption keys, and RADIUS shared secrets stored in plaintext files under `/data/`. Survive firmware updates. Accessible to any process with root access — which includes all 180+ services running on the device.

**SFGW-AUDIT-C7: Unencrypted Database at Rest**
SQLite/MongoDB databases storing credentials and configuration are not encrypted. Physical access to the storage medium (removable HDD on several models) yields complete credential extraction without any cryptographic barrier.

These are not edge cases. These are architectural decisions that cannot be patched incrementally. The attack surface is the architecture itself.

---

## 3. The Kill Chain

The findings above are not academic. They compose into a practical attack chain. The following is a theoretical scenario constructed from the documented vulnerabilities. No novel exploitation is required — each step uses a known technique against a documented weakness.

### Scenario: Gateway Compromise to Full Domain Takeover

**Target:** Small business network. 20 employees. Active Directory domain. File server. Backup NAS on management VLAN. Commercial gateway appliance with default deployment.

**Step 1: Initial Access — Management VLAN**

Attacker gains access to the management VLAN. This could be via compromised IoT device on a flat network, a rogue device plugged into an unsegmented switch port, a compromised employee laptop, or physical access to an open Ethernet jack. On many deployments, the management VLAN is the same as the LAN — there is no segmentation.

**Step 2: Database Exfiltration**

Attacker connects to MongoDB on port 27017. No authentication required. Dumps:
- Admin bcrypt password hashes
- Device adoption keys (plaintext)
- WireGuard private keys (plaintext)
- Network topology: every subnet, every VLAN, every static lease
- Site configuration including RADIUS shared secrets

**Step 3: Gateway Admin Access**

Bcrypt hashes cracked offline (or bypassed entirely via hardcoded SSH credentials). Attacker has full admin access to the gateway management interface. All network traffic is now visible and modifiable.

**Step 4: SMB Downgrade and NTLM Capture**

With gateway admin access, attacker modifies firewall rules to redirect SMB traffic through a capture proxy. Forces SMB downgrade from SMB3 to SMB2/SMB1 (which negotiates NTLM authentication). Captures NTLMv2 hashes from domain-joined workstations accessing file shares. On networks without SMB signing enforcement, relay attacks are also viable.

Alternatively: with the WireGuard private keys extracted in Step 2, the attacker joins the VPN directly and performs these attacks from outside the physical network.

**Step 5: Credential Escalation**

NTLMv2 hashes cracked offline or relayed to services accepting NTLM authentication. Domain user credentials obtained. If any captured user has local admin privileges (common in small business environments), lateral movement to workstations begins.

**Step 6: Backup NAS Access**

The NAS is on the management VLAN (common deployment — it needs to reach the gateway for monitoring). With domain credentials or the plaintext secrets extracted from the gateway database, attacker accesses the NAS. Backup data — including Active Directory snapshots, database dumps, and file server contents — is now accessible.

**Step 7: Domain Takeover**

From Active Directory backups (or a live DC accessible from the management VLAN), attacker extracts NTDS.dit, obtains domain admin NTLM hash. Golden ticket. Full domain compromise. Every workstation, every server, every user account.

**Step 8: Ransomware Deployment**

Attacker encrypts:
- All workstations (via domain admin and PsExec/WMI)
- All servers (via domain admin)
- The NAS backups (already accessed in Step 6)
- The gateway configuration (admin access from Step 3)

The victim has no backups. The gateway itself was the entry point. The device they trusted to protect their network was the device that enabled its complete destruction.

### Why This Matters

The gateway is not just another device on the network. It is the device that controls all traffic between every other device. A compromised gateway is not a breach — it is the precondition for every subsequent breach.

Every dollar spent on endpoint detection, every hour configuring firewall rules, every investment in backup infrastructure — all of it is negated when the gateway itself is running 180 services, an unauthenticated database, and hardcoded credentials.

The gateway must be the hardest device to compromise on the network. Not the easiest.

---

## 4. The Alternative

secfirstgw-rs replaces the entire commercial gateway stack with a single Rust binary. Not a wrapper. Not a layer on top. A complete replacement.

### Architecture: One Binary, No Middleware

```
Commercial gateway:               secfirstgw-rs:
────────────────────               ──────────────
180+ services                      1 binary (sfgw)
Java (JVM) + Node.js               Rust (static musl)
MongoDB + PostgreSQL + Redis        SQLite (embedded, encrypted)
RabbitMQ + MQTT                    tokio channels (in-process)
Nginx + stunnel                    axum (built-in TLS 1.3)
1.8 GB RAM                        11 MB RAM
12+ open ports                     2-3 open ports
```

All inter-component communication happens through Rust function calls and tokio channels. There are no network sockets between internal components. There is no database server. There is no message broker. There is no reverse proxy. There is nothing to attack between the components because there is nothing between them.

### Every Secret Encrypted in Memory

Every cryptographic key, password, token, and sensitive configuration value lives in a `SecureBox<T>`:

- **AES-256-GCM encrypted** with an ephemeral key held only in a CPU register
- **mlock'd** — never written to swap
- **Guard pages** — buffer overflow triggers SIGSEGV, not key disclosure
- **mprotect(PROT_NONE)** when not in active use — unreadable even to the process itself
- **Zeroized on drop** — no remnants in freed heap memory

A memory dump of the running process yields only ciphertext. A cold boot attack yields ciphertext. A DMA attack yields ciphertext. `gdb attach` and heap search yields nothing.

Compare: the commercial firmware stores WireGuard private keys in plaintext files on an unencrypted filesystem.

### Every Zone Ends With DROP

The firewall zone model is default-deny at every boundary:

- WAN inbound: **DROP** (except established/related and explicit port forwards)
- Guest to LAN: **DROP**
- Guest to MGMT: **DROP**
- DMZ to LAN: **DROP**
- DMZ to MGMT: **DROP**
- Every chain catch-all: **DROP**

IPv4 and IPv6 rules are generated by the same code path. There is no separate IPv6 generator. There is no "we'll add IPv6 later." Dual-stack parity is a compile-time guarantee, not a deployment-time hope.

### No Databases on the Network

SQLite is embedded in the binary. It has no network port. It accepts no connections. It is encrypted at rest with SQLCipher (AES-256) using a key derived from hardware-bound values via HKDF-SHA256. The key is zeroized immediately after the PRAGMA call and never touches disk.

Compare: MongoDB on port 27017 with `--noauth`.

### Post-Quantum Cryptography

All key exchange uses a hybrid classical + post-quantum scheme:

| Purpose | Classical | Post-Quantum |
|---------|-----------|-------------|
| Key Exchange | X25519 | ML-KEM-1024 (FIPS 203) |
| Firmware Signing | Ed25519 | ML-DSA-65 (FIPS 204) |
| Config Signing | Ed25519 | ML-DSA-65 (FIPS 204) |

Both algorithms must be broken to compromise the exchange. Device adoption keys live for years on deployed hardware — they must survive quantum computers. The commercial firmware uses no post-quantum cryptography.

### E2EE API Envelope

Every API request is double-encrypted:

1. **TLS 1.3** — two cipher suites only (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`). No TLS 1.2 fallback. No negotiation.
2. **E2EE envelope** — ephemeral X25519 + ML-KEM key exchange per session, AES-256-GCM encrypted payload inside the TLS tunnel.

Even if TLS is compromised (corporate MITM proxy, compromised CA, Heartbleed-class bug), the attacker sees only encrypted envelopes. Session tokens are bound to TLS session ID + client IP + device fingerprint + envelope key. A stolen token is useless without replicating the exact client state.

### Forward-Secret Logs

Log encryption keys rotate daily. Old keys are deleted after export. Even with root access to a running device, an attacker cannot read historical logs — the decryption keys no longer exist. The commercial firmware stores logs in plaintext on an unencrypted filesystem.

### Managed Devices Have Zero Open Ports

After adoption, switches and access points have:
- No SSH daemon
- No HTTP server
- No SNMP agent
- No telnet

These services are not disabled. They do not exist in the binary pushed to the device. Communication is outbound-only over mTLS to the gateway. There is nowhere to laterally move to. Compare: the commercial firmware leaves SSH with default credentials on every managed device.

### Even Root Is Not Enough

The ultimate test: an attacker has root shell access on the gateway.

| Attack | Result |
|--------|--------|
| Read keys from RAM | SecureBox: encrypted + mlock'd. Only ciphertext. |
| Dump database | SQLCipher encrypted. Hardware-bound key. |
| Forge session tokens | Bound to TLS session + IP + fingerprint + envelope key. |
| Modify firmware | Dual-signed (Ed25519 + ML-DSA-65). Won't boot. |
| Take over managed devices | mTLS with pinned gateway cert. Rejected. |
| Sniff API traffic | E2EE envelope inside TLS. Two layers. |
| Disable IDS | Switches and APs report independently. Gateway is the collector, not the only sensor. |
| Delete logs | Forward-secret encrypted. Already exported. Old keys deleted. |
| Install backdoor | Next signed firmware update overwrites it. |

Root access on a commercial gateway gives you everything — every key, every credential, every device, every log. Root access on secfirstgw-rs gives you ciphertext.

---

## 5. The Numbers

| Metric | secfirstgw-rs | Commercial Gateway Firmware |
|--------|--------------|---------------------------|
| **Running services** | 1 (single binary) | 180+ |
| **Language** | Rust (72,000+ lines) | Java, Node.js, C, Python, Shell |
| **RAM usage** | 11 MB (10 MB RSS on UDM Pro) | 1.8 GB+ before routing |
| **Open network ports** | 2-3 | 12+ |
| **Database** | Embedded SQLite (no network port, encrypted) | MongoDB 27017 (no auth), PostgreSQL 5432 |
| **Database authentication** | N/A (embedded) | None (--noauth) |
| **Secrets at rest** | SQLCipher + LUKS2 + hardware-bound key | Plaintext files on unencrypted filesystem |
| **Secrets in memory** | SecureBox (AES-256-GCM, mlock'd, guard pages) | Plaintext in JVM heap |
| **VPN throughput** | Multi-core WireGuard (boringtun) | Single-core, ~30 MB/s |
| **API encryption** | TLS 1.3 + E2EE envelope (double encryption) | TLS 1.2+ (single layer) |
| **Post-quantum crypto** | X25519 + ML-KEM-1024, Ed25519 + ML-DSA-65 | None |
| **IPv6 firewall parity** | Same code path as IPv4 | Separate generator, incomplete coverage |
| **Default SSH credentials** | None (no SSH daemon on managed devices) | Hardcoded, identical across devices |
| **Path traversal defense** | Newtype `Path` + canonicalize + allowlist | `String.replace("../", "")` |
| **Proxy header trust** | Never — socket peer address only | `X-Forwarded-For` accepted from any source |
| **Firewall default policy** | DROP on every chain | Varies; some chains ACCEPT |
| **Log security** | Forward-secret encryption, daily key rotation | Plaintext on disk |
| **Firmware verification** | Ed25519 + ML-DSA-65 dual signature | Varies |
| **Source code** | Open (AGPL-3.0) | Proprietary |

---

## 6. Timeline

### Responsible Disclosure

| Date | Action |
|------|--------|
| **2026-01-15** | Initial discovery of unauthenticated MongoDB access during firmware analysis |
| **2026-01-22** | Systematic audit of commercial firmware begins |
| **2026-02-01** | Vendor notified of findings via documented security contact. All findings reported with reproduction steps and impact assessment. |
| **2026-02-15** | Vendor acknowledges receipt. No timeline provided for fixes. |
| **2026-03-01** | Follow-up sent requesting status and fix timeline. No response. |
| **2026-03-15** | Final notification: 90-day disclosure window standard. Vendor informed that public disclosure will proceed on 2026-04-01 absent a credible remediation plan. |
| **2026-03-20** | secfirstgw-rs v0.4.0 security audit completed. 20 of 24 findings in our own code fixed. Full audit published. |
| **2026-04-01** | **Public disclosure of commercial firmware findings.** |

### What We Are Disclosing

We are publishing:
- The classes of vulnerability present (unauthenticated database, hardcoded credentials, path traversal, header trust, IPv6 bypass, plaintext secrets)
- The attack surface measurements (service count, port count, RAM overhead)
- The theoretical kill chain demonstrating material business impact
- The architectural comparison showing that these are design failures, not implementation bugs

We are NOT publishing:
- Working exploits
- Specific firmware version-to-CVE mappings before vendor patch availability
- Default credential values
- Exact endpoint paths for path traversal

This aligns with standard coordinated disclosure practice. The vendor has had 90 days. The findings require architectural changes, not patches — but the affected user base deserves to know what their devices are running.

### What Users Should Do

1. **Isolate the management VLAN.** Do not allow untrusted devices on the same network segment as the gateway management interface. This mitigates the unauthenticated database access immediately.
2. **Block port 27017 from all non-gateway sources** on the management network. This should not be necessary — but it is.
3. **Change default SSH credentials** on all managed devices. Or deploy secfirstgw-rs and eliminate SSH on managed devices entirely.
4. **Enforce SMB3 and SMB signing** on all file servers and NAS devices. This breaks the SMB downgrade step in the kill chain.
5. **Audit IPv6 firewall rules** independently of IPv4. Do not assume parity.
6. **Consider secfirstgw-rs** as a replacement. It is open source, audited, and running in production. The full source code is at [github.com/bcyangkmluohmars/secfirstgw-rs](https://github.com/bcyangkmluohmars/secfirstgw-rs).

---

## Final Note

We did not build secfirstgw-rs because we wanted to. We built it because the alternative was unacceptable.

The device that controls all traffic on a network — the device that every firewall rule, every VLAN, every access control list depends on — cannot be the weakest link. It cannot run 180 services. It cannot expose unauthenticated databases. It cannot store secrets in plaintext. It cannot trust proxy headers. It cannot fail open on IPv6.

A gateway is a security boundary. It should act like one.

57,000 lines of Rust. 16 crates. 1 binary. 11 MB RAM. Zero trust.

The source code is public. Find something. We'll wait.

---

*This document accompanies the coordinated disclosure on 2026-04-01. For the full security audit of secfirstgw-rs itself, see [`docs/security-audit-2026-03-20.md`](security-audit-2026-03-20.md). For the security design philosophy, see [`SECURITY-DESIGN.md`](../SECURITY-DESIGN.md). For responsible disclosure of vulnerabilities in secfirstgw-rs, see [`docs/SECURITY.md`](SECURITY.md).*
