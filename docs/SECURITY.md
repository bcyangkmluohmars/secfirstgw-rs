# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Contact

Email: **security@stageone.solutions**

If you prefer encrypted communication, use our PGP key (available on request at the same address).

### What to Include

- Description of the vulnerability
- Steps to reproduce (or proof of concept)
- Affected version(s)
- Impact assessment (your best guess is fine)
- Your preferred attribution name/handle (for the advisory)

### What to Expect

| Timeframe | Action |
|-----------|--------|
| **< 48 hours** | Initial response confirming receipt |
| **< 7 days** | Severity assessment and preliminary fix timeline |
| **< 30 days** | Patch release (critical/high) |
| **< 90 days** | Patch release (medium/low) |
| **On fix release** | Public advisory with researcher credit |

We follow coordinated disclosure. If we fail to meet these timelines, you are free to disclose publicly.

## Our Commitments

1. **We respond within 48 hours.** No exceptions.
2. **We credit researchers.** Unless you prefer to remain anonymous.
3. **We will never mark a valid finding as "Informational."** If it's a vulnerability, it's a vulnerability.
4. **We do not pursue legal action** against researchers acting in good faith.
5. **We fix, not suppress.** Every confirmed vulnerability gets a patch and a public advisory.

## Scope

### In Scope

- All code in this repository
- The `sfgw` binary and its behavior on supported platforms
- The web UI (React application)
- The E2EE protocol implementation
- The UniFi Inform protocol implementation
- The install script (`clean-and-install.sh`)
- Firewall rule generation and application
- Cryptographic implementations and key management
- Device adoption flow security
- Session management and authentication

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream, but let us know so we can assess impact)
- Social engineering attacks
- Denial of service via traffic flooding (this is a network device — rate limiting is in place, but we can't prevent volumetric attacks)
- Physical access attacks on unlocked, running devices
- Vulnerabilities in the Linux kernel itself
- Issues in the Ubiquiti hardware/firmware that secfirstgw-rs runs on top of

## Security Design

secfirstgw-rs is built with a defense-in-depth architecture. For the full security design philosophy and threat model, see:

- [ARCHITECTURE.md](ARCHITECTURE.md) — zone model, cryptographic architecture, threat model
- [SECURITY-DESIGN.md](../SECURITY-DESIGN.md) — detailed security design philosophy

### Key Security Properties

- **Minimal attack surface**: 2-3 open ports, single binary, no network-exposed databases
- **Defense in depth**: TLS 1.3 + E2EE envelope, encrypted database, encrypted memory
- **Zero trust**: no hardcoded keys, no trusted proxy headers, no auto-adopt
- **Post-quantum ready**: hybrid X25519 + ML-KEM-1024 key exchange
- **Default deny**: every firewall zone ends with catch-all DROP
- **Dual-stack**: identical IPv4/IPv6 firewall policies — no IPv6 bypass

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x | ✅ Current |
| < 0.3 | ❌ Upgrade recommended |

We support the current release and provide security patches for the previous release for 90 days after a new release.

## Past Advisories

No security advisories have been issued yet. When they are, they will be published as GitHub Security Advisories and listed here.

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged here (with permission):

*No entries yet — be the first.*

---

**Remember:** If you find something, report it. We'd rather know than not know. And we'd rather fix it than hide it.
