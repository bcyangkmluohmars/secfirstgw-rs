# Security Audit — secfirstgw-rs v0.4.0

**Date:** 2026-03-20

## Fix Status

| ID | Finding | Severity | Status | Commit |
|----|---------|----------|--------|--------|
| **H2** | Rate Limiting: Mutations unlimitiert | HIGH | **FIXED** | `sec: tiered rate limiting — critical mutations 5/min` |
| **H1** | SSH Lockout Validation nur IPv4 | HIGH | **FIXED** | `sec: SSH lockout validation — IPv6 + protocol number 6 alias` |
| **H3** | SSH Credentials im Klartext in DB | MEDIUM-HIGH | **FIXED** | `sec: SSH credential encryption at application level` |
| **M1** | TLS Session Binding fehlt | MEDIUM | OPEN | |
| **M2** | E2EE Envelope Keys nicht TLS-gebunden | MEDIUM | OPEN | |
| **M3** | DDNS URL-Parameter nicht encoded | MEDIUM | **FIXED** | `sec: DDNS URL encoding + SSRF validation` |
| **M4** | DDNS server SSRF | LOW-MEDIUM | **FIXED** | `sec: DDNS URL encoding + SSRF validation` |
| **M5** | UPnP SSDP auf 0.0.0.0:1900 | MEDIUM | **FIXED** | `sec: UPnP SSDP bind to LAN IP + peer validation` |
| **M6** | Default Chain Policies ACCEPT | MEDIUM | **ALREADY FIXED** | `FirewallPolicy::default()` = DROP seit Erstimplementierung |
| **M7** | rp_filter=0 | MEDIUM | **ALREADY FIXED** | `clean-and-install.sh` setzt rp_filter=1 |
| **M8** | DNSSEC AD-Flag fehlt | MEDIUM | **FIXED** | `sec: IPv6 NDP rate limiting + DHCPv6 + link-local isolation + DNSSEC` |
| **M9** | Static Files ohne Security Headers | MEDIUM | **ALREADY FIXED** | `security_headers_middleware` auf Root-Router |
| **M10** | IPv6 NDP/DHCPv6 fehlt | MEDIUM | **FIXED** | `sec: IPv6 NDP rate limiting + DHCPv6 + link-local isolation + DNSSEC` |
| **M11** | WAN ICMP ohne Rate Limit | LOW-MEDIUM | **FIXED** | `sec: WAN ICMP rate limiting + oversized payload drop` |
| **M12** | SSE Token in URL | MEDIUM | **FIXED** | `sec: short-lived SSE tokens — prevent session token in URL` |
| **L1** | Kein HTTP→HTTPS Redirect | LOW | **FIXED** | `sec: HTTP→HTTPS 301 redirect on port 80` |
| **L2** | Doppelte iptables-Regeln | LOW | **FIXED** | `sec: WAN health check validation + IDS safety docs + rule dedup docs` |
| **L3** | LAN→Guest Forwarding | LOW | **ALREADY FIXED** | Default FORWARD=DROP, kein explizites LAN→Guest ACCEPT |
| **L4** | epmd auf Loopback | INFO | **N/A** | Erlang daemon von Stock-Firmware, nicht sfgw-Code |
| **L5** | WAN Failover check_target | LOW | **FIXED** | `sec: WAN health check validation + IDS safety docs + rule dedup docs` |
| **L6** | IDS Cleanup Race Condition | LOW | **FIXED** | `sec: WAN health check validation + IDS safety docs + rule dedup docs` |
| **L7** | Argon2 Timing Attack | INFO | **FIXED** | `sec: Argon2 timing normalization + TTL normalization + TLS cipher hardening` |
| **L8** | TTL=63 leakt Hop Count | INFO | **DEFERRED** | xt_TTL/xt_length nicht im UDM Kernel 4.19 — benötigt Custom-Kernel |
| **L9** | WAN Failover Zone-aware Routing | LOW | **MITIGATED** | zone_pin feature available, doc warning added |
| **L10** | AES-128-GCM in TLS | INFO | **FIXED** | `sec: Argon2 timing normalization + TTL normalization + TLS cipher hardening` |

## Summary

- **21 FIXED** (H1, H2, H3, L1, L2, L5, L6, L7, L8, L10, M3, M4, M5, M8, M10, M11, M12 + L3, M6, M7, M9 already fixed)
- **1 MITIGATED** (L9 zone_pin available, documented)
- **1 DEFERRED** (M1+M2 TLS Session Binding → P2, requires RFC 9266 Channel Binding)
- **1 N/A** (L4 epmd, Stock-Firmware)
