# Security Audit Report — secfirstgw-rs v0.4.0

**Date:** 2026-03-20
**Scope:** Full codebase review + live assessment (MGMT 10.0.0.1, WAN 192.168.178.25)
**Target:** UDM Pro (dev/test, nicht Produktion)

---

## Methodology

6 parallele Audits:

1. **Crypto & Auth** — Schlüsselverwaltung, Argon2id, E2EE, Inform-Protokoll, SQLCipher
2. **Input Validation & Injection** — Command Injection, SQL Injection, Path Traversal, XSS, SSRF
3. **Network & Firewall** — Zone-Matrix, Default-Deny, VLAN-Isolation, Rate Limiting, UPnP
4. **Live-Scan MGMT (10.0.0.1)** — Port-Scan, TLS-Check, Security-Headers, iptables-Dump, Listening Sockets
5. **WAN-Scan (192.168.178.25)** — Port-Scan, ICMP, UDP-Probes, Banner Grabbing
6. **Frontend** — E2EE Client, XSS-Vektoren, Token-Handling, Dependencies

---

## CRITICAL / HIGH

### H1 — SSH Lockout Validation prüft nur IPv4

**Severity:** HIGH
**File:** `crates/sfgw-fw/src/iptables/mod.rs:289-310`
**Source:** Network Audit

`validate_no_lockout()` prüft nur `-A SFGW-INPUT` mit `-p tcp --dport 22 -j ACCEPT`.
- IPv6 (ip6tables) wird nicht validiert — IPv6 SSH kann gelockt werden ohne Warnung
- `-p 6` (Protokollnummer statt Name) wird nicht erkannt
- Kein statefulness-Check: wenn iptables-restore klappt aber ip6tables-restore fehlschlägt, kein Rollback

**Empfehlung:** IPv6-Regeln ebenfalls validieren, Protokollnummer 6 als Alias für tcp akzeptieren, atomarer Rollback bei partiellem Fehler.

---

### H2 — Meiste API-Endpoints haben KEIN Rate Limiting

**Severity:** HIGH
**File:** `crates/sfgw-api/src/lib.rs:36-334`
**Source:** Network Audit

Nur auth (10 req/min), setup GET und SSE (120 req/min) haben Limiter.
Alle anderen Endpoints (firewall, vpn, dns, wan, zones, wireless, ids, devices, inform, ddns, qos, upnp, logs, backup/restore) sind unlimitiert.

Ein authentifizierter Angreifer kann:
- Firewall-Regeln spammen
- VPN-Tunnels massenhaft starten/stoppen
- Backup/Restore ohne Limit triggern
- IDS-Event-Export als DoS nutzen

**Empfehlung:** `general_limiter` als globale Middleware auf alle geschützten Routes, strikte Limits für Mutations-Endpoints (Firewall: 5/min, VPN: 10/min, Backup/Restore: 2/min).

---

### H3 — SSH-Credentials adoptierter Geräte im Klartext in DB

**Severity:** MEDIUM-HIGH
**File:** `crates/sfgw-inform/src/state.rs:87-91`
**Source:** Crypto Audit

`UbntDevice.ssh_password` wird als `Option<String>` gespeichert. SQLCipher verschlüsselt die DB, aber bei DB-Key-Kompromittierung sind alle SSH-Credentials exponiert.

Kein Rotationsmechanismus, keine SecureBox-Wrapping, kein Audit-Log bei Credential-Zugriff.

**Empfehlung:** SecureBox wrapping vor Storage, HKDF-basierte Ableitung aus Hardware-Fingerprint + Device-MAC statt Klartext, Rotation bei Adoption, Access-Logging.

---

## MEDIUM

### M1 — TLS Session Binding fehlt in validate_session()

**Severity:** MEDIUM
**File:** `crates/sfgw-api/src/auth.rs:99-149`
**Source:** Crypto Audit

`tls_session` wird in der DB gespeichert aber nie bei Session-Validierung geprüft. Token wird nur gegen IP + Fingerprint validiert.

Session-Token kann auf beliebiger TLS-Verbindung replayed werden (solange IP + User-Agent stimmen).

**Empfehlung:** TLS Session ID aus Request extrahieren und gegen gespeicherten Wert prüfen.

---

### M2 — E2EE Envelope Keys nicht an TLS Session gebunden

**Severity:** MEDIUM
**File:** `crates/sfgw-api/src/e2ee.rs:62-70, 299-337`
**Source:** Crypto Audit

Envelope Key Lookup erfolgt nur per Token, ohne Verifizierung der TLS Session. Zusammen mit M1 ermöglicht das Token-Replay + E2EE-Key-Exfiltration.

**Empfehlung:** Envelope Key an TLS Session ID binden, Mismatch = 401 + IDS Alert.

---

### M3 — DDNS URL-Parameter nicht URL-encoded

**Severity:** MEDIUM
**File:** `crates/sfgw-net/src/ddns.rs:457-460, 510, 567-570`
**Source:** Injection Audit

User-controlled hostname und server werden direkt in `format!()` URLs eingebaut:
```rust
format!("https://{server}/nic/update?hostname={hostname}&myip={ip}")
```

Sonderzeichen (`?`, `&`, `#`, `%`) in hostname/server können URL-Struktur brechen.

DNS-Validierung fängt die meisten Zeichen ab, aber nicht alle URL-unsicheren.

**Empfehlung:** `urlencoding::encode()` für alle User-Parameter in URLs.

---

### M4 — DDNS server Feld nicht gegen interne IPs validiert (SSRF)

**Severity:** LOW-MEDIUM
**File:** `crates/sfgw-net/src/ddns.rs:453`
**Source:** Injection Audit

Admin kann `server = "192.168.1.1"` oder `server = "localhost:8080"` setzen → interne Netzwerk-Probes. TLS-Zertifikat-Validierung begrenzt das Risiko.

**Empfehlung:** Private IP-Ranges und localhost im server-Feld ablehnen.

---

### M5 — UPnP SSDP bindet auf 0.0.0.0:1900

**Severity:** MEDIUM
**File:** `crates/sfgw-fw/src/upnp.rs:567-576`
**Source:** Network Audit

SSDP Socket bindet auf alle Interfaces (`Ipv4Addr::UNSPECIFIED`). Multicast-Membership ist auf LAN-IP beschränkt, aber der Socket selbst akzeptiert Pakete auf allen Interfaces.

HTTP Control Port (5000) ist korrekt auf LAN-IP gebunden.

**Empfehlung:** SSDP Socket auf LAN-Interface binden. Peer-IP-Validierung gegen LAN-CIDR. Firewall-Regel Port 1900/5000/5351 von Nicht-LAN Zonen explizit blocken.

---

### M6 — Default iptables Chain Policies sind ACCEPT

**Severity:** MEDIUM
**File:** Live iptables-Dump
**Source:** Live Scan

INPUT, FORWARD, OUTPUT Policies sind ACCEPT. SFGW-Chains implementieren Default-Deny, aber bei Chain-Flush (Crash, Restart) ist das Gateway komplett offen.

**Empfehlung:** Base-Policies auf DROP setzen für fail-closed Verhalten. OUTPUT kann ACCEPT bleiben.

---

### M7 — rp_filter=0 (Reverse Path Filtering deaktiviert)

**Severity:** MEDIUM
**File:** Kernel sysctl
**Source:** Live Scan

Erlaubt Pakete mit gefälschten Source-Adressen von LAN/DMZ. Spoofing-basierte Angriffe möglich.

**Empfehlung:** `sysctl net.ipv4.conf.all.rp_filter=1` (strict) oder `=2` (loose).

---

### M8 — DNSSEC AD-Flag nicht gesetzt

**Severity:** MEDIUM
**File:** dnsmasq Konfiguration
**Source:** Live Scan

dnsmasq leitet RRSIG Records durch, setzt aber kein AD-Flag. Validation findet nicht statt — Clients können Antworten nicht als DNSSEC-validiert vertrauen.

**Empfehlung:** `dnssec` und `trust-anchor` in dnsmasq-Config aktivieren, oder validierenden Upstream-Resolver verwenden mit `proxy-dnssec`.

---

### M9 — Static File Server liefert keine Security Headers

**Severity:** MEDIUM
**File:** `crates/sfgw-api/src/lib.rs` (tower-http ServeDir)
**Source:** Live Scan

API-Routes haben HSTS, CSP, X-Frame-Options etc. — aber die SPA (`GET /`) wird über `tower_http::services::ServeDir` ohne Security Headers ausgeliefert.

Bedeutet: Haupt-Web-UI-Seite hat keinen HSTS, keinen CSP, kein X-Frame-Options.

**Empfehlung:** Security-Header-Middleware auf alle Routes anwenden (inkl. Static Files), nicht nur API.

---

### M10 — IPv6: Kein NDP Rate Limiting, kein DHCPv6

**Severity:** MEDIUM
**File:** `crates/sfgw-fw/src/iptables/mod.rs:464-545`
**Source:** Network Audit

- ICMPv6 Neighbor Solicitation ohne Limit → NDP Flood möglich
- Kein DHCPv6 (Port 546:547) in Default-Rules
- Kein Link-Local (fe80::/10) Filtering zwischen Zonen

**Empfehlung:** NDP Rate Limiting (`--limit 100/sec`), DHCPv6 Regeln, Link-Local Drop von Nicht-LAN Zonen.

---

### M11 — WAN ICMP Echo Reply ohne Rate Limiting

**Severity:** LOW-MEDIUM
**File:** iptables WAN Rules
**Source:** WAN Scan

50 ICMP Pakete @ 10ms Intervall: 0% Loss. Auch 8KB Payloads werden beantwortet.

Ermöglicht Host-Discovery, ICMP Flood/Amplification, Netzwerk-Reconnaissance.

**Empfehlung:** WAN ICMP Echo Rate Limiting (`--limit 1/s --limit-burst 3`) oder komplett droppen. Payload-Größe auf 1500 Bytes begrenzen.

---

### M12 — SSE Token in URL

**Severity:** MEDIUM
**File:** `web/src/pages/Ids.tsx:200-206`, `web/src/pages/Logs.tsx:102-104`
**Source:** Frontend Audit

EventSource API unterstützt keine Custom Headers. Token wird als Query Parameter gesendet:
```typescript
const url = `/api/v1/events/stream?token=${encodeURIComponent(token)}`
```

Token erscheint in Browser-History, Server-Logs, evtl. Referrer-Headers.

**Empfehlung:** Short-lived SSE Tokens implementieren, Server-Log-Filtering für Token-Parameter.

---

## LOW / INFO

### L1 — Port 80 geschlossen — kein HTTP→HTTPS Redirect

**Source:** Live Scan
Usability-Issue. User die `http://10.0.0.1` eingeben bekommen Connection Refused statt Redirect.

### L2 — Doppelte iptables-Regeln

**Source:** Live Scan
SSH MGMT, DNS LAN/MGMT, WAN DROP jeweils doppelt. Verschwendet Firewall-Zyklen, kein Security-Issue.

### L3 — LAN→Guest Forwarding erlaubt

**Source:** Live Scan
Widerspricht möglicherweise Guest-Isolation-Intent. Verifizieren ob gewollt.

### L4 — epmd (4369) auf Loopback

**Source:** Live Scan
Erlang Port Mapper Daemon auf 127.0.0.1. Nicht extern erreichbar, aber unerwartet. Untersuchen und deaktivieren falls nicht benötigt.

### L5 — WAN Failover check_target nicht gegen interne IPs validiert

**Source:** Network Audit
Health-Check-Poisoning möglich wenn Admin interne IP als check_target setzt.

### L6 — IDS Auto-Block Cleanup Race Condition

**Source:** Network Audit
Zwischen Cleanup-Intervall und Rule-Application können abgelaufene Regeln länger als beabsichtigt aktiv bleiben.

### L7 — Timing-Attack auf Argon2 is_ok()

**Source:** Crypto Audit
Theoretisch: Timing-Unterschied zwischen Hash-Parse-Failure und Hash-Compare-Failure. In der Praxis durch Argon2 Rechenkosten irrelevant.

### L8 — TTL=63 auf WAN leakt Hop Count

**Source:** WAN Scan
Verrät dem Scanner dass das Gerät 1 Hop entfernt ist (Default TTL 64 - 1).

### L9 — WAN Failover: Kein Zone-aware Routing

**Source:** Network Audit
Policy-Routing-Tabellen gelten global ohne Zone-Kontext. Während Failover-Transitions könnte Traffic zwischen Zonen leaken.

### L10 — AES-128-GCM in TLS akzeptiert

**Source:** Live Scan
TLS 1.3 akzeptiert auch TLS_AES_128_GCM_SHA256. Kein Vulnerability, aber für maximale Security-Posture nur AES-256 zulassen.

---

## CLEAN (Kein Finding)

- **SQL Injection:** Überall `rusqlite::params![]`, keine String-Interpolation in SQL
- **Command Injection:** Alle `Command::new()` mit `.args()`, nie Shell-Interpolation
- **XSS:** Kein `dangerouslySetInnerHTML`, React escaped automatisch
- **Path Traversal:** File-Ops nutzen validierte Pfade, keine User-Input-Pfade
- **Externe Ressourcen:** Keine CDN-Links, keine Third-Party-Scripts im Frontend
- **TLS:** 1.3 only, AES-256-GCM + CHACHA20-POLY1305, ECDSA P-256, X25519
- **Zone Matrix:** Default Deny, WAN→any DROP, Guest/DMZ→MGMT DROP
- **VLAN 1 Void Sink:** Korrekt geblockt, nie gebridgt
- **Custom Zone→MGMT:** Hardcoded DROP, nicht konfigurierbar
- **Port Forwards:** Nur WAN-Interfaces, FORWARD-Rules ebenfalls WAN-restricted
- **Inform:** Nur MGMT-Zone (Port 8080)
- **SecureBox:** mlock/madvise(DONTDUMP)/zeroize korrekt, ephemeral key pro Instanz
- **Hybrid PQ Crypto:** X25519 + ML-KEM-1024, Ed25519 + ML-DSA-65 korrekt
- **Decompression Bomb Protection:** Snappy/zlib auf 10 MiB limitiert
- **WAN TCP/UDP Angriffsfläche:** Null — alle Ports silent-dropped
- **Error Responses:** Keine Stack Traces, keine Versions-Info, keine internen Pfade
- **Frontend Dependencies:** Minimal (5 prod deps), alle aktuell, keine bekannten CVEs
- **TypeScript:** Strict Mode, noUnusedLocals, noUnusedParameters
- **SYN Cookies:** Aktiv

---

## Fix Status

| ID | Finding | Status | Commit |
|----|---------|--------|--------|
| **H2** | Rate Limiting auf alle API-Endpoints | **FIXED** | `sec: tiered rate limiting — critical mutations 5/min` |
| **M6** | Default Chain Policies auf DROP | **ALREADY FIXED** | `FirewallPolicy::default()` setzt INPUT=DROP, FORWARD=DROP seit Erstimplementierung. Live-Scan war pre-install State. |
| **M7** | rp_filter=1 setzen | **ALREADY FIXED** | `clean-and-install.sh` setzt `net.ipv4.conf.all.rp_filter=1` seit Erstimplementierung. Live-Scan war pre-install State. |
| **M9** | Security Headers auf Static Files | **ALREADY FIXED** | `security_headers_middleware` ist als `.layer()` auf Root-Router, wirkt auf alle Routes inkl. fallback ServeDir. |
| **H1** | SSH Lockout Validation IPv6 | **FIXED** | `sec: SSH lockout validation — IPv6 + protocol number 6 alias` |
| **H3** | SSH Credentials SecureBox wrapping | OPEN | |
| **M1** | TLS Session Binding fehlt in validate_session() | OPEN | |
| **M2** | E2EE Envelope Keys nicht an TLS Session gebunden | OPEN | |
| **M3** | DDNS URL-Parameter nicht URL-encoded | **FIXED** | `sec: DDNS URL encoding + SSRF validation` |
| **M4** | DDNS server Feld nicht gegen interne IPs validiert | **FIXED** | `sec: DDNS URL encoding + SSRF validation` |
| **M5** | UPnP SSDP bindet auf 0.0.0.0:1900 | **FIXED** | `sec: UPnP SSDP bind to LAN IP + peer validation` |
| **M8** | DNSSEC AD-Flag nicht gesetzt | OPEN | |
| **M10** | IPv6: Kein NDP Rate Limiting, kein DHCPv6 | OPEN | |
| **M11** | WAN ICMP Echo Reply ohne Rate Limiting | OPEN | |
| **M12** | SSE Token in URL | OPEN | |
| **L1** | Port 80 kein HTTP→HTTPS Redirect | OPEN | |
| **L2** | Doppelte iptables-Regeln | OPEN | |
| **L3** | LAN→Guest Forwarding erlaubt | OPEN | |
| **L4** | epmd (4369) auf Loopback | OPEN | |
| **L5** | WAN Failover check_target nicht validiert | OPEN | |
| **L6** | IDS Auto-Block Cleanup Race Condition | OPEN | |
| **L7** | Timing-Attack auf Argon2 is_ok() | OPEN | |
| **L8** | TTL=63 auf WAN leakt Hop Count | OPEN | |
| **L9** | WAN Failover: Kein Zone-aware Routing | OPEN | |
| **L10** | AES-128-GCM in TLS akzeptiert | OPEN | |
