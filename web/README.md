# secfirstgw-rs — Web UI

Management interface for secfirstgw-rs. React + TypeScript + Tailwind CSS.

## Stack

- **React 19** with TypeScript
- **Vite** — dev server and production build
- **Tailwind CSS** — styling
- **React Router** — client-side routing
- **E2EE** — X25519 ECDH session encryption to backend API

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Dashboard | System overview, interface stats, resource usage |
| `/interfaces` | Interfaces | Network interface configuration and status |
| `/wan` | WAN | WAN uplink settings, failover, load balancing |
| `/firewall` | Firewall | Zone-based firewall rules and policies |
| `/network` | Network | VLANs, DHCP, DNS configuration |
| `/vpn` | VPN | WireGuard and OpenVPN tunnel management |
| `/devices` | Devices | Managed device inventory (mTLS adopted) |
| `/ids` | IDS | Intrusion Detection System dashboard |
| `/settings` | Settings | System settings, admin accounts, backups |
| `/login` | Login | Authentication |
| `/setup` | Setup | First-boot setup wizard |

## Development

```bash
npm install
npm run dev
```

Dev server runs on `http://localhost:5173` and proxies API requests to the backend.

## Production Build

```bash
npm run build
```

Output in `dist/` — embedded into the Rust binary at compile time via `include_dir!`.

## Security

- All API communication is end-to-end encrypted (X25519 ECDH + AES-256-GCM)
- Session keys are derived per-connection via HKDF
- No cookies — token-based authentication
- CSP headers enforced by the backend
