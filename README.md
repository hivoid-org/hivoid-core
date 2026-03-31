# Hi Void

<p align="center">
  <img src="https://raw.githubusercontent.com/hivoid-org/hivoid-core/refs/heads/main/logo/hi-logo-white-transparent.png" alt="Hi Void Logo" width="200" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-vv0.10.1-blue.svg" />
  <img src="https://img.shields.io/badge/license-MPL--2.0-green.svg" />
  <img src="https://img.shields.io/badge/platform-cross--platform-blue.svg" />
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?logo=go" />
  <img src="https://img.shields.io/badge/status-beta-yellow.svg" />
</p>
Hi Void is a high-performance core for secure, scalable, and efficient proxy networking.

---

## Documentation

- [Server Configuration Guide](SERVER_GUIDE.md) — Detailed reference for server setup.
- [Client Configuration Guide](CLIENT_GUIDE.md) — Detailed reference for client setup.

## Key Features

- **Next-Gen Obfuscation Suite**: Full support for MASQUE (RFC 9298), WebTransport, and Dynamic Ghost (CBR/Noise) modes.
- **Statistical Stealth (Ghost Mode)**: Dynamic CBR engine with adaptive entropy and intelligent noise generation to defeat advanced scalable DPI.
- **Anti-Probing & Tarpitting**: Immediate silent drop or TCP-like tarpitting for connections that fail strict handshake bounds; fallback redirection (`FallbackAddr`) for unauthorized active scanner probes.
- **ISP Throttling Evasion (Connection Pooling)**: Client-side round-robin `SessionPool` dynamically spreads streams and UDP associates across independent disjoint QUIC tunnels to completely bypass single-flow speed throttling.
- **V2Ray Geographic Bypass**: Native parsing of standard `.dat` domain and IP lists (`geoip` & `geosite`), allowing instant domestic bypass routing (out of tunnel) with intelligent latency-free DNS upstreaming.
- **Comprehensive User Limits**: Server-side Active Quota, Date Expiry, `MaxConnections`, concurrent IP limit (`MaxIPs`), and outgoing egress interface binding (`BindIP`).
- **UDP Relaying**: Fully compliant SOCKS5 UDP Associate natively multiplexed over QUIC streams.
- **High-Performance Architecture**: Scalable, authenticated QUIC tunneling using concurrent connection state management.
- **Dynamic Configuration**: Hot reloading of server listener/TLS certificates and real-time multi-policy user limits snapshotting.

---

## Architecture Overview

Hi Void Core is a standalone service that:

- Handles protocol logic
- Manages active connections
- Processes authentication
- Forwards traffic securely

---

## Requirements

- Linux server (recommended)
- Go 1.24+ (If you want to compile)
- OpenSSL (for certificate generation)
- Firewall access for configured ports
- systemd (recommended for production)

---

## Installation

### 1) Download from Releases (recommended)

Download the latest prebuilt binaries from the project's **Releases** page, extract them, and use `hivoid-server` / `hivoid-client`.

### 2) Or compile from source

#### Clone the repository

```bash
git clone https://github.com/hivoid-org/hivoid-core
cd hivoid-core
```

#### Build binaries

```bash
go build -o hivoid-server ./cmd/server
go build -o hivoid-client ./cmd/client
```

Or use Make targets (recommended):

```bash
make build
make build-server
make build-client
make doctor
```

> If you run `make` inside `dist/`, targets are automatically forwarded to the repository root.

### 3) Generate TLS certificate (example)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=your-domain.com"
```

### 4) Configure server

Edit `server.json` based on your deployment.

### 5) Start server

```bash
./hivoid-server start --config server.json
```

---

## Simple Config Examples

### `server.json`

```json
{
  "server": {
    "listen": ":4433",
    "mode": "PERFORMANCE",
    "log_level": "info"
  },
  "security": {
    "cert_file": "./cert.pem",
    "key_file": "./key.pem"
  },
  "features": {
    "hot_reload": true,
    "connection_tracking": true,
    "disconnect_expired": true
  },
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "email": "user1@example.com",
      "enabled": true,
      "max_connections": 10,
      "max_ips": 3,
      "bind_ip": "192.168.1.50",
      "bandwidth_limit": 1024,
      "data_limit": 53687091200,
      "expire_at": "2027-01-01T00:00:00Z",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "PERFORMANCE",
      "obfs": "none"
    },
    {
      "uuid": "22222222-2222-2222-2222-222222222222",
      "email": "vip@example.com",
      "enabled": true,
      "max_connections": 0,
      "max_ips": 0,
      "bandwidth_limit": 0,
      "expire_at": "",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "HIGH_PERFORMANCE",
      "obfs": "ghost"
    }
  ],
  "max_conns": 0,
  "anti_probe": true,
  "fallback_addr": "1.1.1.1:443",
  "allowed_hosts": [],
  "blocked_hosts": []
}
```

### `client.json`

```json
{
  "uuid": "YOUR-CLIENT-UUID",
  "server": "YOUR_SERVER_IP_OR_DOMAIN",
  "port": 4433,
  "mode": "balanced",
  "obfs": "none",
  "pool_size": 4,
  "socks_port": 1080,
  "dns_port": 5353,
  "dns_upstream": "8.8.8.8:53",
  "insecure": true,
  "bypass_domains": [".ir", "localhost"],
  "bypass_ips": ["10.0.0.0/8"],
  "geoip_path": "./geoip.dat",
  "geosite_path": "./geosite.dat",
  "direct_route": ["ir", "category-ir"],
  "cert_pin": "",
  "name": "My Hi Void"
}
```

> For production with a valid TLS certificate, set `"insecure": false`.

---

## Run Server and Client

1. Start server (on VPS/server machine):

```bash
./hivoid-server start --config server.json
```

2. Start client (on your local machine):

```bash
./hivoid-client start --config client.json
```

3. Set your app proxy to:

- `SOCKS5: 127.0.0.1:1080`
- `HTTP: 127.0.0.1:1080` (if needed)

4. Quick test:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
```

5. Useful commands:

```bash
./hivoid-server status
./hivoid-client status
./hivoid-server stop
./hivoid-client stop
```

---

## Configuration

The core is configured via JSON files, including:

- Listen address/port
- TLS certificate and key
- Allowed UUIDs
- Mode/performance options
- Log level
- Connection limits

---

## Security Notes

- Always enable TLS in production.
- Restrict firewall rules to required ports only.
- Use strong UUIDs.
- Keep dependencies updated.
- Avoid running as root in production.

---

## Monitoring

Structured logs cover:

- Connection events
- Session lifecycle
- Errors and warnings
- Forwarding status

---

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.  
See the `LICENSE` file for details.
