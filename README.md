# Hi Void

<p align="center">
  <img src="https://raw.githubusercontent.com/hivoid-org/hivoid-core/refs/heads/main/logo/hi-logo-white-transparent.png" alt="Hi Void Logo" width="200" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.2.0--stable-blue.svg" />
  <img src="https://img.shields.io/badge/license-MPL--2.0-green.svg" />
  <img src="https://img.shields.io/badge/platform-cross--platform-blue.svg" />
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?logo=go" />
  <img src="https://img.shields.io/badge/status-stable-blue.svg" />
</p>
Hi Void is a high-performance core for secure, scalable, and efficient proxy networking.

---

## Documentation

- [Server Configuration Guide](SERVER_GUIDE.md) — Detailed reference for server setup.
- [Client Configuration Guide](CLIENT_GUIDE.md) — Detailed reference for client setup.

## Key Features (v1.2.0-stable)
- **Adaptive Intelligence Engine**: Real-time network path monitoring using Welford's algorithm to track Jitter (RTT StdDev) and automate state transitions.
- **Stateful Persistence**: Baselines and threat scores are persisted to disk (`state.json`), enabling optimal performance immediately after restart without a learning phase.
- **Multi-Server High Availability**: Seamless failover and server ranking across multiple backends with integrated health-check probing.
- **Advanced Obfuscation**: Production-ready support for MASQUE (RFC 9298), WebTransport, and Dynamic Ghost (CBR) with entropy-aware padding.
- **Granular Routing Control**: Refined GeoData routing with dedicated fields for `GeoSite`, `GeoIP`, `Domains`, and `IPs`, plus `Direct DNS` resolver isolation.
- **Active Defense (Anti-Probing)**: Silent drop or TCP-like tarpitting for unauthorized probes, with fallback redirection to standard web services.
- **ISP Throttling Evasion**: Client-side `SessionPool` dynamically multiplexes traffic across independent QUIC tunnels to bypass single-flow speed caps.
- **Hybrid Cryptography**: Post-quantum ready handshakes using X25519 + ML-KEM key exchange.
- **Ecosystem Ready**: Fully synced with HiVoid Hub and Panel for centralized policy management and advanced telemetry visualization.

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
    "mode": "ADAPTIVE",
    "log_level": "info"
  },
  "security": {
    "cert_file": "./cert.pem",
    "key_file": "./key.pem"
  },
  "features": {
    "hot_reload": true,
    "connection_tracking": true,
    "disconnect_expired": true,
    "anti_probe": true
  },
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "email": "user1@example.com",
      "enabled": true,
      "mode": "adaptive",
      "obfs": "masque",
      "pool_size": 8,
      "direct_route": "category-ads",
      "blocked_hosts": "ads.example.com,tracker.io",
      "data_limit": 53687091200,
      "expire_at": "2027-01-01T00:00:00Z"
    }
  ],
  "fallback_addr": "1.1.1.1:443"
}
```

### `client.json`

```json
{
  "uuid": "YOUR-CLIENT-UUID",
  "server": "node1.hivoid-network.com",
  "servers": [
    "node1.hivoid-network.com:4433",
    "node2.hivoid-network.com:4433"
  ],
  "port": 4433,
  "mode": "adaptive",
  "obfs": "masque",
  "pool_size": 8,
  "socks_port": 1080,
  "dns_port": 5353,
  "dns_upstream": "8.8.8.8:53",
  "insecure": false,
  "cert_pin": "6a992d5529f459a44fee58c7332c52707dd5002b9f718c87bbec021694abb522",
  "persistence": true,
  "state_file": "state.json",
  "bypass_domains": ["localhost", "*.ir"],
  "bypass_ips": ["127.0.0.1/32", "192.168.1.0/24"],
  "direct_route": ["category-ads"],
  "direct_dns_servers": ["127.0.0.1:53"],
  "geoip_path": "./geoip.dat",
  "geosite_path": "./geosite.dat",
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
