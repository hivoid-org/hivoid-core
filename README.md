# Hi Void

<p align="center">
  <img src="logo/hi-logo-white-transparent.png" alt="Hi Void Logo" width="200" />
</p>

Hi Void is a high-performance core for secure, scalable, and efficient proxy networking.

- **Version:** `v0.6.1`
- **License:** `MPL-2.0`

---

## Key Features

- High-performance architecture
- Real-time session management
- UUID-based authentication
- TLS support
- Traffic Quota & Volume Control (Data limits)
- User Expiration Management (Auto-disconnect)
- Concurrency Limiting (Max connections per user)
- Dynamic configuration & Hot reload
- Structured logging & Performance tracking

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
      "max_connections": 2,
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
      "max_connections": 10,
      "bandwidth_limit": 0,
      "expire_at": "",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "HIGH_PERFORMANCE",
      "obfs": "tls"
    }
  ],
  "max_conns": 0,
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
  "socks_port": 1080,
  "dns_port": 5353,
  "dns_upstream": "1.1.1.1:53",
  "insecure": true,
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
