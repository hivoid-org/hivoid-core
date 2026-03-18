# Hi Void

<p align="center">
  <img src="logo/hi-logo-white-transparent.png" alt="Hi Void Logo" width="200" />
</p>

Hi Void is a high-performance core for secure, scalable, and efficient proxy networking.

- **Version:** `v0.1.0`
- **License:** `MPL-2.0`

---

## Key Features

- High-performance architecture
- Real-time session management
- UUID-based authentication
- TLS support
- Dynamic configuration
- Structured logging
- Low-latency, high-concurrency design

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
  "server": "",
  "port": 4433,
  "cert": "cert.pem",
  "key": "key.pem",
  "mode": "balanced",
  "obfs": "none",
  "max_conns": 0,
  "allowed_hosts": [],
  "blocked_hosts": [],
  "allowed_uuids": [
    "YOUR-CLIENT-UUID"
  ],
  "debug": false
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

