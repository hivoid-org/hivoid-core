# HiVoid Client Configuration Guide

This document is a comprehensive guide for configuring and using the HiVoid client for high-speed, stealthy proxying.

---

## 1. Running the Client

The HiVoid client can be started from a configuration file or a URI.

### Basic Commands
- **Start the proxy tunnel:**
  ```bash
  hivoid-client start --config client.json
  ```
- **Stop a running instance:**
  ```bash
  hivoid-client stop
  ```
- **Check status and uptime:**
  ```bash
  hivoid-client status
  ```
- **Test latency to server:**
  ```bash
  hivoid-client ping --config client.json
  ```

---

## 2. Configuration Schema (`client.json`)

HiVoid client configuration defines how the client connects to the server and handles local traffic routing.

```json
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "server": "vps.example.com",
  "port": 4433,
  "mode": "adaptive",
  "obfs": "none",
  "pool_size": 4,
  "socks_port": 1080,
  "dns_port": 5353,
  "dns_upstream": "8.8.8.8:53",
  "insecure": false,
  "cert_pin": "fde2f8...",
  "bypass_domains": [".ir", "localhost"],
  "bypass_ips": ["10.0.0.0/8", "192.168.1.0/24"],
  "geoip_path": "./geoip.dat",
  "geosite_path": "./geosite.dat",
  "direct_route": ["ir", "category-ir"],
  "name": "Personal HiVoid"
}
```

---

## 3. Field Definitions

### 3.1 Connection Details
- **`uuid`** (**Required**): RFC 4122 UUID v4 that matches an entry in your server's configuration.
- **`server`** (**Required**): IP address or hostname of the HiVoid server.
- **`port`**: UDP port where the server is listening. Default: `4433`.

### 3.2 Engine & Performance
- **`mode`**: Intelligence engine profile (`performance`, `stealth`, `balanced`, `adaptive`).
- **`obfs`**: Traffic obfuscation layer. Values: `none`, `random`, `http`, `tls`, `masque`, `webtransport`, `ghost`.
- **`pool_size`**: Number of parallel QUIC connections to establish to the server. Increasing this helps bypass ISP single-stream throttling. Range: `1–16`. Default: `4`.

### 3.3 Local Proxy Settings
- **`socks_port`**: Local TCP port for the SOCKS5/HTTP dual-protocol proxy. Set to `0` to disable. Default: `1080`.
- **`dns_port`**: Local UDP port for the DNS-over-tunnel proxy. Set to `0` to disable. Default: `0`.
- **`dns_upstream`**: The remote DNS server to query through the tunnel. Default: `8.8.8.8:53`.

### 3.4 Security & Trust
- **`insecure`**: Set to `true` to skip TLS certificate verification. Useful for self-signed certificates or testing.
- **`cert_pin`**: Hex-encoded SHA-256 fingerprint of the expected server TLS certificate. If set, the client only trusts this specific certificate.

### 3.5 Smart Routing (Bypass)
- **`bypass_domains`**: A list of domain suffixes (e.g., `.ir`, `localhost`) to route directly (bypassing the tunnel).
- **`bypass_ips`**: A list of IPs or CIDR notation blocks (e.g., `10.0.0.0/8`) to route locally.
- **`geoip_path` / `geosite_path`**: Path to official V2Ray configuration database files (`geoip.dat` and `geosite.dat`).
- **`direct_route`**: A list of countries or tags (e.g., `["ir", "category-ads"]`) to automatically extract from the database files and bypass.

---

## 4. HiVoid URIs (`hivoid://`)

HiVoid supports sharing configurations through a convenient URI scheme.

**Format:**
```
hivoid://<uuid>@<host>:<port>[?key=value&...]#<name>
```

**Example:**
`hivoid://550e8400-e29b@vps.com:443?mode=stealth&obfs=random&socks_port=1080#Home`

### CLI URI Commands
- **Export URI from JSON file:**
  ```bash
  hivoid-client export --config client.json
  ```
- **Expand URI to Pretty JSON:**
  ```bash
  hivoid-client export --uri "hivoid://..."
  ```

---

## 5. Advanced Optimization

- **Performance Tuning:** For high-bandwidth paths, use `mode: performance` and `pool_size: 8`.
- **Maximum Stealth:** For strict environments, use `mode: stealth` and `obfs: ghost` with `pool_size: 1`. Note that `ghost` mode (Constant Bitrate) consumes data even when idle to hide activity patterns.
- **Low Latency:** Using `mode: adaptive` allows the engine to optimize for the lowest possible RTT by adjusting congestion control parameters in real-time.
