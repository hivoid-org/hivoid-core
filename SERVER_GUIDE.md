# HiVoid Server Configuration Guide

This document provides a comprehensive guide for configuring and deploying the HiVoid QUIC proxy server. HiVoid is designed for high-performance, stealthy communication using the QUIC protocol.

---

## 1. Running the Server

The HiVoid server is managed through a sub-command based CLI.

### 1.1 Basic Commands
- **Start the server:**
  ```bash
  hivoid-server start --config server.json
  ```
- **Stop the server:**
  ```bash
  hivoid-server stop
  ```
- **Force Reconnect (Shock):**
  ```bash
  hivoid-server shock
  ```
- **List Active Clients:**
  ```bash
  hivoid-server list
  # Or for JSON output (useful for panels):
  hivoid-server list --json
  ```
- **Check Status:**
  ```bash
  hivoid-server status
  ```

---

## 2. Configuration Schema (`server.json`)

HiVoid supports a structured (recommended) JSON schema for clear organization of server, security, and feature settings.

### 2.1 Recommended Nested Structure

```json
{
  "server": {
    "listen": ":4433",
    "mode": "adaptive",
    "log_level": "info"
  },
  "name": "My-HiVoid-Server",
  "security": {
    "cert_file": "/etc/hivoid/cert.pem",
    "key_file": "/etc/hivoid/key.pem"
  },
  "features": {
    "hot_reload": true,
    "connection_tracking": true,
    "disconnect_expired": true
  },
  "max_conns": 1000,
  "anti_probe": true,
  "fallback_addr": "127.0.0.1:80",
  "geoip_path": "/var/lib/hivoid/geoip.dat",
  "geosite_path": "/var/lib/hivoid/geosite.dat",
  "allowed_hosts": ["*.google.com", "github.com"],
  "blocked_hosts": ["*.ads.doubleclick.net"],
  "blocked_tags": ["category-ads-all"],
  "users": [
    {
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "enabled": true,
      "max_connections": 5,
      "max_ips": 2,
      "blocked_hosts": ["x.com"],
      "blocked_tags": ["us"],
      "bandwidth_limit": 2048,
      "data_limit": 10737418240,
      "expire_at": "2026-12-31T23:59:59Z"
    }
  ]
}
```

---

## 3. Field Definitions

### 3.1 Server Section (`server`)
- **`listen`**: The address and port for the server to listen on (UDP). Use `:port` to listen on all interfaces.
- **`mode`**: Global default engine mode. Values: `performance`, `stealth`, `balanced`, `adaptive`.
- **`log_level`**: Logging verbosity (`debug`, `info`, `warn`, `error`).

### 3.2 Security Section (`security`)
- **`cert_file`**: Path to the PEM-encoded TLS certificate.
- **`key_file`**: Path to the PEM-encoded TLS private key.

### 3.3 Features Section (`features`)
- **`hot_reload`**: If `true`, the server watches the config file and applies changes (users, limits, even TLS certificates) without restarting.
- **`connection_tracking`**: Enables real-time tracking of user connections and traffic.
- **`disconnect_expired`**: If `true`, users will be forcefully disconnected immediately upon account expiration or reaching data limits.

### 3.4 Global Controls
- **`max_conns`**: Maximum concurrent global QUIC streams allowed. `0` means unlimited.
- **`anti_probe`**: Protects the server from active scanners. Unauthorized packets are either silently dropped or lead to a "tarpit".
- **`fallback_addr`**: If an incoming connection identifies as standard HTTP/TLS (not HiVoid), it can be transparently forwarded to this address (e.g., a real web server).
- **`allowed_hosts` / `blocked_hosts`**: Standard wildcard/domain lists to control where clients can connect through this server.
- **`geoip_path` / `geosite_path`**: Path to V2Ray data files for mapping IPs and domains to country codes or categories.
- **`blocked_tags`**: A global list of GeoData tags (e.g., `["ir", "category-ads"]`) to block for all users.

---

## 4. User Management (`users`)

The `users` array allows granular per-client policies.

| Field | Description | Unit / Format |
| :--- | :--- | :--- |
| `uuid` | **Required**. Unique identifier for the client. | RFC 4122 UUID v4 |
| `email` | Descriptive label for the user. | String |
| `enabled` | Whether the user is allowed to connect. | Boolean |
| `max_connections`| Concurrent stream limit for this user. | Integer (0=unlimited) |
| `max_ips` | **Account Sharing Protection**: Limit unique source IPs per UUID. | Integer (0=unlimited) |
| `bind_ip` | Force all outbound traffic for this user through a specific IP. | IP Address |
| `bandwidth_limit`| Shared speed limit for all user streams. | **KB/s** (0=unlimited) |
| `data_limit` | Total allowed traffic quota (In + Out). | **Bytes** (0=unlimited) |
| `expire_at` | Account expiration date. | **RFC3339** (ISO 8601) |
| `mode` / `obfs` | Per-user override for engine behavior. | String |
| `blocked_hosts` | Explicit per-user blacklist for domains/IPs. | Array of strings |
| `blocked_tags` | Per-user GeoData filter (e.g. `["ir"]`). | Array of strings |

---

## 5. Traffic Accounting & Persistence

HiVoid tracks traffic with high precision:
- **`bytes_in`**: Total bytes downloaded by the client.
- **`bytes_out`**: Total bytes uploaded by the client.

**Persistence:**  
Traffic usage is saved to a companion file named `<config-name>.usage.json` periodically and upon graceful shutdown. This allows the server to resume counting after a restart.

---

## 6. Operation Modes (`mode`)

Modes control how the intelligence engine shapes traffic:
- **`performance`**: Minimal processing, maximum throughput.
- **`stealth`**: Aggressive timing jitter and packet size normalization to bypass deep packet inspection (DPI).
- **`balanced`**: High throughput with moderate obfuscation.
- **`adaptive`** (Default): Dynamically adjusts based on path quality and ISP detection risks.

---

## 7. Troubleshooting & Diagnostics

- **List Active Sessions:** Use `hivoid-server list` to see high-level session diagnostics (UUID, Email, Uptime, Traffic) for all currently connected clients.
- **GeoData Diagnostics:** During startup/reload, check logs for `geo filter` messages to verify if your tags (like `category-ads`) were loaded correctly.
- **Smart Reload:** Updating user policies (limits, UUIDs, tags) is instantaneous and does not interrupt existing sessions. The GeoData database is only reloaded if the file paths change.
- **Validation Errors:** If the JSON is invalid, the server will fail to start and print a detailed validation report showing exactly which field (and user index) caused the error.
- **Log Files:** Check logs for "handshake failed" messages which usually indicate a UUID mismatch or expired certificate.
- **Hot Reload:** When updating the config file, always check `hivoid-server status` to ensure the new configuration was accepted.
