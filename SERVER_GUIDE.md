# HiVoid Server Configuration Guide (vv1.0.0-stable)

This guide documents the production-grade server commands, configuration schemas, hub integration protocols, and runtime contract details implemented in the HiVoid Core stable release.

---

## 1. Server Commands

### 1.1 Standard Commands
- Start from server config:
  ```bash
  hivoid-server start --config server.json
  ```
- Stop running server:
  ```bash
  hivoid-server stop
  ```
- Force reconnect all active sessions:
  ```bash
  hivoid-server shock
  ```
- List active sessions:
  ```bash
  hivoid-server list
  hivoid-server list --json
  ```
- Show status and uptime:
  ```bash
  hivoid-server status
  ```
- Print version:
  ```bash
  hivoid-server version
  ```

### 1.2 Hub Slave Mode
- Start stateless node managed by Hub:
  ```bash
  hivoid-server hub --config hub.json
  ```

---

## 2. server.json Schema

HiVoid accepts both:
- structured nested style (recommended)
- flat legacy style

### 2.1 Recommended Structured Example

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
  "max_conns": 0,
  "anti_probe": true,
  "fallback_addr": "",
  "geoip_path": "/var/lib/hivoid/geoip.dat",
  "geosite_path": "/var/lib/hivoid/geosite.dat",
  "allowed_hosts": [],
  "blocked_hosts": [],
  "blocked_tags": [],
  "hub": {
    "endpoint": "wss://hub.example.com/api/v1/node",
    "node_token": "token-value",
    "sync_interval_ms": 5000,
    "insecure": false
  },
  "users": [
    {
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "cert_pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "enabled": true,
      "max_connections": 5,
      "max_ips": 2,
      "bind_ip": "",
      "mode": "adaptive",
      "obfs": "none",
      "bandwidth_limit": 2048,
      "data_limit": 10737418240,
      "expire_at": "2026-12-31T23:59:59Z",
      "bytes_in": 0,
      "bytes_out": 0,
      "blocked_hosts": [],
      "blocked_tags": []
    }
  ]
}
```

### 2.2 Flat Legacy Fields Still Supported
- server, port, mode, obfs, cert, key
- max_conns, allowed_hosts, blocked_hosts, allowed_uuids
- anti_probe, fallback_addr, blocked_tags
- geoip_path, geosite_path, users, hub

---

## 3. Field Details and Defaults

### 3.1 Core Server Fields
- server.listen (or server + port): bind address for QUIC listener.
- name: optional label for this server instance. Shows up in diagnostic reports and Hub telemetry.
- mode: performance, high_performance, stealth, balanced, adaptive.
- obfs: none, random, http, tls, masque, webtransport, ghost.
- cert/key: PEM files for TLS.

Defaults applied when omitted:
- port: 4433
- cert: cert.pem
- key: key.pem
- mode: adaptive
- obfs: none

### 3.2 Features
- hot_reload: watch config file and apply runtime updates.
- connection_tracking: track per-user active connections/usage details.
- disconnect_expired: disconnect expired or over-quota users in enforcement loop.

### 3.3 Global Access and Routing Controls
- max_conns: global concurrent connection limit, 0 = unlimited.
- allowed_hosts: optional global allowlist.
- blocked_hosts: global explicit blocklist.
- blocked_tags: global GeoData category/country blocklist.
- fallback_addr: optional host:port fallback for non-HiVoid traffic classification flow.
- anti_probe: anti-scanner protection toggle.
- geoip_path/geosite_path: GeoData sources.

### 3.4 User Policy Fields
- uuid: required user identity.
- email: label for ops dashboards/logs.
- cert_pin: optional expected cert pin metadata per user.
- enabled: soft allow/deny switch.
- max_connections: per-user concurrency limit, 0 = unlimited.
- max_ips: per-user unique source IP limit, 0 = unlimited.
- bind_ip: optional local egress bind override for that user.
- mode/obfs: user policy override.
- bandwidth_limit: per-user shaping value in KB/s for local server.json policies.
- data_limit: total traffic quota bytes, 0 = unlimited.
- expire_at: RFC3339 expiry timestamp.
- bytes_in/bytes_out: persistent counters seed values.
- blocked_hosts/blocked_tags: per-user ACL/GeoData block rules.

Validation notes:
- UUID format is strictly checked.
- Negative values for max/bandwidth/data limits are rejected.
- Invalid mode/obfs values are rejected.
- Invalid expire_at RFC3339 format is rejected.

---

## 4. Hub Slave Mode (hub.json)

Use this for stateless node operation where Hub owns policies/config updates.

Example:

```json
{
  "endpoint": "wss://hub.example.com/api/v1/node",
  "node_token": "HUB_MASTER_TOKEN",
  "cert": "certificate.crt",
  "key": "private.key",
  "sync_interval_ms": 5000,
  "insecure": false,
  "port": 4433
}
```

Fields:
- endpoint: Hub websocket base endpoint.
- node_token: required auth token.
- cert/key: local TLS files used by node listener.
- sync_interval_ms: USAGE send interval in milliseconds.
- insecure: skip TLS verification for Hub dial (testing/private endpoints).
- port: node listen port, default 4433.

Behavior:
- hub mode starts with no local users and waits for Hub SYNC.
- requireKnownPolicy is enabled; unknown UUIDs are rejected.
- runtime policy and forwarder controls are updated from Hub events.

---

## 5. Hub <-> Node Sync Contract

### 5.1 Transport and Auth
- protocol: WebSocket
- preferred endpoint: /api/v1/nodes/ws
- backward-compatible fallback: /api/v1/node/ws
- aliases like /api/v1, /api/v1/node, /api/v1/nodes are normalized by core to the preferred path first
- auth methods sent by node:
  - Authorization: Bearer <token>
  - query token=<token> (fallback)
- node identity:
  - X-Node-ID header and node_id query when available

### 5.2 Messages Hub Sends to Node
- SYNC: user policy snapshot.
- CONFIG_UPDATE: runtime server config patch.
- SHOCK: force reconnect all active clients.
- REVOKE: disconnect specific UUID.
- TLS_INSTALL: install/sync TLS certificates.
- GEODATA_INSTALL: install/validate GeoData files.

### 5.3 Messages Node Sends to Hub
- USAGE:
  - cumulative bytes_in/bytes_out
  - request_pool > 0 means online
  - request_pool = 0 sent on offline transitions to clear presence
  - connected_at and src_ip are normalized and included
- COMMAND_ACK:
  - sent immediately after receiving long-running commands (CONFIG_UPDATE, TLS_INSTALL, GEODATA_INSTALL)
  - includes request_id, kind, accepted status, and received_at
- COMMAND_RESULT:
  - sent when CONFIG_UPDATE finishes (success/failed)
  - includes request_id, kind, status, message, and optional details
- INSTALL_RESULT:
  - includes request_id echo, kind, status, message
  - TLS success includes cert_pin in root and details
- REPORT:
  - sent at startup, periodically, and after relevant runtime changes
  - carries cert_pin and runtime telemetry fields used by node popup
  - includes reported_at (RFC3339) and report_interval_ms for freshness tracking
  - includes popup fields: cpu_usage, ram_usage, uptime, uptime_seconds, connected_at
  - includes separate process and system metrics:
    - process_cpu_usage, process_ram_usage_mb, process_ram_usage_bytes
    - system_cpu_usage, system_ram_usage, system_ram_usage_mb, system_ram_total_mb
  - keeps backward-compatible nested stats payload (active_connections, cpu_percent, memory_percent, uptime_seconds, memory_bytes)

### 5.4 Hub Policy Compatibility Notes
- expire_at or expire_at_unix are normalized to runtime unix expiry.
- enabled and is_active are both accepted.
- legacy routing fields are merged:
  - bypass_domains into direct_domains
  - bypass_ips into direct_ips
  - direct_route into direct_geosite and direct_geoip
- for hub policy bandwidth_limit:
  - current core treats empty bandwidth_unit as kbps and converts to KB/s internally.

---

## 6. Traffic, Persistence, and Diagnostics

- user usage is tracked continuously in UserControlManager.
- persisted to companion file:
  - <config_path>.usage.json
- flushed periodically and on graceful shutdown.

Diagnostic API:
- local endpoint: http://127.0.0.1:23080/sessions
- used by hivoid-server list and list --json

---

## 7. Operations and Troubleshooting

Checklist:
- server fails at start:
  - validate cert/key file paths exist
  - validate JSON and UUID formats
  - validate mode/obfs names
- no sessions in list:
  - verify diagnostic API is reachable on 127.0.0.1:23080
  - verify users and allowlist policy
- users disconnected unexpectedly:
  - check expire_at/data_limit/max_ips/max_connections
  - check disconnect_expired behavior
- hub mode not receiving policies:
  - verify endpoint/token and TLS trust
  - inspect websocket auth and node_id mapping
  - verify hub sends SYNC after connect
- geodata filtering not applied:
  - verify geoip/geosite paths
  - check blocked_tags and runtime logs

Useful commands:
- hivoid-server status
- hivoid-server list --json
- hivoid-server shock
