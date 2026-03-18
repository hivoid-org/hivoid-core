# HiVoid Configuration Manual

This document is a complete, production-oriented reference for configuring HiVoid server and client deployments, including schema variants, precedence rules, hot-reload behavior, validation constraints, and full configuration examples.

---

## Table of Contents

1. [Configuration Models](#1-configuration-models)
2. [Supported Value Sets](#2-supported-value-sets)
3. [Server Configuration (`server.json`)](#3-server-configuration-serverjson)
4. [Per-User Runtime Policy](#4-per-user-runtime-policy)
5. [Client Configuration (`client.json`)](#5-client-configuration-clientjson)
6. [Precedence, Fallback, and Runtime Resolution](#6-precedence-fallback-and-runtime-resolution)
7. [Hot Reload Behavior](#7-hot-reload-behavior)
8. [Validation Rules and Error Conditions](#8-validation-rules-and-error-conditions)
9. [Operational Notes (Performance and Safety)](#9-operational-notes-performance-and-safety)
10. [Ready-to-Use Configuration Profiles](#10-ready-to-use-configuration-profiles)

---

## 1) Configuration Models

HiVoid supports two server config styles:

1. **Nested schema (recommended)**
2. **Legacy flat schema (backward compatible)**

Both are accepted by the loader. The nested schema is preferred for readability and future extensibility.

---

## 2) Supported Value Sets

### 2.1 `mode`

Accepted values (case-insensitive):
- `performance`
- `high_performance`
- `stealth`
- `balanced`
- `adaptive`

Notes:
- `high_performance` is accepted and mapped to the same runtime engine mode as `performance`.
- Unknown values are rejected at validation time.

### 2.2 `obfs`

Accepted values (case-insensitive):
- `none`
- `random`
- `http`
- `tls`

Runtime profile intent:
- `none`: no obfuscation
- `random`: generic randomized padding/jitter
- `http`: HTTP-like shaping profile
- `tls`: more aggressive TLS-like shaping profile

Unknown values are rejected at validation time.

---

## 3) Server Configuration (`server.json`)

## 3.1 Recommended Nested Schema

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
  "users": [],
  "max_conns": 0,
  "allowed_hosts": [],
  "blocked_hosts": []
}
```

## 3.2 Legacy Flat Schema (Still Supported)

```json
{
  "server": "0.0.0.0",
  "port": 4433,
  "cert": "cert.pem",
  "key": "key.pem",
  "mode": "balanced",
  "obfs": "none",
  "max_conns": 0,
  "allowed_hosts": [],
  "blocked_hosts": [],
  "allowed_uuids": [],
  "debug": false
}
```

## 3.3 Server Field Reference

### `server` section (nested)
- `server.listen`  
  Listen address (`host:port` or `:port`).
- `server.mode`  
  Default mode for server-side sessions.
- `server.log_level`  
  Log level hint string.

### `security` section
- `security.cert_file`  
  TLS certificate path.
- `security.key_file`  
  TLS private key path.

### `features` section
- `features.hot_reload`  
  Enables config watcher-based runtime reload.
- `features.connection_tracking`  
  Enables per-user connection and traffic tracking paths.
- `features.disconnect_expired`  
  If true, active relay traffic is terminated when a user reaches expiration.

### Top-level controls
- `max_conns`  
  Global connection cap (`0` = unlimited).
- `allowed_hosts`  
  Outbound allowlist patterns.
- `blocked_hosts`  
  Outbound denylist patterns.
- `allowed_uuids`  
  Explicit UUID allowlist. If omitted and `users` exists, enabled user UUIDs are auto-derived.
- `debug` (legacy flat style)  
  Enables debug logger setup when provided.

---

## 4) Per-User Runtime Policy

Each `users[]` entry supports:

```json
{
  "uuid": "11111111-1111-1111-1111-111111111111",
  "email": "user@example.com",
  "enabled": true,
  "max_connections": 2,
  "bandwidth_limit": 1024,
  "data_limit": 53687091200,
  "expire_at": "2027-01-01T00:00:00Z",
  "bytes_in": 0,
  "bytes_out": 0,
  "mode": "balanced",
  "obfs": "random"
}
```

### 4.1 Field Semantics

- `uuid`  
  Required, valid UUID, unique within `users`.
- `email`  
  Metadata.
- `enabled`  
  If false, user is denied for new connections.
- `max_connections`  
  Per-user concurrent connection cap (`0` = unlimited).
- `bandwidth_limit`  
  Per-user shared **bandwidth speed** limit in **KB/s** (`0` = unlimited).
- `data_limit`  
  Per-user total **traffic volume** quota in **Bytes** (`0` = unlimited).
- `expire_at`  
  RFC3339 timestamp. Empty string means no expiration.
- `bytes_in`, `bytes_out`  
  Usage counters (download/upload). Can seed counters at startup.
- `mode`, `obfs`  
  Per-user overrides for runtime behavior.

### 4.2 Traffic Accounting

HiVoid tracks:
- `bytes_in` (download to client)
- `bytes_out` (upload from client)
- `total_usage = bytes_in + bytes_out`

Implementation characteristics:
- Atomic per-user counters
- Real-time increment during relay
- Periodic flush to disk
- Final graceful flush on shutdown

Persisted usage file:
- `<server-config-path>.usage.json`

---

## 5) Client Configuration (`client.json`)

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
  "name": "My HiVoid"
}
```

### Client Field Semantics

- `uuid` (required)
- `server` (required)
- `port` (`1..65535`)
- `mode` (enum)
- `obfs` (enum)
- `socks_port` (`0..65535`, `0` disables)
- `dns_port` (`0..65535`, `0` disables)
- `dns_upstream`
- `insecure`
- `cert_pin` (64 hex chars when set)
- `name`

---

## 6) Precedence, Fallback, and Runtime Resolution

## 6.1 Schema precedence

- If nested `server` object is present, its values are normalized into runtime fields.
- Security nested fields (`security.cert_file`, `security.key_file`) override flat `cert`/`key`.

## 6.2 User precedence

For a matching user UUID:
1. Per-user `max_connections` overrides global `max_conns`.
2. Per-user `mode` and `obfs` override server defaults.
3. Per-user `bandwidth_limit` is enforced across all user connections (shared speed bucket).
4. Per-user `data_limit` controls the total volume allowed for the user (quota).
5. Per-user expiration controls admission and (optionally) active relay lifetime.

## 6.3 Fallbacks

- Missing user `mode` falls back to server mode.
- Missing user `obfs` falls back to server obfs.
- `bandwidth_limit = 0` means unlimited.
- Empty `expire_at` means no expiration.

---

## 7) Hot Reload Behavior

When `features.hot_reload` is enabled:

- Config file is watched and reloaded on change.
- New config is validated before apply.
- Invalid reload is rejected; previous runtime state remains active.
- Runtime-mutable fields are applied immediately (users, limits, ACLs, behavior flags).

### 7.1 Listener and TLS live reload

The server now reloads these fields live:
- Listener address (`server.listen` / flat `server`+`port`)
- TLS certificate path
- TLS key path

Reload strategy:
- New listener is created first.
- Accept loop is moved to the new endpoint.
- Previous listener is then removed.
- Existing active sessions continue until natural completion.

---

## 8) Validation Rules and Error Conditions

Validation failures reject startup or reload.

### 8.1 Numeric constraints

- `port` in `1..65535`
- `max_conns >= 0`
- `max_connections >= 0`
- `bandwidth_limit >= 0`

### 8.2 Format constraints

- All UUIDs must be syntactically valid.
- User UUIDs must be unique in `users[]`.
- `expire_at` must be valid RFC3339 when non-empty.
- `cert_pin` must be 64 hex chars if provided (client config).

### 8.3 Enum constraints

- Unknown `mode` is invalid.
- Unknown `obfs` is invalid.

---

## 9) Operational Notes (Performance and Safety)

- Per-user traffic counters use atomic operations for low overhead.
- Per-user connection limiting uses lock-light state.
- Bandwidth limiting uses a shared token-bucket per user (not per stream).
- Runtime updates are applied atomically through snapshot replacement.
- Usage is persisted periodically and on graceful shutdown to reduce loss risk.

---

## 10) Ready-to-Use Configuration Profiles

## 10.1 Minimal Production (No User Overrides)

```json
{
  "server": { "listen": ":4433", "mode": "balanced", "log_level": "info" },
  "security": { "cert_file": "./cert.pem", "key_file": "./key.pem" },
  "features": { "hot_reload": true, "connection_tracking": false, "disconnect_expired": false },
  "max_conns": 0,
  "allowed_hosts": [],
  "blocked_hosts": []
}
```

## 10.2 Strict Controlled Access

```json
{
  "server": { "listen": ":4433", "mode": "stealth", "log_level": "info" },
  "security": { "cert_file": "./cert.pem", "key_file": "./key.pem" },
  "features": { "hot_reload": true, "connection_tracking": true, "disconnect_expired": true },
  "allowed_hosts": ["*.example.com", "api.service.local"],
  "blocked_hosts": ["*.malware.test"],
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "email": "ops@example.com",
      "enabled": true,
      "max_connections": 2,
      "bandwidth_limit": 512,
      "expire_at": "2027-01-01T00:00:00Z",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "stealth",
      "obfs": "tls"
    }
  ]
}
```

## 10.3 Multi-Tier Users (All Obfuscation Modes)

```json
{
  "server": { "listen": ":4433", "mode": "balanced", "log_level": "info" },
  "security": { "cert_file": "./cert.pem", "key_file": "./key.pem" },
  "features": { "hot_reload": true, "connection_tracking": true, "disconnect_expired": true },
  "max_conns": 0,
  "allowed_hosts": [],
  "blocked_hosts": [],
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "email": "normal@example.com",
      "enabled": true,
      "max_connections": 2,
      "bandwidth_limit": 512,
      "expire_at": "2027-01-01T00:00:00Z",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "balanced",
      "obfs": "none"
    },
    {
      "uuid": "22222222-2222-2222-2222-222222222222",
      "email": "random@example.com",
      "enabled": true,
      "max_connections": 5,
      "bandwidth_limit": 1024,
      "expire_at": "",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "performance",
      "obfs": "random"
    },
    {
      "uuid": "33333333-3333-3333-3333-333333333333",
      "email": "http@example.com",
      "enabled": true,
      "max_connections": 3,
      "bandwidth_limit": 256,
      "expire_at": "",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "high_performance",
      "obfs": "http"
    },
    {
      "uuid": "44444444-4444-4444-4444-444444444444",
      "email": "tls@example.com",
      "enabled": true,
      "max_connections": 10,
      "bandwidth_limit": 0,
      "expire_at": "",
      "bytes_in": 0,
      "bytes_out": 0,
      "mode": "stealth",
      "obfs": "tls"
    }
  ]
}
```

---

## Quick Checklist Before Deploy

- [ ] TLS files exist and are readable
- [ ] All UUIDs are valid and unique
- [ ] `mode` / `obfs` values are valid
- [ ] No negative limits
- [ ] `expire_at` uses RFC3339 format
- [ ] ACL lists (`allowed_hosts` / `blocked_hosts`) are intentional
- [ ] `hot_reload` and `disconnect_expired` are set according to operations policy

