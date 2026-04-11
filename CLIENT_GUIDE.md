# HiVoid Client Configuration Guide (v1.0.0-stable)

This document covers the high-performance client commands, configuration fields, URI behavior, and routing semantics implemented in the HiVoid Core stable release.

---

## 1. Client Commands

### 1.1 Supported Subcommands
- Start tunnel and local proxy stack:
  ```bash
  hivoid-client start --config client.json
  ```
- Start from URI directly:
  ```bash
  hivoid-client start --uri "hivoid://..."
  ```
- Stop running instance:
  ```bash
  hivoid-client stop
  ```
- Show status and approximate uptime:
  ```bash
  hivoid-client status
  ```
- Ping server by multiple connect attempts:
  ```bash
  hivoid-client ping --config client.json -c 4
  ```
- Ping from URI:
  ```bash
  hivoid-client ping --uri "hivoid://..." -c 4
  ```
- Export URI from JSON:
  ```bash
  hivoid-client export --config client.json
  ```
- Expand URI to pretty JSON:
  ```bash
  hivoid-client export --uri "hivoid://..."
  ```
- Print version:
  ```bash
  hivoid-client version
  ```

### 1.2 Important Flags
- start:
  - --config required unless --uri is provided
  - --uri optional alternative to --config
  - --debug enables debug logs
- ping:
  - --config required unless --uri is provided
  - --uri optional alternative to --config
  - -c number of attempts (default 4)
  - --http tests end-to-end HTTP over tunnel (default true)

---

## 2. Full Client JSON Schema

Example with all currently supported fields:

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
  "direct_dns_servers": ["1.1.1.1:53", "8.8.4.4:53"],

  "insecure": false,
  "cert_pin": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",

  "bypass_domains": [".ir", "localhost"],
  "bypass_ips": ["10.0.0.0/8", "192.168.1.0/24"],
  "direct_domains": ["example.com"],
  "direct_ips": ["172.16.0.0/12"],

  "geoip_path": "./geoip.dat",
  "geosite_path": "./geosite.dat",
  "direct_route": ["ir", "category-ir"],
  "direct_geosite": ["category-social-media"],
  "direct_geoip": ["private"],

  "name": "Personal HiVoid"
}
```

---

## 3. Field Reference

### 3.1 Required Core Fields
- uuid: required RFC4122 UUID string.
- server: required hostname or IP.
- port: server QUIC UDP port, 1..65535.

### 3.2 Engine and Transport
- mode: performance, high_performance, stealth, balanced, adaptive.
- obfs: none, random, http, tls, masque, webtransport, ghost.
- pool_size: number of parallel QUIC sessions. Valid range in runtime is 1..16. Default 4.

### 3.3 Local Proxy and DNS
- socks_port: local SOCKS5/HTTP proxy bind port. 0 disables local proxy. Default 1080.
- dns_port: local UDP DNS proxy bind port. 0 disables DNS proxy. Default 0.
- dns_upstream: upstream resolver queried through tunnel for non-bypass lookups. Default 8.8.8.8:53.
- direct_dns_servers: direct resolvers used for bypass traffic.

### 3.4 Security
- insecure:
  - false: normal TLS verification
  - true: skip TLS verification (testing only)
- cert_pin:
  - preferred format: sha256:<64 hex>
  - legacy accepted format: <64 hex>

### 3.5 Smart Routing and GeoData
- bypass_domains: direct-route domain suffix list.
- bypass_ips: direct-route IP/CIDR list.
- direct_domains: additional domain direct list.
- direct_ips: additional IP/CIDR direct list.
- geoip_path and geosite_path: GeoData file paths.
- direct_route: legacy tag list for direct routing via GeoData.
- direct_geosite: explicit geosite direct tags.
- direct_geoip: explicit geoip direct tags.

### 3.6 Profile Label
- name: display label. Default hivoid.

---

## 4. Effective Routing Merge Rules

HiVoid merges legacy and newer routing fields before runtime:

- EffectiveBypassDomains = bypass_domains + direct_domains
- EffectiveBypassIPs = bypass_ips + direct_ips
- EffectiveDirectRouteTags = direct_route + direct_geosite + direct_geoip

Notes:
- Values are trimmed and de-duplicated.
- GeoData expansion happens only if geoip_path/geosite_path are configured and effective tags are not empty.
- Server policy is authoritative. If server blocks a host/tag, client local direct rules cannot override it.

---

## 5. HiVoid URI Scheme

URI format:

```text
hivoid://<uuid>@<host>:<port>[?key=value&...]#<name>
```

Example:

```text
hivoid://550e8400-e29b-41d4-a716-446655440000@vps.com:4433?mode=stealth&obfs=random&socks-port=1080#Home
```

### 5.1 Supported URI Query Keys
- mode
- obfs
- pool-size
- socks-port
- dns-port
- dns-up
- insecure
- cert_pin (preferred)
- cert-pin (legacy accepted in parser)
- bypass-domains
- bypass-ips
- geoip-path
- geosite-path
- direct-route

### 5.2 URI Export Behavior
- export includes non-default values to keep URI compact.
- if all values are default, socks-port is still emitted for a useful URI.
- direct_geosite, direct_geoip, direct_domains, direct_ips, direct_dns_servers are JSON-native fields and are not currently emitted as URI query params.

---

## 6. Runtime Behavior Notes

- Client start builds a session pool first, then starts:
  - local SOCKS5/HTTP proxy if socks_port > 0
  - local DNS proxy if dns_port > 0
- On Unix, shutdown handles SIGINT and SIGTERM.
- On Windows, shutdown handles Ctrl+C (SIGINT).
- Status command reads PID metadata and reports approximate uptime.

---

## 7. Troubleshooting Checklist

- Config validation fails:
  - verify uuid format and port ranges
  - verify mode/obfs names
  - verify cert_pin length and hex format
- DNS proxy not running:
  - ensure dns_port > 0
- Local proxy not running:
  - ensure socks_port > 0
- Bypass rules seem ignored:
  - check effective merged fields
  - verify geoip/geosite files and tags
  - verify server is not blocking same destination
- Ping fails but status is running:
  - check server address/port
  - temporarily test with insecure=true for self-signed certs
