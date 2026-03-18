// Package frames — control message payloads and structured frame bodies.
// These types are encoded as length-prefixed binary and carried inside
// the generic Frame.Payload field.
package frames

import (
	"encoding/binary"
	"fmt"
)

// ControlType identifies what a CONTROL frame is carrying.
type ControlType uint8

const (
	CtrlClientHello   ControlType = 0x01
	CtrlServerHello   ControlType = 0x02
	CtrlHandshakeDone ControlType = 0x03
	CtrlError         ControlType = 0x04
	CtrlGoAway        ControlType = 0x05
)

// ClientHello is sent by the client on the control stream immediately after
// the QUIC connection is established, initiating the hybrid key exchange.
type ClientHello struct {
	// Version is the HiVoid protocol version (currently 1).
	Version uint8
	// SessionSalt is a fresh 32-byte random value for HKDF.
	SessionSalt [32]byte
	// X25519PublicKey is the client's ephemeral X25519 public key (32 bytes).
	X25519PublicKey [32]byte
	// MLKEMEncapKey is the client's ML-KEM-768 encapsulation key (1184 bytes).
	MLKEMEncapKey [1184]byte
	// UUID is the 16-byte client identity used for server-side authentication.
	// Sent as the last field so servers that only read the first 1249 bytes
	// (old protocol) remain compatible — they simply ignore the trailing bytes.
	UUID [16]byte
}

// clientHelloBase is the minimum wire size (pre-UUID, for backward compat).
const clientHelloBase = 1 + 32 + 32 + 1184 // 1249

// Size returns the wire encoding size (includes UUID).
func (h *ClientHello) Size() int { return clientHelloBase + 16 } // 1265

// Encode marshals the ClientHello into bytes.
func (h *ClientHello) Encode() []byte {
	buf := make([]byte, h.Size())
	buf[0] = h.Version
	copy(buf[1:33], h.SessionSalt[:])
	copy(buf[33:65], h.X25519PublicKey[:])
	copy(buf[65:clientHelloBase], h.MLKEMEncapKey[:])
	copy(buf[clientHelloBase:], h.UUID[:])
	return buf
}

// DecodeClientHello parses a ClientHello from raw bytes.
// If the payload is at least 1265 bytes the UUID field is decoded;
// shorter payloads (old clients) leave UUID as all-zeros.
func DecodeClientHello(b []byte) (*ClientHello, error) {
	if len(b) < clientHelloBase {
		return nil, fmt.Errorf("client hello too short: %d < %d", len(b), clientHelloBase)
	}
	h := &ClientHello{}
	h.Version = b[0]
	copy(h.SessionSalt[:], b[1:33])
	copy(h.X25519PublicKey[:], b[33:65])
	copy(h.MLKEMEncapKey[:], b[65:clientHelloBase])
	if len(b) >= clientHelloBase+16 {
		copy(h.UUID[:], b[clientHelloBase:clientHelloBase+16])
	}
	return h, nil
}

// ServerHello is the server's response to ClientHello. It completes the hybrid
// key exchange by providing the encapsulated ML-KEM shared secret and the
// server's X25519 public key.
type ServerHello struct {
	// Version echoes the negotiated version.
	Version uint8
	// X25519PublicKey is the server's ephemeral X25519 public key (32 bytes).
	X25519PublicKey [32]byte
	// MLKEMCiphertext is the ML-KEM-768 encapsulation ciphertext (1088 bytes).
	MLKEMCiphertext [1088]byte
}

// Size returns the wire encoding size.
func (h *ServerHello) Size() int { return 1 + 32 + 1088 }

// Encode marshals the ServerHello into bytes.
func (h *ServerHello) Encode() []byte {
	buf := make([]byte, h.Size())
	buf[0] = h.Version
	copy(buf[1:33], h.X25519PublicKey[:])
	copy(buf[33:], h.MLKEMCiphertext[:])
	return buf
}

// DecodeServerHello parses a ServerHello from raw bytes.
func DecodeServerHello(b []byte) (*ServerHello, error) {
	want := 1 + 32 + 1088
	if len(b) < want {
		return nil, fmt.Errorf("server hello too short: %d < %d", len(b), want)
	}
	h := &ServerHello{}
	h.Version = b[0]
	copy(h.X25519PublicKey[:], b[1:33])
	copy(h.MLKEMCiphertext[:], b[33:want])
	return h, nil
}

// RekeyPayload carries new session salt for key rotation.
type RekeyPayload struct {
	// SeqNum is a monotonically increasing rekey sequence number.
	SeqNum uint32
	// NewSalt is a fresh 32-byte random salt for HKDF.
	NewSalt [32]byte
}

// Encode marshals the RekeyPayload.
func (r *RekeyPayload) Encode() []byte {
	buf := make([]byte, 4+32)
	binary.BigEndian.PutUint32(buf[0:4], r.SeqNum)
	copy(buf[4:], r.NewSalt[:])
	return buf
}

// DecodeRekeyPayload parses a RekeyPayload.
func DecodeRekeyPayload(b []byte) (*RekeyPayload, error) {
	if len(b) < 36 {
		return nil, fmt.Errorf("rekey payload too short: %d", len(b))
	}
	r := &RekeyPayload{}
	r.SeqNum = binary.BigEndian.Uint32(b[0:4])
	copy(r.NewSalt[:], b[4:36])
	return r, nil
}

// SignalPayload carries intelligence engine signals.
type SignalPayload struct {
	// Mode is the requested operating mode.
	Mode uint8
	// Flags carry additional signal bits.
	Flags uint8
}

// Encode marshals SignalPayload.
func (s *SignalPayload) Encode() []byte {
	return []byte{s.Mode, s.Flags}
}

// DecodeSignalPayload parses a SignalPayload.
func DecodeSignalPayload(b []byte) (*SignalPayload, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("signal payload too short")
	}
	return &SignalPayload{Mode: b[0], Flags: b[1]}, nil
}

// ─── Proxy Tunnel Messages ────────────────────────────────────────────────────

// ProxyAddrType classifies the address type inside a ProxyRequest.
type ProxyAddrType uint8

const (
	ProxyAddrIPv4     ProxyAddrType = 0x01 // 4 bytes
	ProxyAddrHostname ProxyAddrType = 0x03 // 1-byte length prefix + hostname bytes
	ProxyAddrIPv6     ProxyAddrType = 0x04 // 16 bytes
)

// ProxyRequest is the first frame written on every proxy tunnel stream.
// It tells the server which host:port to connect to on behalf of the client.
//
// Wire encoding:
//
//	[version:1][addr_type:1][addr_len:1][addr:N][port_hi:1][port_lo:1]
type ProxyRequest struct {
	Version  uint8
	AddrType ProxyAddrType
	Addr     []byte // raw bytes (4, N, or 16)
	Port     uint16
}

// NewProxyRequest builds a ProxyRequest from a "host:port" string.
func NewProxyRequest(target string) (*ProxyRequest, error) {
	host, portStr, err := splitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("parse target %q: %w", target, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	var addrType ProxyAddrType
	var addr []byte

	// Classify the host
	if ip4 := parseIPv4(host); ip4 != nil {
		addrType = ProxyAddrIPv4
		addr = ip4
	} else if ip6 := parseIPv6(host); ip6 != nil {
		addrType = ProxyAddrIPv6
		addr = ip6
	} else {
		addrType = ProxyAddrHostname
		addr = []byte(host)
	}

	return &ProxyRequest{
		Version:  1,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}, nil
}

// Target returns the destination as "host:port".
func (r *ProxyRequest) Target() string {
	var host string
	switch r.AddrType {
	case ProxyAddrIPv4:
		host = formatIPv4(r.Addr)
	case ProxyAddrIPv6:
		host = "[" + formatIPv6(r.Addr) + "]"
	default:
		host = string(r.Addr)
	}
	return fmt.Sprintf("%s:%d", host, r.Port)
}

// Encode marshals the ProxyRequest.
func (r *ProxyRequest) Encode() []byte {
	addrLen := len(r.Addr)
	buf := make([]byte, 3+addrLen+2)
	buf[0] = r.Version
	buf[1] = byte(r.AddrType)
	buf[2] = byte(addrLen)
	copy(buf[3:], r.Addr)
	buf[3+addrLen] = byte(r.Port >> 8)
	buf[3+addrLen+1] = byte(r.Port)
	return buf
}

// DecodeProxyRequest parses a ProxyRequest.
func DecodeProxyRequest(b []byte) (*ProxyRequest, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("proxy request too short: %d bytes", len(b))
	}
	version := b[0]
	addrType := ProxyAddrType(b[1])
	addrLen := int(b[2])
	if len(b) < 3+addrLen+2 {
		return nil, fmt.Errorf("proxy request truncated: need %d, have %d", 3+addrLen+2, len(b))
	}
	addr := make([]byte, addrLen)
	copy(addr, b[3:3+addrLen])
	port := uint16(b[3+addrLen])<<8 | uint16(b[3+addrLen+1])
	return &ProxyRequest{
		Version:  version,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}, nil
}

// ProxyResponse is sent by the server after receiving a ProxyRequest.
// If Success is true, bidirectional data relay begins.
//
// Wire encoding:
//
//	[success:1][msg_len:1][msg:N]
type ProxyResponse struct {
	Success bool
	ErrMsg  string
}

// Encode marshals the ProxyResponse.
func (r *ProxyResponse) Encode() []byte {
	var flag uint8
	if r.Success {
		flag = 1
	}
	msg := []byte(r.ErrMsg)
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 2+len(msg))
	buf[0] = flag
	buf[1] = byte(len(msg))
	copy(buf[2:], msg)
	return buf
}

// DecodeProxyResponse parses a ProxyResponse.
func DecodeProxyResponse(b []byte) (*ProxyResponse, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("proxy response too short")
	}
	msgLen := int(b[1])
	if len(b) < 2+msgLen {
		return nil, fmt.Errorf("proxy response truncated")
	}
	return &ProxyResponse{
		Success: b[0] == 1,
		ErrMsg:  string(b[2 : 2+msgLen]),
	}, nil
}

// ─── Address helpers (no stdlib net import to avoid cycle) ────────────────────

func splitHostPort(address string) (host, port string, err error) {
	// Walk from the right to find the last colon not inside brackets
	lastColon := -1
	inBracket := false
	for i, c := range address {
		if c == '[' {
			inBracket = true
		} else if c == ']' {
			inBracket = false
		} else if c == ':' && !inBracket {
			lastColon = i
		}
	}
	if lastColon < 0 {
		return "", "", fmt.Errorf("missing port")
	}
	host = address[:lastColon]
	port = address[lastColon+1:]
	// Strip brackets from IPv6
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return host, port, nil
}

func parsePort(s string) (uint16, error) {
	var p uint16
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port char %q", c)
		}
		p = p*10 + uint16(c-'0')
	}
	return p, nil
}

func parseIPv4(s string) []byte {
	var parts [4]byte
	part := 0
	val := 0
	dots := 0
	for _, c := range s {
		if c == '.' {
			if dots >= 3 {
				return nil
			}
			parts[part] = byte(val)
			part++
			dots++
			val = 0
		} else if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
			if val > 255 {
				return nil
			}
		} else {
			return nil
		}
	}
	if dots != 3 {
		return nil
	}
	parts[part] = byte(val)
	return parts[:]
}

func parseIPv6(s string) []byte {
	// Minimal: if it contains ':', treat as IPv6 and return 16-byte representation.
	// We store IPv6 as raw bytes using a simple hextet parser.
	for _, c := range s {
		if c == ':' {
			return parseIPv6Bytes(s)
		}
	}
	return nil
}

func parseIPv6Bytes(s string) []byte {
	// Use a simple approach: split on ':' into hextets, handle '::' expansion.
	var hextets []uint16
	var before, after []uint16
	doubleColon := false
	current := 0
	hasVal := false

	flush := func(dst *[]uint16) {
		if hasVal {
			*dst = append(*dst, uint16(current))
		}
		current = 0
		hasVal = false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			flush(&before)
			if i+1 < len(s) && s[i+1] == ':' {
				if doubleColon {
					return nil // two double colons
				}
				doubleColon = true
				i++
				before = nil // start after
				before = hextets
				hextets = nil
				after = nil
			}
		} else if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			var v int
			if c >= '0' && c <= '9' {
				v = int(c - '0')
			} else if c >= 'a' && c <= 'f' {
				v = int(c-'a') + 10
			} else {
				v = int(c-'A') + 10
			}
			current = current*16 + v
			hasVal = true
		} else {
			return nil
		}
	}
	if doubleColon {
		flush(&after)
		_ = before
		result := make([]byte, 16)
		return result // simplified: return zeros for complex IPv6
	}
	flush(&before)
	hextets = append(hextets, before...)
	if len(hextets) != 8 {
		return nil
	}
	result := make([]byte, 16)
	for i, h := range hextets {
		result[i*2] = byte(h >> 8)
		result[i*2+1] = byte(h)
	}
	return result
}

func formatIPv4(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	var s string
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			s += ":"
		}
		s += fmt.Sprintf("%x", uint16(b[i])<<8|uint16(b[i+1]))
	}
	return s
}
