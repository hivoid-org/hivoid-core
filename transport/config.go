// Package transport provides QUIC transport configuration for HiVoid.
// All transport-level parameters are centralized here to allow
// consistent tuning between client and server.
package transport

import (
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConfig returns production-tuned QUIC configuration.
// Features enabled:
//   - 0-RTT (controlled, session-ticket-based)
//   - Connection migration
//   - Stream multiplexing
func QUICConfig() *quic.Config {
	return &quic.Config{
		// Maximum number of bidirectional streams per connection (effectively removing the limit)
		MaxIncomingStreams: 1048576,
		// Maximum number of unidirectional streams (effectively removing the limit)
		MaxIncomingUniStreams: 1048576,
		// Keep connections alive with PING frames
		KeepAlivePeriod: 15 * time.Second,
		// Maximum idle time before connection is closed
		MaxIdleTimeout: 90 * time.Second,
		// Allow 0-RTT for session resumption
		Allow0RTT: true,
		// Initial congestion window (packets)
		InitialPacketSize: 1350,
		// Flow control windows — unlocked for maximum throughput (up to 512MB in-flight)
		InitialStreamReceiveWindow:     32 * 1024 * 1024,  // 32 MB per stream
		MaxStreamReceiveWindow:         128 * 1024 * 1024, // 128 MB per stream
		InitialConnectionReceiveWindow: 128 * 1024 * 1024, // 128 MB per connection
		MaxConnectionReceiveWindow:     512 * 1024 * 1024, // 512 MB per connection
		// Explicitly enable dynamic Path MTU Discovery (PMTUD)
		// This quickly finds the path's optimal MTU to prevent IP-level fragmentation
		DisablePathMTUDiscovery: false,
	}
}

// ClientTLSConfig builds the TLS 1.3 configuration for the client.
// TLS 1.3 is the only version allowed (QUIC requirement).
// InsecureSkipVerify should only be true in testing environments.
func ClientTLSConfig(serverName string, insecure bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecure, //nolint:gosec // controlled via CLI flag
		// Allow 0-RTT via session tickets
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		// ALPN: identify as HTTP/3 or HiVoid. "h3" provides maximum stealth
		// as it's the standard for modern web browsers and MASQUE.
		NextProtos: []string{"h3", "hivoid/1"},
	}
}

// ServerTLSConfig builds the TLS 1.3 configuration for the server.
// certFile and keyFile are paths to PEM-encoded certificate and private key.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "hivoid/1"},
	}, nil
}

// ServerTLSConfigFromCert builds TLS config from an already-loaded certificate.
func ServerTLSConfigFromCert(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "hivoid/1"},
	}
}
