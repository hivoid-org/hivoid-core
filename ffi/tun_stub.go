//go:build !android

package main

// runTunForwarder is a no-op on non-Android platforms.
// On Windows/Linux the SOCKS5 proxy is used directly by applications.
func runTunForwarder(tunFD, socksPort, dnsPort int) {
	// Not applicable on desktop platforms
}
