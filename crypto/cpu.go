// Package crypto — CPU capability detection used by AEAD auto-selection.
package crypto

import "golang.org/x/sys/cpu"

// HasAESNI reports whether the current CPU supports hardware AES instruction
// acceleration (Intel AES-NI or ARM Cryptography Extensions).
// When true, AES-256-GCM is preferred. Otherwise, ChaCha20-Poly1305 is used.
func HasAESNI() bool {
	if cpu.X86.HasAES {
		return true
	}
	if cpu.ARM64.HasAES {
		return true
	}
	return false
}
