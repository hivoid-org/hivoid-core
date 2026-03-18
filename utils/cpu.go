// Package utils — CPU capability detection.
// Used to auto-select AES-256-GCM when hardware AES acceleration is available.
package utils

import "golang.org/x/sys/cpu"

// HasAESNI returns true if the CPU has hardware AES-NI acceleration.
// On AES-NI-capable CPUs, AES-256-GCM is faster than ChaCha20-Poly1305.
// On mobile/ARM without AES extensions, ChaCha20-Poly1305 is preferred.
func HasAESNI() bool {
	return cpu.X86.HasAES
}
