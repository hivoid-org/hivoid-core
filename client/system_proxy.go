// Package client — system-wide proxy configuration.
//
// SetSystemProxy configures the operating system to route all HTTP/HTTPS traffic
// (and optionally SOCKS5 traffic) through the local HiVoid proxy listener.
//
// Platform support:
//   - Windows: Internet Settings registry under HKCU
//   - macOS:   networksetup command-line tool
//   - Linux:   exports http_proxy / https_proxy / SOCKS environment variables
//              and writes /etc/environment (requires root)
package client

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ProxyType describes what kind of proxy to configure.
type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeBoth   ProxyType = "both"
)

// SystemProxyConfig holds system proxy settings.
type SystemProxyConfig struct {
	Host      string
	HTTP      int // HTTP/HTTPS proxy port (0 = disabled)
	SOCKS5    int // SOCKS5 proxy port (0 = disabled)
	Bypass    []string // hosts to bypass (e.g. "localhost,127.0.0.1")
}

// EnableSystemProxy routes system traffic through the local proxy at addr:port.
// addr is usually "127.0.0.1".
func EnableSystemProxy(cfg SystemProxyConfig) error {
	switch runtime.GOOS {
	case "windows":
		return enableWindowsProxy(cfg)
	case "darwin":
		return enableMacOSProxy(cfg)
	case "linux":
		return enableLinuxProxy(cfg)
	default:
		return fmt.Errorf("system proxy not supported on %s", runtime.GOOS)
	}
}

// DisableSystemProxy removes the system-level proxy configuration.
func DisableSystemProxy() error {
	switch runtime.GOOS {
	case "windows":
		return disableWindowsProxy()
	case "darwin":
		return disableMacOSProxy()
	case "linux":
		return disableLinuxProxy()
	default:
		return fmt.Errorf("system proxy not supported on %s", runtime.GOOS)
	}
}

// ─── Windows ─────────────────────────────────────────────────────────────────

func enableWindowsProxy(cfg SystemProxyConfig) error {
	// Windows uses "ProxyServer" and "ProxyEnable" in the Internet Settings key.
	// Format: "http=host:port;https=host:port;socks=host:port"
	var parts []string
	if cfg.HTTP > 0 {
		parts = append(parts, fmt.Sprintf("http=%s:%d", cfg.Host, cfg.HTTP))
		parts = append(parts, fmt.Sprintf("https=%s:%d", cfg.Host, cfg.HTTP))
	}
	if cfg.SOCKS5 > 0 {
		parts = append(parts, fmt.Sprintf("socks=%s:%d", cfg.Host, cfg.SOCKS5))
	}
	if len(parts) == 0 {
		return fmt.Errorf("no proxy ports configured")
	}

	proxyServer := strings.Join(parts, ";")
	bypass := strings.Join(append(cfg.Bypass, "<local>"), ";")

	return runRegCommand(
		"add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyServer, "/f",
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f",
		"/v", "ProxyOverride", "/t", "REG_SZ", "/d", bypass, "/f",
	)
}

func disableWindowsProxy() error {
	return runRegCommand(
		"add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f",
	)
}

// runRegCommand executes a reg.exe subcommand with the given arguments.
// Each triplet "/v name /t type /d value /f" must be split into separate
// reg add calls; this helper splits them properly.
func runRegCommand(args ...string) error {
	// The reg add command can only set one value per invocation, so we split.
	key := args[1]
	rest := args[2:]
	for i := 0; i < len(rest); {
		if rest[i] == "/v" && i+5 < len(rest) {
			singleArgs := append([]string{"add", key}, rest[i:i+6]...)
			if err := exec.Command("reg", singleArgs...).Run(); err != nil {
				return fmt.Errorf("reg %v: %w", singleArgs, err)
			}
			i += 6
		} else {
			i++
		}
	}
	return nil
}

// ─── macOS ────────────────────────────────────────────────────────────────────

// macOSNetworkService is the default service name. A real implementation would
// enumerate available services via `networksetup -listallnetworkservices`.
const macOSNetworkService = "Wi-Fi"

func enableMacOSProxy(cfg SystemProxyConfig) error {
	var errs []string

	if cfg.HTTP > 0 {
		if err := networksetup("-setwebproxy", macOSNetworkService,
			cfg.Host, fmt.Sprintf("%d", cfg.HTTP)); err != nil {
			errs = append(errs, "HTTP: "+err.Error())
		}
		if err := networksetup("-setsecurewebproxy", macOSNetworkService,
			cfg.Host, fmt.Sprintf("%d", cfg.HTTP)); err != nil {
			errs = append(errs, "HTTPS: "+err.Error())
		}
		networksetup("-setwebproxystate", macOSNetworkService, "on")   //nolint:errcheck
		networksetup("-setsecurewebproxystate", macOSNetworkService, "on") //nolint:errcheck
	}

	if cfg.SOCKS5 > 0 {
		if err := networksetup("-setsocksfirewallproxy", macOSNetworkService,
			cfg.Host, fmt.Sprintf("%d", cfg.SOCKS5)); err != nil {
			errs = append(errs, "SOCKS5: "+err.Error())
		}
		networksetup("-setsocksfirewallproxystate", macOSNetworkService, "on") //nolint:errcheck
	}

	if len(errs) > 0 {
		return fmt.Errorf("macOS proxy config errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func disableMacOSProxy() error {
	networksetup("-setwebproxystate", macOSNetworkService, "off")          //nolint:errcheck
	networksetup("-setsecurewebproxystate", macOSNetworkService, "off")    //nolint:errcheck
	networksetup("-setsocksfirewallproxystate", macOSNetworkService, "off") //nolint:errcheck
	return nil
}

func networksetup(args ...string) error {
	return exec.Command("networksetup", args...).Run()
}

// ─── Linux ────────────────────────────────────────────────────────────────────

func enableLinuxProxy(cfg SystemProxyConfig) error {
	// On Linux there is no single system-wide proxy API. Instead we print
	// the shell export commands so the user can apply them to their session,
	// and optionally try to write /etc/environment with root.
	var lines []string
	if cfg.HTTP > 0 {
		hp := fmt.Sprintf("%s:%d", cfg.Host, cfg.HTTP)
		lines = append(lines,
			fmt.Sprintf("http_proxy=http://%s", hp),
			fmt.Sprintf("HTTP_PROXY=http://%s", hp),
			fmt.Sprintf("https_proxy=http://%s", hp),
			fmt.Sprintf("HTTPS_PROXY=http://%s", hp),
		)
	}
	if cfg.SOCKS5 > 0 {
		sp := fmt.Sprintf("socks5://%s:%d", cfg.Host, cfg.SOCKS5)
		lines = append(lines,
			fmt.Sprintf("SOCKS_PROXY=%s", sp),
			fmt.Sprintf("socks_proxy=%s", sp),
			fmt.Sprintf("ALL_PROXY=%s", sp),
		)
	}
	if len(cfg.Bypass) > 0 {
		no := strings.Join(cfg.Bypass, ",")
		lines = append(lines,
			fmt.Sprintf("no_proxy=%s", no),
			fmt.Sprintf("NO_PROXY=%s", no),
		)
	}

	// Try to write /etc/environment (succeeds only as root or with sudo)
	content := strings.Join(lines, "\n") + "\n"
	if err := writeFileAsRoot("/etc/environment", content); err != nil {
		// Non-fatal: print instructions instead
		fmt.Printf("[hivoid] Run these exports in your shell session:\n")
		for _, l := range lines {
			fmt.Printf("  export %s\n", l)
		}
	}
	return nil
}

func disableLinuxProxy() error {
	// Remove proxy vars from /etc/environment (best-effort)
	removeFromEtcEnvironment()
	fmt.Println("[hivoid] Proxy variables removed. You may need to restart your session.")
	return nil
}

func writeFileAsRoot(path, content string) error {
	// Use tee via sudo for a cross-distro approach
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}

func removeFromEtcEnvironment() {
	// Use sed to remove proxy-related lines (best-effort, requires sudo)
	proxyVars := []string{
		"http_proxy", "HTTP_PROXY",
		"https_proxy", "HTTPS_PROXY",
		"SOCKS_PROXY", "socks_proxy",
		"ALL_PROXY", "NO_PROXY", "no_proxy",
	}
	pattern := strings.Join(proxyVars, `\|`)
	cmd := exec.Command("sudo", "sed", "-i", "/^"+pattern+"=/d", "/etc/environment")
	cmd.Run() //nolint:errcheck
}
