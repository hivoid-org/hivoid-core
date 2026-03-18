package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// pidFilePath returns the OS-appropriate path for the HiVoid PID file.
func pidFilePath() string {
	if runtime.GOOS == "windows" {
		tmp := os.Getenv("TEMP")
		if tmp == "" {
			tmp = os.Getenv("TMP")
		}
		if tmp == "" {
			tmp = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
		}
		return filepath.Join(tmp, "hivoid.pid")
	}
	return "/tmp/hivoid.pid"
}

// writePID writes the current process PID using atomic write-then-rename.
func writePID() error {
	path := pidFilePath()
	tmp := path + ".tmp"
	content := strconv.Itoa(os.Getpid())

	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return fmt.Errorf("write tmp pid: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("rename pid: %w", err)
	}
	return nil
}

// readPID reads and parses the PID file.
func readPID() (int, error) {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0, fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse pid %q: %w", string(data), err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	return pid, nil
}

// removePID deletes the PID file.
func removePID() error {
	return os.Remove(pidFilePath())
}
