package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// runStatus handles `hivoid-server status`.
func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server status")
	}
	fs.Parse(args) //nolint:errcheck

	pid, err := readPID()
	if err != nil {
		fmt.Println("HiVoid server is not running.")
		os.Exit(0)
	}

	alive, err := isProcessAlive(pid)
	if err != nil || !alive {
		fmt.Printf("HiVoid server is not running (stale PID %d — removing).\n", pid)
		removePID() //nolint:errcheck
		os.Exit(0)
	}

	uptime := pidFileUptime()
	fmt.Printf("HiVoid server is RUNNING (pid=%d, uptime≈%s)\n", pid, uptime)
	fmt.Println("  Use 'hivoid-server stop' to stop.")
}

// pidFileUptime returns a human-readable uptime string.
func pidFileUptime() string {
	info, err := os.Stat(pidFilePath())
	if err != nil {
		return "unknown"
	}
	d := time.Since(info.ModTime()).Truncate(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}
