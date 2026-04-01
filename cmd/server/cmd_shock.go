package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)

// runShock handles `hivoid-server shock`.
func runShock(args []string) {
	fs := flag.NewFlagSet("shock", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server shock")
		fmt.Fprintln(os.Stderr, "Forces all active sessions to reconnect immediately (Shock).")
	}
	fs.Parse(args) //nolint:errcheck

	pid, err := readPID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "HiVoid server is not running (no PID file: %v)\n", err)
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("Sending shock signal (RECONNECT) to process %d...\n", pid)
	// SIGUSR1 is 10 on Linux.
	if err := proc.Signal(syscall.Signal(10)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send signal: %v (Only supported on Linux/Unix)\n", err)
		os.Exit(1)
	}

	fmt.Println("Shock successful. Clients will reconnect shortly.")
}
