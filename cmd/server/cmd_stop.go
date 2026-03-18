package main

import (
	"flag"
	"fmt"
	"os"
)

// runStop handles `hivoid-server stop`.
func runStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server stop")
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
		removePID() //nolint:errcheck
		os.Exit(1)
	}

	if err := terminateProcess(proc); err != nil {
		fmt.Fprintf(os.Stderr, "terminate process %d: %v\n", pid, err)
		os.Exit(1)
	}

	removePID() //nolint:errcheck
	fmt.Println("HiVoid server stopped.")
}
