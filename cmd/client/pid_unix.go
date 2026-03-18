//go:build !windows

package main

import (
	"os"
	"syscall"
)

// terminateProcess sends SIGTERM to the process on Unix/macOS.
func terminateProcess(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

// isProcessAlive sends signal 0 to check process existence.
func isProcessAlive(pid int) (bool, error) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true, nil
	}
	if err == syscall.ESRCH || err == os.ErrProcessDone {
		return false, nil
	}
	if err == syscall.EPERM {
		return true, nil
	}
	return false, err
}
