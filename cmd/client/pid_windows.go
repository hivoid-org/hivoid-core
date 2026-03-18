//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// terminateProcess calls TerminateProcess on Windows.
func terminateProcess(proc *os.Process) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(proc.Pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(handle) //nolint:errcheck
	if err := windows.TerminateProcess(handle, 0); err != nil {
		return fmt.Errorf("TerminateProcess: %w", err)
	}
	return nil
}

// isProcessAlive checks if a process is running on Windows.
func isProcessAlive(pid int) (bool, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false, nil
	}
	defer windows.CloseHandle(handle) //nolint:errcheck

	result, _ := windows.WaitForSingleObject(handle, 0)
	return result == 0x00000102, nil // WAIT_TIMEOUT
}
