//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// lockStatusGeneration uses an advisory lock held by an open descriptor. The
// guard file is intentionally retained: process exit closes the descriptor and
// releases the lock, so a crash cannot leave a stale lock behind. Its distinct
// name also means obsolete *.lock files from the former O_EXCL scheme are never
// consulted or removed.
func lockStatusGeneration(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("advisory lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
