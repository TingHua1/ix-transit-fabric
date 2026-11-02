//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const lockfileExclusiveLock = 0x00000002

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

// lockStatusGeneration uses a whole-file Windows byte-range lock held by the
// open descriptor. The guard is retained rather than deleted, because closing
// the descriptor releases it even if the process crashes.
func lockStatusGeneration(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped syscall.Overlapped
	r1, _, callErr := procLockFileEx.Call(
		file.Fd(),
		lockfileExclusiveLock,
		0,
		0xffffffff,
		0xffffffff,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		_ = file.Close()
		return nil, fmt.Errorf("LockFileEx: %w", callErr)
	}
	return func() {
		_, _, _ = procUnlockFileEx.Call(
			file.Fd(),
			0,
			0xffffffff,
			0xffffffff,
			uintptr(unsafe.Pointer(&overlapped)),
		)
		_ = file.Close()
	}, nil
}
