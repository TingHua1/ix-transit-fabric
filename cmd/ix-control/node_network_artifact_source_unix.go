//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openArtifactSourceNoFollow opens the source exactly once with O_NOFOLLOW.
// The descriptor, not a preceding Lstat result, is then hashed and staged.
func openArtifactSourceNoFollow(name string) (*os.File, error) {
	fd, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open local artifact without following symlinks: %w", err)
	}
	return os.NewFile(uintptr(fd), name), nil
}
