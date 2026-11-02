//go:build !unix && !windows

package main

import (
	"fmt"
	"os"
)

// A platform without POSIX O_NOFOLLOW has no safe implementation here.
func openArtifactSourceNoFollow(name string) (*os.File, error) {
	return nil, fmt.Errorf("local artifact source opening is unsupported on this platform: %s", name)
}
