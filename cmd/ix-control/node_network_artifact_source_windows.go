//go:build windows

package main

import (
	"fmt"
	"os"
)

// Local artifact installation is already unsupported on Windows. Keep source
// opening fail-closed rather than relying on Windows reparse-point semantics.
func openArtifactSourceNoFollow(name string) (*os.File, error) {
	return nil, fmt.Errorf("local artifact source opening is unsupported on Windows: %s", name)
}
