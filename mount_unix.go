//go:build unix && !linux

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// isMountPoint only detects a file mounted from a different filesystem, as there's no portable mount ID.
func isMountPoint(path string) (bool, error) {
	file, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	return file.Sys().(*syscall.Stat_t).Dev != dir.Sys().(*syscall.Stat_t).Dev, nil
}
