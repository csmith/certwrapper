package main

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func isMountPoint(path string) (bool, error) {
	var file, dir unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &file); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if err := unix.Statx(unix.AT_FDCWD, filepath.Dir(path), 0, unix.STATX_MNT_ID, &dir); err != nil {
		return false, err
	}

	if file.Mask&dir.Mask&unix.STATX_MNT_ID == 0 {
		// Kernels before 5.8 don't report mount IDs, so only a mount of a different filesystem is detectable.
		return file.Dev_major != dir.Dev_major || file.Dev_minor != dir.Dev_minor, nil
	}
	return file.Mnt_id != dir.Mnt_id, nil
}
