//go:build linux

package containers

import (
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// whiteout reports an overlayfs whiteout: a character device numbered 0/0.
func whiteout(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0
}

// opaque reports an overlayfs opaque directory, which hides lower layers.
// Rootless storage uses the user. namespace.
func opaque(dir string) bool {
	buf := make([]byte, 4)
	for _, name := range []string{"trusted.overlay.opaque", "user.overlay.opaque"} {
		if n, err := unix.Lgetxattr(dir, name, buf); err == nil && n == 1 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

// FreeBytes returns the space available to the collector below dir.
func FreeBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return 0, false
	}
	return int64(st.Bavail) * st.Bsize, true
}
