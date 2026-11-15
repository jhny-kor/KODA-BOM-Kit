//go:build unix

package localfs

import (
	"os"
	"syscall"
)

func openEvidence(root *os.Root, path string) (*os.File, error) {
	// A file that is replaced by a FIFO after Lstat must not block the scan.
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
