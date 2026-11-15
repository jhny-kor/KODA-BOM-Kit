//go:build linux

package hostcontext

import (
	"errors"
	"os"
	"path"
	"strings"
	"syscall"
)

// Walk each component with O_NOFOLLOW. This closes the check/open symlink race,
// including an intermediate directory redirected into a network/virtual mount.
func openNoFollow(root *os.Root, name string) (*os.File, error) {
	name = path.Clean(name)
	if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
		return nil, errors.New("invalid target path")
	}
	current, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		fd, openErr := syscall.Openat(int(current.Fd()), part, flags, 0)
		current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = os.NewFile(uintptr(fd), part)
	}
	return current, nil
}
