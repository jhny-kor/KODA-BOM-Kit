package localfs

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// indexedDescriptor pins a directory or file without opening devices, FIFOs
// or new symlinks. The fallback also supports pre-openat2 Linux kernels.
func indexedDescriptor(root *os.Root, name string, directory bool) (*os.File, error) {
	anchor, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(int(anchor.Fd()), name, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
		fd, err = indexedDescriptorByComponent(int(anchor.Fd()), name, flags)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func indexedDescriptorByComponent(anchor int, name string, flags int) (int, error) {
	parent := anchor
	for {
		part, rest, more := strings.Cut(name, "/")
		currentFlags := flags
		if more {
			currentFlags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, part, currentFlags, 0)
		if parent != anchor {
			unix.Close(parent)
		}
		if err != nil || !more {
			return fd, err
		}
		name, parent = rest, fd
	}
}

func descriptorPath(file *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
}

func openRelativeDirectory(root *os.Root, name string) (*os.Root, error) {
	if name == "." {
		return root, nil
	}
	dir, err := indexedDescriptor(root, name, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return os.OpenRoot(descriptorPath(dir))
}

func openIndexedFile(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	pinned, err := indexedDescriptor(root, name, false)
	if err != nil {
		return nil, nil, err
	}
	defer pinned.Close()
	before, err := pinned.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, errEvidenceChanged
	}
	fd, err := unix.Open(descriptorPath(pinned), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil || !os.SameFile(info, before) {
		f.Close()
		return nil, nil, errEvidenceChanged
	}
	return f, info, nil
}
