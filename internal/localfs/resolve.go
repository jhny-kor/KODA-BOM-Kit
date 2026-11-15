package localfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveLocal checks every path component against remote/virtual mounts BEFORE
// lstat/readlink. This also protects explicitly supplied archives and output paths.
// A missing trailing path is allowed for creation; callers validate input type.
func ResolveLocal(input string) (string, error) {
	abs, e := filepath.Abs(input)
	if e != nil {
		return "", e
	}
	mounts, e := RemoteMounts()
	if e != nil {
		return "", fmt.Errorf("cannot verify local filesystem mounts")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	resolved := string(filepath.Separator)
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		candidate := filepath.Join(resolved, part)
		for _, m := range mounts {
			if Within(m, candidate) {
				return "", fmt.Errorf("remote or virtual filesystem path rejected")
			}
		}
		info, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			tail := filepath.Join(append([]string{candidate}, parts...)...)
			for _, m := range mounts {
				if Within(m, tail) {
					return "", fmt.Errorf("remote filesystem path rejected")
				}
			}
			return tail, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", fmt.Errorf("symbolic link depth exceeded")
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(resolved, target)
			}
			target = filepath.Clean(target)
			parts = append(strings.Split(strings.TrimPrefix(target, string(filepath.Separator)), string(filepath.Separator)), parts...)
			resolved = string(filepath.Separator)
			continue
		}
		resolved = candidate
	}
	return resolved, nil
}
