//go:build !linux

package localfs

import (
	"os"
	"path/filepath"
	"strings"
)

func openRelativeDirectory(root *os.Root, name string) (*os.Root, error) {
	parent := root
	for part := range strings.SplitSeq(name, "/") {
		if part == "." {
			continue
		}
		child, err := openChildDirectory(parent, part)
		if parent != root {
			parent.Close()
		}
		if err != nil {
			return nil, err
		}
		parent = child
	}
	return parent, nil
}

func openChildDirectory(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil || !before.IsDir() {
		return nil, errOutsidePlan
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := child.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		child.Close()
		return nil, errOutsidePlan
	}
	return child, nil
}

func openIndexedFile(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	parent, err := openRelativeDirectory(root, filepath.ToSlash(filepath.Dir(name)))
	if err != nil {
		return nil, nil, err
	}
	if parent != root {
		defer parent.Close()
	}
	return OpenRegularEvidence(parent, filepath.Base(name))
}
