//go:build !unix

package evidencefile

import (
	"errors"
	"os"
	"path/filepath"
)

func Open(name string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return OpenRoot(root, filepath.Base(name))
}

func OpenRoot(root *os.Root, name string) (*os.File, error) {
	expected, err := root.Lstat(name)
	if err != nil || !expected.Mode().IsRegular() {
		return nil, errors.New("expected a local regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		f.Close()
		return nil, errors.New("file changed during open")
	}
	return f, nil
}
