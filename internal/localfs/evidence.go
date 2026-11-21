package localfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var errEvidenceChanged = errors.New("evidence is no longer a readable regular file")

// OpenRoot reopens the directory identified by preflight and verifies its identity.
func (p Plan) OpenRoot() (*os.Root, error) {
	root, err := openCanonicalRoot(p.Root)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || p.rootInfo == nil || !os.SameFile(p.rootInfo, info) {
		root.Close()
		return nil, errOutsidePlan
	}
	return root, nil
}

// ResolveLocal has already interpreted the operator's path. Walk that
// canonical spelling from the volume root without following any replacement.
func openCanonicalRoot(name string) (*os.Root, error) {
	volume := filepath.VolumeName(name)
	root, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	relative := strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(name, volume)), "/")
	if relative == "" {
		return root, nil
	}
	dir, err := openRelativeDirectory(root, relative)
	if dir != root {
		root.Close()
	}
	return dir, err
}

// IndexedLinks returns the permitted symbolic links in path order.
func (p Plan) IndexedLinks() []string {
	links := make([]string, 0, len(p.links))
	for name := range p.links {
		if !p.ExcludesPath(name) {
			links = append(links, name)
		}
	}
	sort.Strings(links)
	return links
}

// OpenIndexedRegular uses the preflight link interpretation, then opens the
// canonical path component by component without trusting a new symbolic link.
func (p Plan) OpenIndexedRegular(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	canonical, _, err := p.ResolveIndexedPath(name)
	if err != nil {
		return nil, nil, err
	}
	f, info, err := openIndexedFile(root, canonical)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case info.Mode().Perm()&0444 == 0:
		f.Close()
		return nil, nil, fs.ErrPermission
	case info.Size() > 2<<30:
		f.Close()
		return nil, nil, errEvidenceChanged
	}
	return f, info, nil
}

// OpenIndexedDirectory confines lookup to a directory permitted by preflight.
func (p Plan) OpenIndexedDirectory(root *os.Root, name string) (*os.File, error) {
	canonical, _, err := p.ResolveIndexedPath(name)
	if err != nil {
		return nil, err
	}
	dir, err := openRelativeDirectory(root, canonical)
	if err != nil {
		return nil, err
	}
	if dir != root {
		defer dir.Close()
	}
	return dir.Open(".")
}

// OpenRegularEvidence opens a preflight path beneath root and rejects a
// symlink or a file replaced between the metadata check and the open.
func OpenRegularEvidence(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, errEvidenceChanged
	}
	file, err := openEvidence(root, name)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, errEvidenceChanged
	}
	return file, after, nil
}
