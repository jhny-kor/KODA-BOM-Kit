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

// LinkTargets returns the canonical paths that admitted symbolic links resolve to.
func (p Plan) LinkTargets() map[string]bool {
	out := map[string]bool{}
	for _, link := range p.IndexedLinks() {
		if target, _, err := p.ResolveIndexedPath(link); err == nil {
			out[target] = true
		}
	}
	return out
}

// DebianAvailable classifies a file under a Debian-style *-available
// directory, which takes effect only through links in the sibling *-enabled
// directory. read is false when the file should not be read under its own
// name: an admitted link resolves to it (read the link instead), or every
// entry of the *-enabled directory was resolved and none enables it.
// unresolved is true when preflight recorded issues inside the *-enabled
// directory, such as absolute links a directory scan cannot follow; the file
// is then read because whether it is enabled is unknown.
func (p Plan) DebianAvailable(name string, linked map[string]bool) (read, unresolved bool) {
	i := strings.Index(name, "-available/")
	if i < 0 {
		return true, false
	}
	if linked[name] {
		return false, false
	}
	enabled := name[:i] + "-enabled/"
	for _, issue := range p.Issues {
		if strings.HasPrefix(issue.Path, enabled) {
			return true, true
		}
	}
	return false, false
}
