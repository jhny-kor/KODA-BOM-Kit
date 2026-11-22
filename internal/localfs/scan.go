// Package localfs builds a bounded, local-only scan plan without following directory links.
package localfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"koda.local/security-sbom-linux/internal/model"
)

var DefaultExcludes = []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers"}

const DefaultMaxFiles int64 = 1_000_000

type Options struct {
	// MaxFiles limits eligible regular files. Zero disables this limit.
	MaxFiles int64
	// FilesAlreadyCounted counts eligible files from previous scan targets.
	FilesAlreadyCounted int64
	// ExcludeDirs contains literal paths to directories below the scan root.
	ExcludeDirs []string
	// RootFilesystem marks the target as another system's "/" (a container
	// root): absolute symbolic links resolve inside the target, as chroot does.
	RootFilesystem bool
}

// FileLimitError reports the first eligible file that would exceed the limit.
type FileLimitError struct {
	Limit    int64
	Observed int64
}

func (e *FileLimitError) Error() string {
	return fmt.Sprintf("filesystem file limit exceeded (limit=%d, observed=%d)", e.Limit, e.Observed)
}

type Plan struct {
	Root  string
	Paths []string
	// ModelHeaderPaths records large weights admitted only for bounded metadata reads.
	ModelHeaderPaths []string
	modelHeaders     map[string]string
	Excluded         []string
	ExcludedDirs     []string
	Issues           []model.Issue
	// RootFilesystem resolves absolute links inside Root (see Options).
	RootFilesystem bool
	links          map[string]string
	rootAlias      string
	rootInfo       os.FileInfo
	deniedPaths    map[string]bool
	patternCount   int
}

// ExcludesPath checks a path relative to the plan root against the scan filters.
func (p Plan) ExcludesPath(relative string) bool {
	if p.deniedPaths == nil {
		return matches(relative, p.Excluded)
	}
	for name := strings.TrimPrefix(filepath.ToSlash(relative), "/"); name != "." && name != ""; name = filepath.ToSlash(filepath.Dir(name)) {
		if p.deniedPaths[name] {
			return true
		}
	}
	return matches(relative, p.Excluded[:p.patternCount])
}

func Within(root, path string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func matches(rel string, patterns []string) bool {
	rel = "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
	for _, p := range patterns {
		p = "/" + strings.TrimPrefix(filepath.ToSlash(p), "/")
		if !strings.ContainsAny(p, globPatternChars) {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				return true
			}
			continue
		}
		if ok, _ := doublestar.Match(p, rel); ok {
			return true
		}
		if ok, _ := doublestar.Match(p+"/**", rel); ok {
			return true
		}
	}
	return false
}
func Build(ctx context.Context, root string, excludes []string) (Plan, error) {
	return BuildWithOptions(ctx, root, excludes, Options{MaxFiles: DefaultMaxFiles})
}

const directoryReadBatch = 256

func walkDirectory(ctx context.Context, root, dir *os.Root, relative string, excluded func(string) bool, visit func(*os.Root, string, fs.FileInfo, error) error) error {
	if dir != root {
		defer dir.Close()
	}
	f, err := dir.Open(".")
	if err != nil {
		return visit(dir, relative, nil, err)
	}
	defer f.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reading names directly preserves evidence of an entry even when its
		// filesystem reports it in readdir but denies the subsequent stat.
		entries, readErr := f.Readdirnames(directoryReadBatch)
		last := errors.Is(readErr, io.EOF) || len(entries) < directoryReadBatch && readErr == nil
		if last {
			f.Close()
		}
		children := make([]string, 0, len(entries))
		for _, entry := range entries {
			name := filepath.ToSlash(filepath.Join(relative, entry))
			if excluded(name) {
				continue
			}
			info, statErr := dir.Lstat(entry)
			err := visit(dir, name, info, statErr)
			if err != nil {
				return err
			}
			if statErr == nil && info.IsDir() {
				children = append(children, name)
			}
		}
		if last && dir != root {
			dir.Close()
		}
		for _, name := range children {
			child, err := openRelativeDirectory(root, name)
			if err != nil {
				err = visit(root, name, nil, err)
			} else {
				err = walkDirectory(ctx, root, child, name, excluded, visit)
			}
			if err != nil {
				return err
			}
		}
		if last {
			return nil
		}
		if readErr != nil {
			return visit(dir, relative, nil, readErr)
		}
	}
}

func BuildWithOptions(ctx context.Context, root string, excludes []string, options Options) (Plan, error) {
	if options.MaxFiles < 0 {
		return Plan{}, fmt.Errorf("maximum file count must be zero (unlimited) or positive")
	}
	abs, e := ResolveLocal(root)
	if e != nil {
		return Plan{}, e
	}
	scanRoot, e := openCanonicalRoot(abs)
	if e != nil {
		return Plan{}, fmt.Errorf("target must be a readable local directory")
	}
	defer scanRoot.Close()
	st, e := scanRoot.Stat(".")
	if e != nil || !st.IsDir() {
		return Plan{}, fmt.Errorf("target must be a readable local directory")
	}
	rootAlias, _ := filepath.Abs(root)
	p := Plan{Root: abs, rootInfo: st, rootAlias: filepath.ToSlash(rootAlias), Excluded: append(append([]string{}, DefaultExcludes...), excludes...), Issues: []model.Issue{}, RootFilesystem: options.RootFilesystem}
	p.ExcludedDirs, e = resolveExcludedDirectories(abs, options.ExcludeDirs)
	if e != nil {
		return p, e
	}
	for _, dir := range p.ExcludedDirs {
		pattern := "/" + LiteralPathPattern(dir)
		// Syft can index a symlink target as a separate root beneath this directory.
		p.Excluded = append(p.Excluded, pattern, pattern+"/**")
	}
	mounts, e := RemoteMounts()
	if e != nil && abs == "/" {
		return p, fmt.Errorf("cannot verify local mounts: %w", e)
	}
	for _, m := range mounts {
		if Within(m, abs) {
			return p, fmt.Errorf("network/virtual filesystem targets are not supported")
		}
		if Within(abs, m) {
			r, _ := filepath.Rel(abs, m)
			pattern := "/" + LiteralPathPattern(r)
			p.Excluded = append(p.Excluded, pattern, pattern+"/**")
		}
	}
	for _, pattern := range p.Excluded {
		if !doublestar.ValidatePattern(pattern) {
			return p, fmt.Errorf("invalid exclude pattern")
		}
	}
	p.patternCount = len(p.Excluded)
	p.deniedPaths = make(map[string]bool)
	deny := func(relative string) {
		p.deniedPaths[relative] = true
		p.Excluded = append(p.Excluded, "/"+LiteralPathPattern(relative))
	}
	auxiliaryLimit := max(DefaultMaxFiles, options.MaxFiles)
	auxiliaryUsed := int64(0)
	reserveAuxiliary := func() error {
		auxiliaryUsed++
		if auxiliaryUsed > auxiliaryLimit {
			return fmt.Errorf("filesystem link and special-entry limit exceeded (limit=%d)", auxiliaryLimit)
		}
		return nil
	}
	hasFilteredEntries := false
	issue := func(path, status, msg string) {
		if len(p.Issues) < 1000 {
			p.Issues = append(p.Issues, model.Issue{Collector: "filesystem", Status: status, Path: filepath.ToSlash(path), Message: msg})
		}
	}
	excluded := func(relative string) bool {
		skip := p.ExcludesPath(relative)
		hasFilteredEntries = hasFilteredEntries || skip
		return skip
	}
	err := walkDirectory(ctx, scanRoot, scanRoot, ".", excluded, func(parent *os.Root, rel string, info fs.FileInfo, err error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if err != nil {
			issue(rel, "permission_denied", "directory entry could not be read")
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if err := reserveAuxiliary(); err != nil {
				return err
			}
			target, err := parent.Readlink(info.Name())
			if err != nil {
				issue(rel, "incomplete", "unresolved symbolic link")
				deny(rel)
				return nil
			}
			if p.links == nil {
				p.links = map[string]string{}
			}
			p.links[filepath.ToSlash(rel)] = filepath.ToSlash(target)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			if err := reserveAuxiliary(); err != nil {
				return err
			}
			deny(rel)
			return nil
		}
		if info.Mode().Perm()&0444 == 0 {
			if err := reserveAuxiliary(); err != nil {
				return err
			}
			issue(rel, "permission_denied", "file has no read permission")
			deny(rel)
			return nil
		}
		if info.Size() > 2<<30 {
			if err := reserveAuxiliary(); err != nil {
				return err
			}
			if modelHeaderCandidate(rel, p.Root) {
				files := options.FilesAlreadyCounted + int64(len(p.Paths)+len(p.ModelHeaderPaths))
				if options.MaxFiles > 0 && files >= options.MaxFiles {
					return &FileLimitError{Limit: options.MaxFiles, Observed: files + 1}
				}
				if p.modelHeaders == nil {
					p.modelHeaders = map[string]string{}
				}
				p.modelHeaders[rel] = rel
				p.ModelHeaderPaths = append(p.ModelHeaderPaths, rel)
			}
			issue(rel, "incomplete", "file exceeds 2 GiB per-file bound")
			deny(rel)
			return nil
		}
		files := options.FilesAlreadyCounted + int64(len(p.Paths)+len(p.ModelHeaderPaths))
		if options.MaxFiles > 0 && files >= options.MaxFiles {
			return &FileLimitError{Limit: options.MaxFiles, Observed: files + 1}
		}
		p.Paths = append(p.Paths, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(p.Paths)
	// Inspect links after the physical walk so forward references, chain
	// exclusions and cycles are checked against the same directory snapshot.
	if err == nil && len(p.links) > 0 {
		links := make([]string, 0, len(p.links))
		for name := range p.links {
			links = append(links, name)
		}
		sort.Strings(links)
		headerPlan := p
		headerPlan.deniedPaths = make(map[string]bool, len(p.deniedPaths))
		for name, denied := range p.deniedPaths {
			if p.modelHeaders[name] == "" {
				headerPlan.deniedPaths[name] = denied
			}
		}
		var denied []string
		for _, name := range links {
			if err = ctx.Err(); err != nil {
				break
			}
			_, _, linkErr := p.ResolveIndexedPath(name)
			if linkErr == nil {
				continue
			}
			if modelHeaderCandidate(name, p.Root) {
				if canonical, _, err := headerPlan.ResolveIndexedPath(name); err == nil && p.modelHeaders[canonical] != "" {
					p.modelHeaders[name] = canonical
					p.ModelHeaderPaths = append(p.ModelHeaderPaths, name)
				}
			}
			message := "unresolved symbolic link"
			if errors.Is(linkErr, errOutsidePlan) || errors.Is(linkErr, errLinkTraversal) {
				message = linkErr.Error()
			}
			issue(name, "incomplete", message)
			denied = append(denied, name)
		}
		for _, name := range denied {
			deny(name)
		}
	}
	if err == nil && strings.ContainsAny(abs, globPatternChars) &&
		(hasFilteredEntries || len(p.Excluded) > len(DefaultExcludes)+len(excludes)) {
		// Syft interpolates the absolute root as a glob prefix. Avoid
		// indexing when that would invalidate any required exclusions.
		return p, fmt.Errorf("scan target with glob special characters cannot safely apply exclusions")
	}

	sort.Strings(p.ModelHeaderPaths)
	return p, err
}
