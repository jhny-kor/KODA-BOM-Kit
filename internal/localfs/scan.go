// Package localfs builds a bounded, local-only scan plan without following directory links.
package localfs

import (
	"context"
	"errors"
	"fmt"
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
	Root         string
	Paths        []string
	Excluded     []string
	ExcludedDirs []string
	Issues       []model.Issue
	// RootFilesystem resolves absolute links inside Root (see Options).
	RootFilesystem bool
	links          map[string]string
	rootAlias      string
}

// ExcludesPath checks a path relative to the plan root against the scan filters.
func (p Plan) ExcludesPath(relative string) bool {
	return matches(relative, p.Excluded)
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

func BuildWithOptions(ctx context.Context, root string, excludes []string, options Options) (Plan, error) {
	if options.MaxFiles < 0 {
		return Plan{}, fmt.Errorf("maximum file count must be zero (unlimited) or positive")
	}
	abs, e := ResolveLocal(root)
	if e != nil {
		return Plan{}, e
	}
	st, e := os.Stat(abs)
	if e != nil || !st.IsDir() {
		return Plan{}, fmt.Errorf("target must be a readable local directory")
	}
	rootAlias, _ := filepath.Abs(root)
	p := Plan{Root: abs, rootAlias: filepath.ToSlash(rootAlias), Excluded: append(append([]string{}, DefaultExcludes...), excludes...), Issues: []model.Issue{}, RootFilesystem: options.RootFilesystem}
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
	hasFilteredEntries := false
	issue := func(path, status, msg string) {
		if len(p.Issues) < 1000 {
			p.Issues = append(p.Issues, model.Issue{Collector: "filesystem", Status: status, Path: filepath.ToSlash(path), Message: msg})
		}
	}
	err := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		rel, _ := filepath.Rel(abs, path)
		if rel != "." && matches(rel, p.Excluded) {
			hasFilteredEntries = true
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err != nil {
			issue(rel, "permission_denied", "directory entry could not be read")
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				issue(rel, "incomplete", "unresolved symbolic link")
				p.Excluded = append(p.Excluded, "/"+LiteralPathPattern(rel))
				return nil
			}
			if p.links == nil {
				p.links = map[string]string{}
			}
			p.links[filepath.ToSlash(rel)] = filepath.ToSlash(target)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			p.Excluded = append(p.Excluded, "/"+LiteralPathPattern(rel))
			return nil
		}
		info, e := d.Info()
		if e != nil {
			issue(rel, "incomplete", "file metadata unavailable")
			return nil
		}
		if info.Mode().Perm()&0444 == 0 {
			issue(rel, "permission_denied", "file has no read permission")
			p.Excluded = append(p.Excluded, "/"+LiteralPathPattern(rel))
			return nil
		}
		if info.Size() > 2<<30 {
			issue(rel, "incomplete", "file exceeds 2 GiB per-file bound")
			p.Excluded = append(p.Excluded, "/"+LiteralPathPattern(rel))
			return nil
		}
		files := options.FilesAlreadyCounted + int64(len(p.Paths))
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
		var denied []string
		for _, name := range links {
			if err = ctx.Err(); err != nil {
				break
			}
			_, _, linkErr := p.ResolveIndexedPath(name)
			if linkErr == nil {
				continue
			}
			message := "unresolved symbolic link"
			if errors.Is(linkErr, errOutsidePlan) || errors.Is(linkErr, errLinkTraversal) {
				message = linkErr.Error()
			}
			issue(name, "incomplete", message)
			denied = append(denied, "/"+LiteralPathPattern(name))
		}
		p.Excluded = append(p.Excluded, denied...)
	}
	if err == nil && strings.ContainsAny(abs, globPatternChars) &&
		(hasFilteredEntries || len(p.Excluded) > len(DefaultExcludes)+len(excludes)) {
		// Syft interpolates the absolute root as a glob prefix. Avoid
		// indexing when that would invalidate any required exclusions.
		return p, fmt.Errorf("scan target with glob special characters cannot safely apply exclusions")
	}

	return p, err
}
