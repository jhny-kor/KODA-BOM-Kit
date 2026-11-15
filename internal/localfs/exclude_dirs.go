package localfs

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const globPatternChars = `\*?[]{}`

var globLiteral = strings.NewReplacer(
	"\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]", "{", "\\{", "}", "\\}",
)

// LiteralPathPattern preserves a filesystem path when passed to a glob matcher.
func LiteralPathPattern(path string) string {
	return globLiteral.Replace(filepath.ToSlash(path))
}

func resolveExcludedDirectories(root string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	// Syft prepends its unescaped absolute scan root to all exclusion globs.
	// Refuse the exact-exclusion scan if that prefix would be interpreted as a pattern.
	if strings.ContainsAny(root, globPatternChars) {
		return nil, fmt.Errorf("--exclude-dir requires a scan target path without glob special characters")
	}
	dirs := make([]string, 0, len(requested))
	for i, name := range requested {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\x00\r\n\t") {
			return nil, fmt.Errorf("--exclude-dir entry %d must be a nonempty directory path", i+1)
		}
		path := filepath.Clean(name)
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		if path == root || !Within(root, path) {
			return nil, fmt.Errorf("--exclude-dir entry %d must be below the scan target", i+1)
		}
		resolved, err := ResolveLocal(path)
		if err != nil || resolved != path {
			return nil, fmt.Errorf("--exclude-dir entry %d must be a local directory without symbolic links", i+1)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("--exclude-dir entry %d must be an existing directory", i+1)
		}
		relative, err := filepath.Rel(root, resolved)
		if err != nil {
			return nil, fmt.Errorf("--exclude-dir entry %d could not be made relative to the scan target", i+1)
		}
		dirs = append(dirs, filepath.ToSlash(relative))
	}
	slices.Sort(dirs)
	return slices.Compact(dirs), nil
}
