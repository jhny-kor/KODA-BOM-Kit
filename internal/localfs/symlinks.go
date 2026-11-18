package localfs

import (
	"errors"
	"path"
	"strings"
)

var errOutsidePlan = errors.New("path leaves the permitted scan scope")
var errLinkLimit = errors.New("symbolic link depth exceeded")
var errLinkTraversal = errors.New("symbolic link has an ambiguous target path")

// ResolveIndexedPath translates a root-relative candidate using only links
// observed during preflight. It rejects excluded paths at each hop before
// passing a canonical path to a collector. It does not open the candidate.
func (p Plan) ResolveIndexedPath(name string) (canonical string, terminalLink bool, err error) {
	if name == "" || path.IsAbs(name) {
		return "", false, errOutsidePlan
	}
	if path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || p.ExcludesPath(name) {
		return "", false, errOutsidePlan
	}

	if len(p.links) == 0 {
		return name, false, nil
	}

	parts := strings.Split(name, "/")
	var resolved []string
	linkCount := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return "", terminalLink, errOutsidePlan
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		resolved = append(resolved, part)
		candidate := strings.Join(resolved, "/")
		target, found := p.links[candidate]
		if !found {
			if linkCount > 0 && p.ExcludesPath(candidate) {
				return "", terminalLink, errOutsidePlan
			}
			continue
		}
		if p.ExcludesPath(candidate) {
			return "", terminalLink, errOutsidePlan
		}
		terminalLink = terminalLink || len(parts) == 0
		linkCount++
		if linkCount > 40 {
			return "", terminalLink, errLinkLimit
		}
		if path.IsAbs(target) && p.RootFilesystem {
			target = strings.TrimPrefix(path.Clean(target), "/")
			resolved = resolved[:0]
		} else if path.IsAbs(target) {
			tail, within := relativeLinkTarget(target, p.Root)
			if !within && p.rootAlias != "" && p.rootAlias != p.Root {
				// Build verified this alternate spelling when it resolved the
				// scan root (for example macOS /var and /private/var).
				tail, within = relativeLinkTarget(target, p.rootAlias)
			}
			if !within {
				return "", terminalLink, errOutsidePlan
			}
			target = tail
			resolved = resolved[:0]
		} else {
			resolved = resolved[:len(resolved)-1]
		}
		targetParts := strings.Split(target, "/")
		// Syft normalizes each target before resolving further symlinks. A
		// later ".." could make it visit a different path from the kernel.
		if hasAmbiguousTraversal(targetParts) {
			return "", terminalLink, errLinkTraversal
		}
		parts = append(targetParts, parts...)
	}
	if len(resolved) == 0 {
		return ".", terminalLink, nil
	}
	canonical = strings.Join(resolved, "/")
	if p.ExcludesPath(canonical) {
		return "", terminalLink, errOutsidePlan
	}
	return canonical, terminalLink, nil
}

func hasAmbiguousTraversal(parts []string) bool {
	named := false
	for _, part := range parts {
		switch part {
		case "", ".":
		case "..":
			if named {
				return true
			}
		default:
			named = true
		}
	}
	return false
}

// Check the original prefix before processing "..", so a link cannot leave
// the root and then re-enter through another symlink.
func relativeLinkTarget(target, root string) (string, bool) {
	if target == root {
		return ".", true
	}
	return strings.CutPrefix(target, strings.TrimSuffix(root, "/")+"/")
}
