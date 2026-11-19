package collect

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
)

// usrMerged maps top-level directories of root that are symbolic links into
// /usr ("bin" -> "usr/bin"). Package databases may record the old spelling
// (dpkg: /bin/dash) while procfs reports /usr/bin/dash.
var usrMerged = func(root string) map[string]string {
	merged := map[string]string{}
	for _, dir := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		if target, err := os.Readlink(filepath.Join(root, dir)); err == nil && strings.TrimPrefix(path.Clean(target), "/") == "usr/"+dir {
			merged[dir] = "usr/" + dir
		}
	}
	return merged
}

// canonicalPath returns the root-relative path as procfs would report it.
func canonicalPath(p string, merged map[string]string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if first, rest, found := strings.Cut(p, "/"); found {
		if target, ok := merged[first]; ok {
			return target + "/" + rest
		}
	}
	return p
}

// LinkRuntimePackages identifies the installed owner of a mapped file. The
// installed version is never asserted to be the version loaded in memory.
func LinkRuntimePackages(context *model.Context, inventory *sbom.SBOM) {
	if context == nil || inventory == nil || inventory.Artifacts.Packages == nil {
		return
	}
	wanted := map[string]bool{}
	for _, process := range context.ProcessLinks {
		if !process.FilesystemComparable {
			continue
		}
		for _, file := range process.RuntimeFiles {
			wanted[file.Path] = true
		}
	}
	owners := map[string][]pkg.Package{}
	// Process links are compared only when they share the collector's root.
	merged := usrMerged("/")
	for _, component := range inventory.Artifacts.Packages.Sorted() {
		owner, ok := component.Metadata.(pkg.FileOwner)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, filename := range owner.OwnedFiles() {
			filename = canonicalPath(filename, merged)
			if wanted[filename] && !seen[filename] {
				owners[filename] = append(owners[filename], component)
				seen[filename] = true
			}
		}
	}
	for i := range context.ProcessLinks {
		if !context.ProcessLinks[i].FilesystemComparable {
			continue
		}
		for j := range context.ProcessLinks[i].RuntimeFiles {
			file := &context.ProcessLinks[i].RuntimeFiles[j]
			matches := owners[file.Path]
			if len(matches) != 1 {
				continue
			}
			file.Package = matches[0].Name
			file.PURL = matches[0].PURL
			file.InstalledVersion = matches[0].Version
		}
	}
}

const maxUnidentifiedExecutables = 1024

// UnidentifiedExecutables records running executables that no installed
// package owns, that no collector cataloged, and that are not inside a detected
// product's install path. These are the blind spots of the SBOM. Call after
// LinkRuntimePackages.
func UnidentifiedExecutables(context *model.Context, inventory *sbom.SBOM, products []model.Product) {
	if context == nil || inventory == nil || inventory.Artifacts.Packages == nil {
		return
	}
	located := map[string]bool{}
	merged := usrMerged("/")
	for _, component := range inventory.Artifacts.Packages.Sorted() {
		for _, location := range component.Locations.ToSlice() {
			located[canonicalPath(location.RealPath, merged)] = true
		}
	}
	installs := []string{}
	for _, product := range products {
		if p := strings.Trim(path.Clean("/"+product.InstallPath), "/"); p != "" {
			installs = append(installs, p+"/")
		}
	}
	self := os.Getpid()
	byPath := map[string][]int{}
	for _, process := range context.ProcessLinks {
		exe := process.Executable
		if !process.FilesystemComparable || process.ExecutableDeleted || process.PID == self || located[exe] {
			continue
		}
		accounted := slices.ContainsFunc(process.RuntimeFiles, func(f model.RuntimeFile) bool { return f.Path == exe && f.PURL != "" }) ||
			slices.ContainsFunc(installs, func(prefix string) bool { return strings.HasPrefix(exe, prefix) })
		if !accounted {
			byPath[exe] = append(byPath[exe], process.PID)
		}
	}
	for _, exe := range slices.Sorted(maps.Keys(byPath)) {
		if len(context.UnidentifiedExecutables) == maxUnidentifiedExecutables {
			context.Issues = append(context.Issues, model.Issue{Collector: "host-context", Status: "incomplete", Message: "unidentified executable list limit reached"})
			break
		}
		context.UnidentifiedExecutables = append(context.UnidentifiedExecutables, model.UnidentifiedExecutable{Path: exe, PIDs: byPath[exe]})
	}
}

// ExposureByExecutable joins listening sockets, keyed by executable path
// relative to root, to the component that provides that executable.
func ExposureByExecutable(inventory *sbom.SBOM, root string, byExecutable map[string][]model.Socket) Exposure {
	exposure := Exposure{}
	executables := make([]string, 0, len(byExecutable))
	for exe := range byExecutable {
		executables = append(executables, exe)
	}
	for exe, purl := range ExecutablePURLs(inventory, root, executables) {
		for _, socket := range byExecutable[exe] {
			if !slices.Contains(exposure[purl], socket) {
				exposure[purl] = append(exposure[purl], socket)
			}
		}
	}
	return exposure
}

// ExecutablePURLs maps executable paths relative to root to the component
// that provides each: the one installed package owning the file, else the one
// component cataloged at that path (for a Go binary, its main module).
// Ambiguous matches are skipped.
func ExecutablePURLs(inventory *sbom.SBOM, root string, executables []string) map[string]string {
	result := map[string]string{}
	if inventory == nil || inventory.Artifacts.Packages == nil || len(executables) == 0 {
		return result
	}
	merged := usrMerged(root)
	wanted := map[string]bool{}
	for _, exe := range executables {
		wanted[canonicalPath(exe, merged)] = true
	}
	owners, located := map[string][]pkg.Package{}, map[string][]pkg.Package{}
	for _, component := range inventory.Artifacts.Packages.Sorted() {
		if component.PURL == "" {
			continue
		}
		if owner, ok := component.Metadata.(pkg.FileOwner); ok {
			for _, name := range owner.OwnedFiles() {
				if p := canonicalPath(name, merged); wanted[p] {
					owners[p] = append(owners[p], component)
				}
			}
		}
		for _, location := range component.Locations.ToSlice() {
			if p := canonicalPath(location.RealPath, merged); wanted[p] {
				located[p] = append(located[p], component)
			}
		}
	}
	for _, exe := range executables {
		p := canonicalPath(exe, merged)
		candidates := owners[p]
		if len(candidates) == 0 {
			candidates = located[p]
			if len(candidates) > 1 {
				candidates = slices.DeleteFunc(slices.Clone(candidates), func(c pkg.Package) bool {
					meta, ok := c.Metadata.(pkg.GolangBinaryBuildinfoEntry)
					return !ok || meta.MainModule != c.Name
				})
			}
		}
		if len(candidates) == 1 {
			result[exe] = candidates[0].PURL
		}
	}
	return result
}
