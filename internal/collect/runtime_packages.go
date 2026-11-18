package collect

import (
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
)

// usrMerged maps top-level directories that are symbolic links into /usr on
// the collecting host ("bin" -> "usr/bin"). Package databases may record the
// old spelling (dpkg: /bin/dash) while procfs reports /usr/bin/dash. Process
// links are compared only when they share the collector's root, so the live
// "/" is the right filesystem to consult.
var usrMerged = func() map[string]string {
	merged := map[string]string{}
	for _, dir := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		if target, err := os.Readlink("/" + dir); err == nil && strings.TrimPrefix(path.Clean(target), "/") == "usr/"+dir {
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
	merged := usrMerged()
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
	merged := usrMerged()
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
