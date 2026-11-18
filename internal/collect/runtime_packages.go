package collect

import (
	"path"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
)

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
	for _, component := range inventory.Artifacts.Packages.Sorted() {
		owner, ok := component.Metadata.(pkg.FileOwner)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, filename := range owner.OwnedFiles() {
			filename = strings.TrimPrefix(path.Clean(filename), "/")
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
