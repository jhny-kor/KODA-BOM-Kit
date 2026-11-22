package main

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
)

func TestContainerRuntimeAttributionIncludesNonListeningAndMappedLibraries(t *testing.T) {
	packages := pkg.NewCollection()
	for _, p := range []pkg.Package{
		{Name: "job", Version: "1", PURL: "pkg:deb/debian/job@1", Metadata: pkg.DpkgDBEntry{Files: []pkg.DpkgFileRecord{{Path: "/usr/bin/job"}}}},
		{Name: "library", Version: "2", PURL: "pkg:deb/debian/library@2", Metadata: pkg.DpkgDBEntry{Files: []pkg.DpkgFileRecord{{Path: "/usr/lib/shared.so"}}}},
	} {
		p.SetID()
		packages.Add(p)
	}
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: packages}}
	processes := []model.ProcessLink{
		{PID: 42, Executable: "usr/bin/job", FilesystemComparable: true, RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/job", State: "observed"}, {Path: "usr/lib/shared.so", State: "restart_review", Deleted: true}}},
		{PID: 43, Executable: "usr/bin/job", RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/job", State: "namespace_unknown"}}},
	}
	linkContainerRuntime(processes, inventory, t.TempDir())
	if processes[0].RuntimeFiles[0].PURL != "pkg:deb/debian/job@1" || processes[0].RuntimeFiles[1].InstalledVersion != "2" || processes[0].RuntimeFiles[1].State != "restart_review" || processes[1].RuntimeFiles[0].PURL != "" {
		t.Fatalf("runtime attribution lost scope or evidence: %+v", processes)
	}
}
