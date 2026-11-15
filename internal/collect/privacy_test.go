package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestScrubRemovesPrivateOriginsAuthorsAndJavaExtrasFromAllFormats(t *testing.T) {
	privateURL := "https://private-user:ORIGIN_PASSWORD@packages.example.invalid/private/pkg?token=QUERY_SECRET#FRAGMENT_SECRET"
	values := []pkg.Package{
		{Name: "fixture-npm", Version: "1.2.3", Type: pkg.NpmPkg, Metadata: pkg.NpmPackage{Name: "fixture-npm", Version: "1.2.3", Author: "PRIVATE_AUTHOR", Description: "PRIVATE_DESCRIPTION", URL: privateURL, Homepage: privateURL}},
		{Name: "fixture-python", Version: "1.2.3", Type: pkg.PythonPkg, Metadata: pkg.PythonPackage{Name: "fixture-python", Version: "1.2.3", Author: "PRIVATE_AUTHOR", AuthorEmail: "private-author@example.invalid", DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{URL: privateURL, VCS: "git", CommitID: "abc123"}}},
		{Name: "fixture-composer", Version: "1.2.3", Type: pkg.PhpComposerPkg, Metadata: pkg.PhpComposerInstalledEntry(pkg.PhpComposerLockEntry{Name: "fixture/composer", Version: "1.2.3", Source: pkg.PhpComposerExternalReference{Type: "git", URL: privateURL, Reference: "abc123"}, Dist: pkg.PhpComposerExternalReference{Type: "zip", URL: privateURL}, Authors: []pkg.PhpComposerAuthors{{Name: "PRIVATE_AUTHOR", Email: "private-author@example.invalid"}}, Description: "PRIVATE_DESCRIPTION", NotificationURL: privateURL, Homepage: privateURL})},
		{Name: "fixture-java", Version: "1.2.3", Type: pkg.JavaPkg, Metadata: pkg.JavaArchive{Manifest: &pkg.JavaManifest{Main: pkg.KeyValues{{Key: "Implementation-Version", Value: "1.2.3"}, {Key: "Build-Secret", Value: "MANIFEST_SECRET"}}}}},
	}
	packages := pkg.NewCollection()
	for i := range values {
		values[i].Locations = file.NewLocationSet(file.NewLocation("/fixture/metadata"))
		values[i].SetID()
		packages.Add(values[i])
	}
	originalIDs := map[string]string{}
	for _, p := range packages.Sorted() {
		originalIDs[p.Name] = string(p.ID())
	}
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: packages}, Source: source.Description{ID: "fixture", Name: "fixture", Metadata: source.DirectoryMetadata{Path: "."}}, Descriptor: sbom.Descriptor{Name: "koda-sbom", Version: "test"}}
	Scrub(inventory)
	for _, p := range inventory.Artifacts.Packages.Sorted() {
		if originalIDs[p.Name] != string(p.ID()) {
			t.Fatalf("package ID changed for %s", p.Name)
		}
		if p.Version != "1.2.3" {
			t.Fatal("identity version removed")
		}
	}
	dir := t.TempDir()
	if err := WriteSBOMs(dir, "both", inventory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inventory.syft.json", "sbom.cdx.json", "sbom.spdx.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, secret := range []string{"PRIVATE_AUTHOR", "PRIVATE_DESCRIPTION", "private-author@example.invalid", "private-user", "ORIGIN_PASSWORD", "QUERY_SECRET", "FRAGMENT_SECRET", "MANIFEST_SECRET"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s leaks %s", name, secret)
			}
		}
		for _, packageName := range []string{"fixture-npm", "fixture-python", "fixture-composer", "fixture-java"} {
			if !strings.Contains(text, packageName) {
				t.Errorf("%s lost package %s", name, packageName)
			}
		}
	}
}
