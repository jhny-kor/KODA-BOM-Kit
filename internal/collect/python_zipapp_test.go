package collect

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

func pythonArchiveFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	writer := zip.NewWriter(&b)
	for name, data := range files {
		f, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestPythonZipappUsesBundledMetadata(t *testing.T) {
	data := pythonArchiveFixture(t, map[string]string{".deps/requests/requests-2.32.3.dist-info/METADATA": "Metadata-Version: 2.1\nName: Requests\nVersion: 2.32.3\n\nPrivate description\n", ".deps/requests/requests/__init__.py": "", "requirements.txt": "imaginary==1.0"})
	packages, err := pythonZipappPackages(context.Background(), bytes.NewReader(data), int64(len(data)), "app.pex")
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].PURL != "pkg:pypi/requests@2.32.3" {
		t.Fatalf("unexpected packages %+v", packages)
	}
	if packages[0].Locations.ToSlice()[0].RealPath != "app.pex!/.deps/requests/requests-2.32.3.dist-info/METADATA" {
		t.Fatal("member location missing")
	}
}
func TestPythonZipappRejectsUnsafeOrConflictingMetadata(t *testing.T) {
	for _, files := range []map[string]string{{"../x": "bad"}, {"x.dist-info/METADATA": "Name: x\nName: y\nVersion: 1"}, {"x.dist-info/METADATA": "Name: x\n"}} {
		data := pythonArchiveFixture(t, files)
		if _, err := pythonZipappPackages(context.Background(), bytes.NewReader(data), int64(len(data)), "app.pyz"); err == nil {
			t.Fatal("invalid archive accepted")
		}
	}
}
func TestPythonZipappHonorsSelectedPaths(t *testing.T) {
	root := t.TempDir()
	data := pythonArchiveFixture(t, map[string]string{"x.dist-info/METADATA": "Name: x\nVersion: 1\n"})
	if err := os.WriteFile(filepath.Join(root, "excluded.pyz"), data, 0600); err != nil {
		t.Fatal(err)
	}
	inventory := &sbom.SBOM{}
	inventory.Artifacts.Packages = pkg.NewCollection()
	if err := collectPythonZipapps(context.Background(), inventory, localfs.Plan{Root: root}); err != nil {
		t.Fatal(err)
	}
	if inventory.Artifacts.Packages.PackageCount() != 0 {
		t.Fatal("excluded archive collected")
	}
}

func TestMalformedPythonZipappPreservesOtherPackages(t *testing.T) {
	root := t.TempDir()
	good := pythonArchiveFixture(t, map[string]string{"x.dist-info/METADATA": "Name: x\nVersion: 1\n"})
	for name, data := range map[string][]byte{"good.pyz": good, "bad.pyz": []byte("broken ZIP")} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inventory := &sbom.SBOM{}
	inventory.Artifacts.Packages = pkg.NewCollection()
	if err := collectPythonZipapps(context.Background(), inventory, localfs.Plan{Root: root, Paths: []string{"bad.pyz", "good.pyz"}}); err != nil {
		t.Fatal(err)
	}
	if inventory.Artifacts.Packages.PackageCount() != 1 {
		t.Fatal("valid package lost")
	}
	issues := DeployedCollectionIssues(inventory, root)
	if len(issues) != 1 || issues[0].Collector != pythonZipappCollector || issues[0].Status != "incomplete" || issues[0].Code != "deployment_metadata_unreadable" {
		t.Fatalf("missing partial diagnostic %+v", issues)
	}
}
