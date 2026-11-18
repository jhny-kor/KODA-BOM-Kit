package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/localfs"
)

func TestSnapFlatpakAndCondaInventory(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		t.Helper()
		name := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(root, p)); err != nil {
			t.Fatal(err)
		}
	}
	put("snap/lxd/28463/meta/snap.yaml", "name: lxd\nversion: '5.21.1-2d13beb'\nbase: core22\napps:\n  lxd:\n    name: nested\n")
	put("snap/lxd/27948/meta/snap.yaml", "name: lxd\nversion: '5.21.0-old'\n")
	link("28463", "snap/lxd/current")
	const commit = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const stale = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	app := "var/lib/flatpak/app/org.example.Tool/x86_64/stable/"
	put(app+commit+"/metadata", "[Application]\nname=org.example.Tool\n")
	put(app+commit+"/files/share/metainfo/org.example.Tool.metainfo.xml", `<component><releases><release version="2.4.1" date="2026-10-01"/><release version="2.4.0"/></releases></component>`)
	put(app+stale+"/metadata", "[Application]\nname=org.example.Tool\n")
	link(commit, app+"active")
	put("opt/conda/conda-meta/openssl-3.0.15-h5eee18b_0.json", `{"name":"openssl","version":"3.0.15","build":"h5eee18b_0","build_number":0,"channel":"https://repo.anaconda.com/pkgs/main","subdir":"linux-64","files":[],"depends":[]}`)
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Scan(context.Background(), plan, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, p := range s.Artifacts.Packages.Sorted() {
		found[p.PURL] = p.FoundBy
	}
	for purl, collector := range map[string]string{
		"pkg:generic/snap/lxd@5.21.1-2d13beb":                                           appBundleCollector,
		"pkg:generic/flatpak/org.example.Tool@2.4.1?arch=x86_64&branch=stable&type=app": appBundleCollector,
	} {
		if found[purl] != collector {
			t.Errorf("%s: found by %q (inventory %v)", purl, found[purl], found)
		}
	}
	if _, ok := found["pkg:generic/snap/lxd@5.21.0-old"]; ok {
		t.Error("inactive snap revision reported")
	}
	if found["pkg:conda/openssl@3.0.15?build=h5eee18b_0&channel=main&subdir=linux-64"] != "conda-meta-cataloger" {
		t.Errorf("conda package PURL missing: %v", found)
	}
	if n := len(found); n != 3 {
		t.Errorf("expected 3 packages (inactive revisions excluded), got %d: %v", n, found)
	}
}
