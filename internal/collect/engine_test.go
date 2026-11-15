package collect

import (
	"context"
	"encoding/json"
	"koda.local/security-sbom-linux/internal/localfs"
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledPackagesAndOfflineFormats(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		t.Helper()
		name := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(name), 0700)
		if e := os.WriteFile(name, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	put("etc/os-release", "ID=debian\nVERSION_ID=12\nNAME=Debian\n")
	put("var/lib/dpkg/status", "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\nSource: openssl\nMaintainer: Fixture <fixture@example.invalid>\nDescription: fixture\n\n")
	put("app/venv/lib/python3.11/site-packages/demo-1.2.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo\nVersion: 1.2\nLicense: MIT\n")
	put("app/node_modules/@scope/example/package.json", `{"name":"@scope/example","version":"2.3.4","license":"MIT","dependencies":{"absent":"9.9.9"}}`)
	put("app/vendor/composer/installed.json", `{"packages":[{"name":"vendor/example","version":"1.2.3","type":"library","license":["MIT"]}]}`)
	put("app/requirements.txt", "NOT_INSTALLED==88.0\n")
	put("app/composer.lock", `{"packages":[{"name":"not/installed","version":"99.0"}]}`)
	plan, e := localfs.Build(context.Background(), root, nil)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Scan(context.Background(), plan, "test")
	if e != nil {
		t.Fatal(e)
	}
	Scrub(s)
	names := map[string]bool{}
	for _, p := range s.Artifacts.Packages.Sorted() {
		names[p.Name] = true
	}
	for _, n := range []string{"openssl", "demo", "@scope/example", "vendor/example"} {
		if !names[n] {
			t.Errorf("missing %s: %v", n, names)
		}
	}
	for _, n := range []string{"NOT_INSTALLED", "absent", "not/installed"} {
		if names[n] {
			t.Errorf("declared-only package included %s", n)
		}
	}
	out := t.TempDir()
	if e = WriteSBOMs(out, "both", s); e != nil {
		t.Fatal(e)
	}
	for name, keyVersion := range map[string][2]string{"sbom.cdx.json": {"specVersion", "1.6"}, "sbom.spdx.json": {"spdxVersion", "SPDX-2.3"}} {
		b, _ := os.ReadFile(filepath.Join(out, name))
		var data map[string]any
		if e = json.Unmarshal(b, &data); e != nil {
			t.Fatal(e)
		}
		if data[keyVersion[0]] != keyVersion[1] {
			t.Fatalf("wrong version %s: %v", name, data[keyVersion[0]])
		}
	}
	if e = WriteSBOMs(out, "both", s); e == nil {
		t.Fatal("overwrote existing outputs")
	}
	if e = Checksums(out); e != nil {
		t.Fatal(e)
	}
}
func TestConfigurationCannotEnableRemoteEnrichment(t *testing.T) {
	c := Config("test")
	if c.Parallelism != 2 || c.DataGeneration.GenerateCPEs || c.Packages.JavaArchive.UseNetwork || c.Packages.JavaArchive.UseMavenLocalRepository || c.Packages.Python.SearchRemoteLicenses || c.Packages.JavaScript.SearchRemoteLicenses {
		t.Fatal("unsafe cataloger config")
	}
	goConfig := c.Packages.Golang
	if goConfig.UsePackagesLib || goConfig.SearchRemoteLicenses || goConfig.SearchLocalModCacheLicenses ||
		goConfig.SearchLocalVendorLicenses || goConfig.MainModuleVersion.FromContents ||
		goConfig.MainModuleVersion.FromLDFlags || goConfig.MainModuleVersion.FromBuildSettings {
		t.Fatal("Go binary collection must use embedded version evidence")
	}
	for _, name := range Catalogers {
		switch name {
		case "sbom-cataloger", "php-composer-lock-cataloger", "python-package-cataloger", "go-module-file-cataloger", "rust-cargo-lock-cataloger",
			"dotnet-packages-lock-cataloger", "ruby-gemfile-cataloger", "ruby-gemspec-cataloger":
			t.Fatal("declared-only cataloger included")
		}
	}
}

func TestCancelledEncodingDoesNotCreateOutputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := t.TempDir()
	if err := WriteSBOMsContext(ctx, out, "both", nil, false, nil); err == nil {
		t.Fatal("cancelled encoding reported success")
	}
	files, _ := os.ReadDir(out)
	if len(files) != 0 {
		t.Fatal("cancelled encoding wrote outputs")
	}
}
