package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExportNISSBOM(t *testing.T) {
	dir := t.TempDir()
	sbom, out := filepath.Join(dir, "sbom.cdx.json"), filepath.Join(dir, "nis.csv")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","metadata":{"timestamp":"2026-11-25T00:00:00Z"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--sbom", sbom, "--organization", "K", "--output", out}
	if code := exportNISSBOM(args); code != 0 {
		t.Fatalf("first export: exit %d", code)
	}
	first, _ := os.ReadFile(out)
	if code := exportNISSBOM(args); code != 2 {
		t.Fatalf("an existing result must not be overwritten: exit %d", code)
	}
	if again, _ := os.ReadFile(out); string(again) != string(first) || len(first) == 0 {
		t.Fatal("existing result changed")
	}
	link, other := filepath.Join(dir, "link.json"), filepath.Join(dir, "other.csv")
	cases := map[string][]string{
		"no organization":   {"--sbom", sbom, "--output", other},
		"missing output":    {"--sbom", sbom, "--organization", "K"},
		"directory as SBOM": {"--sbom", dir, "--organization", "K", "--output", other},
	}
	if os.Symlink(sbom, link) == nil { // not every platform allows symlinks
		cases["symlinked input"] = []string{"--sbom", link, "--organization", "K", "--output", other}
	}
	for name, bad := range cases {
		if code := exportNISSBOM(bad); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
		if _, err := os.Stat(other); err == nil {
			t.Errorf("%s: left an output file", name)
		}
	}
}
