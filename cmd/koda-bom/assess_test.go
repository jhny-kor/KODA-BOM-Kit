package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssessAdvisoriesMayBeOmittedButNotEmpty(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	// An unset shell variable passed as --advisories must not yield a clean report.
	for _, args := range [][]string{{"--advisories", ""}, {"--advisories="}} {
		if code := assessEvidence(append(args, "--sbom", sbom, "--output", filepath.Join(dir, "empty.json"))); code != 2 {
			t.Fatalf("%v: got exit %d", args, code)
		}
	}
	if code := assessEvidence([]string{"--sbom", sbom, "--output", filepath.Join(dir, "risks.json")}); code != 0 {
		t.Fatalf("omitted --advisories: got exit %d", code)
	}
}
