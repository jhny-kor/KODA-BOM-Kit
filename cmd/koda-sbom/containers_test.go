package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/containers"
)

func TestReserveContainerOutputGivesRepeatedNamesDistinctDirectories(t *testing.T) {
	root := t.TempDir()
	for _, group := range []string{"containers", "images"} {
		item := containers.Container{ID: "web", Name: "service"}
		for _, want := range []string{group + "/service", group + "/service-web", group + "/service-web-2"} {
			got, err := reserveContainerOutput(context.Background(), root, group, item)
			if err != nil || got != want {
				t.Fatalf("reserve %q, err %v, want %q", got, err, want)
			}
			if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(got))); err != nil || !st.IsDir() {
				t.Fatalf("missing reserved directory %q, err %v", got, err)
			}
		}
	}
	if c := (containers.Container{ID: "web"}); c.FileName() != "web" {
		t.Fatalf("short ID fallback was changed: %q", c.FileName())
	}
}

func TestStoredContainerWritesBothCycloneDXVersions(t *testing.T) {
	layer := t.TempDir()
	status := filepath.Join(layer, "var/lib/dpkg/status")
	if err := os.MkdirAll(filepath.Dir(status), 0755); err != nil {
		t.Fatal(err)
	}
	pkg := []byte("Package: fixture-app\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.2.3\nDescription: fixture package\n\n")
	if err := os.WriteFile(status, pkg, 0644); err != nil {
		t.Fatal(err)
	}
	options := containerOptions{dir: t.TempDir(), format: "both", cyclonedx17: true, maxFiles: 50}
	summary := containerSummary{Container: containers.Container{ID: "web", Name: "web", State: "stopped"}}
	scanLayers(context.Background(), &summary, []string{layer}, "containers", options)
	if summary.Output != "containers/web" || summary.PackageCount == 0 || summary.Status == "failed" || summary.Status == "not_collected" {
		t.Fatalf("stored container not collected: %+v", summary)
	}
	for name, version := range map[string]string{"sbom.cdx.json": "1.6", collect.CycloneDX17Filename: "1.7"} {
		data, err := os.ReadFile(filepath.Join(options.dir, filepath.FromSlash(summary.Output), name))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			SpecVersion string
			Components  []struct{ Name, Version string }
		}
		if err := json.Unmarshal(data, &result); err != nil || result.SpecVersion != version {
			t.Fatalf("%s has spec %q, parse error %v", name, result.SpecVersion, err)
		}
		found := false
		for _, component := range result.Components {
			found = found || component.Name == "fixture-app" && component.Version == "1.2.3"
		}
		if !found {
			t.Fatalf("%s did not include fixture-app 1.2.3", name)
		}
	}
}
