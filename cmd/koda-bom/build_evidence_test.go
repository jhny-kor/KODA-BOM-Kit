package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/imagearchive"
	"koda.local/security-sbom-linux/internal/localfs"
)

func buildEvidenceFixture(t *testing.T) (buildEvidenceFlags, string) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "app.bin")
	data := []byte("opaque deployed application")
	if err := os.WriteFile(artifact, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	declaration := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": map[string]any{"component": map[string]any{"name": "app", "bom-ref": "app", "hashes": []map[string]string{{"alg": "SHA-256", "content": hex.EncodeToString(sum[:])}}}}, "components": []map[string]string{{"name": "build-tool", "version": "1", "purl": "pkg:generic/build-tool@1", "bom-ref": "tool"}}, "dependencies": []map[string]any{{"ref": "app", "dependsOn": []string{"tool"}}}}
	raw, _ := json.Marshal(declaration)
	supplier := filepath.Join(t.TempDir(), "supplier.json")
	if err := os.WriteFile(supplier, raw, 0600); err != nil {
		t.Fatal(err)
	}
	flags := buildEvidenceFlags{supplier: supplier, artifact: artifact}
	if err := flags.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return flags, root
}

func TestBuildEvidenceAdmitsOnlyPlannedArtifactAndWritesBothVersions(t *testing.T) {
	flags, root := buildEvidenceFixture(t)
	plan, err := localfs.BuildWithOptions(context.Background(), root, nil, localfs.Options{MaxFiles: 100})
	if err != nil {
		t.Fatal(err)
	}
	flags.admit(plan)
	out := t.TempDir()
	if err := flags.write(context.Background(), out, "", nil, true); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"build-sbom.cdx.json": "1.6", "build-sbom.cdx-1.7.json": "1.7"} {
		raw, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SpecVersion  string `json:"specVersion"`
			Components   []struct{ Name string }
			Dependencies []struct {
				Ref       string
				DependsOn []string
			}
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.SpecVersion != want || len(doc.Components) != 1 || doc.Components[0].Name != "build-tool" || len(doc.Dependencies) != 1 {
			t.Fatalf("incomplete declaration %+v", doc)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); !os.IsNotExist(err) {
		t.Fatal("observed SBOM written by build evidence")
	}
}

func TestBuildEvidenceRejectsExcludedOutsideChangedAndWrongImage(t *testing.T) {
	for _, kind := range []string{"excluded", "outside", "changed", "wrong-image"} {
		t.Run(kind, func(t *testing.T) {
			flags, root := buildEvidenceFixture(t)
			var excluded []string
			if kind == "excluded" {
				excluded = []string{"app.bin"}
			}
			if kind == "outside" {
				root = t.TempDir()
			}
			plan, err := localfs.BuildWithOptions(context.Background(), root, excluded, localfs.Options{MaxFiles: 100})
			if err != nil {
				t.Fatal(err)
			}
			flags.admit(plan)
			image := ""
			var identity *imagearchive.Identity
			if kind == "changed" {
				if err := os.WriteFile(flags.artifact, []byte("different"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "wrong-image" {
				image = filepath.Join(t.TempDir(), "different.tar")
				identity = &imagearchive.Identity{ArchiveSHA256: flags.inventory.SHA256}
			}
			out := t.TempDir()
			if err := flags.write(context.Background(), out, image, identity, true); err == nil {
				t.Fatal("invalid binding accepted")
			}
			entries, _ := os.ReadDir(out)
			if len(entries) != 0 {
				t.Fatal("failed binding emitted evidence")
			}
		})
	}
}

func TestBuildEvidencePreservesExistingOutputAndRollsBackOwnFirstVersion(t *testing.T) {
	flags, root := buildEvidenceFixture(t)
	plan, err := localfs.BuildWithOptions(context.Background(), root, nil, localfs.Options{MaxFiles: 100})
	if err != nil {
		t.Fatal(err)
	}
	flags.admit(plan)
	out := t.TempDir()
	existing := filepath.Join(out, "build-sbom.cdx-1.7.json")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := flags.write(context.Background(), out, "", nil, true); err == nil {
		t.Fatal("overwrote existing declaration")
	}
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "keep" {
		t.Fatal("existing declaration damaged")
	}
	if _, err := os.Stat(filepath.Join(out, "build-sbom.cdx.json")); !os.IsNotExist(err) {
		t.Fatal("partial new output retained")
	}
}

func TestBuildEvidenceFlagsRequirePairAndCycloneDX(t *testing.T) {
	for _, flags := range []buildEvidenceFlags{{supplier: "x"}, {artifact: "x"}} {
		if flags.validate("both") == nil {
			t.Fatal("unpaired flags accepted")
		}
	}
	if (&buildEvidenceFlags{supplier: "x", artifact: "y"}).validate("spdx") == nil {
		t.Fatal("unsupported output accepted")
	}
}
