package bomset

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/domainbom"
)

func generatedDomains(t *testing.T) map[string][]byte {
	t.Helper()
	path := func(name string) string { return filepath.Join("..", "domainbom", "testdata", name) }
	files, err := domainbom.Generate(context.Background(), domainbom.Options{
		SaaS:       []string{path("services.json"), path("openapi.json")},
		Models:     []domainbom.ModelInput{{Evidence: path("model.json"), Artifact: path("model.safetensors")}},
		Provenance: []domainbom.ProvenanceInput{{Evidence: path("provenance.json"), Artifact: path("product.bin")}, {Evidence: path("manufacturing.json")}},
		Include17:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func dualFixture(t *testing.T, dir string) {
	t.Helper()
	fixture(t, dir, true)
	for _, kind := range []string{"sbom", "obom"} {
		doc := load(t, dir, kind+suffix("1.6"))
		doc["specVersion"] = "1.7"
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		write(t, dir, kind+suffix("1.7"), string(raw))
	}
}

func TestGeneratedDomainsPreserveNativeGraphsAcrossSplitMerge(t *testing.T) {
	in, split, merged, repeated := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	dualFixture(t, in)
	files := generatedDomains(t)
	for name, raw := range files {
		write(t, in, name, string(raw))
	}
	seal(t, in)
	if err := Split(context.Background(), in, split, true); err != nil {
		t.Fatal(err)
	}
	seal(t, split)
	if err := Merge(context.Background(), split, merged, true); err != nil {
		t.Fatal(err)
	}
	if err := Merge(context.Background(), split, repeated, true); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"1.6", "1.7"} {
		doc := load(t, merged, "bom"+suffix(spec))
		actual := map[string]any{}
		for _, field := range []string{"components", "services"} {
			for _, item := range doc[field].([]any) {
				row := item.(map[string]any)
				actual[row["bom-ref"].(string)] = row
			}
		}
		for _, kind := range domainKinds {
			var source map[string]any
			if err := json.Unmarshal(files[kind+suffix(spec)], &source); err != nil {
				t.Fatal(err)
			}
			projected := load(t, split, kind+suffix(spec))
			for _, field := range []string{"components", "services"} {
				if values, exists := source[field]; exists {
					if !sameJSON(values, projected[field]) {
						t.Fatalf("%s changed projected %s", kind, field)
					}
					for _, item := range values.([]any) {
						row := item.(map[string]any)
						if !sameJSON(row, actual[row["bom-ref"].(string)]) {
							t.Fatalf("%s lost merged %s", kind, field)
						}
					}
				}
			}
			if kind == "mbom" {
				if !sameJSON(source["formulation"], projected["formulation"]) || !sameJSON(source["formulation"], doc["formulation"]) {
					t.Fatal("native formulation graph lost or changed")
				}
			}
		}
		root, err := os.OpenRoot(merged)
		if err != nil {
			t.Fatal(err)
		}
		sp, err := newSpool(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		seal(t, merged)
		sums, err := checksums(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = readSource(context.Background(), root, "bom"+suffix(spec), sums["bom"+suffix(spec)], "inventory", spec, sp); err != nil {
			t.Fatal("merged references invalid", err)
		}
		root.Close()
		sp.close()
		first, _ := os.ReadFile(filepath.Join(merged, "bom"+suffix(spec)))
		second, _ := os.ReadFile(filepath.Join(repeated, "bom"+suffix(spec)))
		if string(first) != string(second) {
			t.Fatal("non-deterministic domain merge")
		}
		var origins []struct {
			Kind   string
			Header map[string]any
		}
		for _, item := range doc["metadata"].(map[string]any)["properties"].([]any) {
			p := item.(map[string]any)
			if p["name"] == "koda:bom:source-metadata" {
				if err = json.Unmarshal([]byte(p["value"].(string)), &origins); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(origins) != 5 {
			t.Fatal("domain source metadata omitted")
		}
	}
}

func TestNoEvidenceDomainsAndLegacySets(t *testing.T) {
	for _, domains := range []bool{false, true} {
		in, split, out := t.TempDir(), t.TempDir(), t.TempDir()
		fixture(t, in, true)
		if domains {
			for _, kind := range domainKinds {
				doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": map[string]any{"properties": []map[string]string{{"name": "koda:domain:kind", "value": kind}, {"name": "koda:domain:coverage", "value": "no-evidence"}}}, "compositions": []map[string]string{{"aggregate": "unknown"}}}
				raw, _ := json.Marshal(doc)
				write(t, in, kind+suffix("1.6"), string(raw))
			}
		}
		seal(t, in)
		if err := Split(context.Background(), in, split, false); err != nil {
			t.Fatal(err)
		}
		seal(t, split)
		if err := Merge(context.Background(), split, out, false); err != nil {
			t.Fatal(err)
		}
		m := load(t, split, ManifestFilename)
		n := len(m["versions"].([]any)[0].(map[string]any)["profiles"].([]any))
		if (domains && n != 7) || (!domains && n != 4) {
			t.Fatal("wrong no-evidence or legacy profile count")
		}
		if domains {
			for _, kind := range domainKinds {
				raw, _ := os.ReadFile(filepath.Join(split, kind+suffix("1.6")))
				if !strings.Contains(string(raw), "no-evidence") {
					t.Fatal("no-evidence state lost")
				}
			}
		}
	}
}

func TestDomainCompanionsAndProfileTampering(t *testing.T) {
	for _, mutation := range []string{"missing-base", "missing-companion", "different-companion", "wrong-kind", "unverified-file", "dangling-formulation", "altered-profile", "missing-profile", "manifest-companion-mismatch"} {
		t.Run(mutation, func(t *testing.T) {
			in, split, out := t.TempDir(), t.TempDir(), t.TempDir()
			dualFixture(t, in)
			files := generatedDomains(t)
			for name, raw := range files {
				write(t, in, name, string(raw))
			}
			switch mutation {
			case "missing-base":
				os.Remove(filepath.Join(in, "aibom.cdx.json"))
			case "missing-companion":
				os.Remove(filepath.Join(in, "aibom.cdx-1.7.json"))
			case "different-companion":
				write(t, in, "aibom.cdx-1.7.json", strings.Replace(string(files["aibom.cdx-1.7.json"]), "example-model", "different-model", 1))
			case "wrong-kind":
				write(t, in, "saasbom.cdx.json", string(files["aibom.cdx.json"]))
			case "dangling-formulation":
				doc := load(t, in, "mbom.cdx.json")
				formula := doc["formulation"].([]any)[0].(map[string]any)
				workflow := formula["workflows"].([]any)[0].(map[string]any)
				workflow["resourceReferences"] = []map[string]string{{"ref": "missing-resource"}}
				raw, _ := json.Marshal(doc)
				write(t, in, "mbom.cdx.json", string(raw))
			}
			seal(t, in)
			if mutation == "unverified-file" {
				os.Remove(filepath.Join(in, "SHA256SUMS"))
				write(t, in, "SHA256SUMS", "")
			}
			err := Split(context.Background(), in, split, true)
			if mutation != "altered-profile" && mutation != "missing-profile" && mutation != "manifest-companion-mismatch" {
				if err == nil {
					t.Fatal("accepted invalid domain source")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "manifest-companion-mismatch" {
				raw, readErr := os.ReadFile(filepath.Join(split, ManifestFilename))
				if readErr != nil {
					t.Fatal(readErr)
				}
				var set manifest
				if err = json.Unmarshal(raw, &set); err != nil {
					t.Fatal(err)
				}
				for i := range set.Versions[1].Sources {
					if set.Versions[1].Sources[i].Kind == "aibom" {
						set.Versions[1].Sources[i].Components[0].SHA256 = strings.Repeat("a", 64)
					}
				}
				raw, err = json.Marshal(set)
				if err != nil {
					t.Fatal(err)
				}
				write(t, split, ManifestFilename, string(raw))
			} else if mutation == "altered-profile" {
				write(t, split, "saasbom.cdx.json", string(files["saasbom.cdx.json"]))
			} else {
				os.Remove(filepath.Join(split, "mbom.cdx.json"))
			}
			seal(t, split)
			if err = Merge(context.Background(), split, out, true); err == nil {
				t.Fatal("accepted altered or missing domain profile")
			}
		})
	}
}

// Build a historical set using the original profile spelling. This exercises
// existing manifests independently of Split's new output naming.
func legacyModelSet(t *testing.T, collection, outputDir string) {
	t.Helper()
	ctx := context.Background()
	in, err := os.OpenRoot(collection)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	sums, err := checksums(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := newOutput(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	defer out.close(true)
	data, err := newSpool(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	defer data.close()
	data.ctx = ctx
	set := manifest{Schema: "koda-bom-set-1"}
	for _, spec := range []string{"1.6", "1.7"} {
		v := version{SpecVersion: spec}
		for _, row := range []struct{ filename, kind string }{{"sbom", "inventory"}, {"mlbom", "mlbom"}} {
			name := row.filename + suffix(spec)
			s, err := readSource(ctx, in, name, sums[name], row.kind, spec, data)
			if err != nil {
				t.Fatal(err)
			}
			v.Sources = append(v.Sources, s)
			kinds := []string{"mlbom"}
			if row.kind == "inventory" {
				kinds = []string{"sbom", "hbom", "cbom"}
			}
			for _, kind := range kinds {
				profile, err := writeProfile(ctx, out, s, spec, kind, data)
				if err != nil {
					t.Fatal(err)
				}
				v.Profiles = append(v.Profiles, profile)
			}
		}
		v.Relationships, err = writeRelationshipSidecar(ctx, out, data, v)
		if err != nil {
			t.Fatal(err)
		}
		set.Versions = append(set.Versions, v)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	write(t, outputDir, ManifestFilename, string(raw))
	seal(t, outputDir)
}

func TestLegacyModelCollectionsAndSets(t *testing.T) {
	in, split, historical, merged, repeated := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	dualFixture(t, in)
	files := generatedDomains(t)
	for _, spec := range []string{"1.6", "1.7"} {
		raw := strings.ReplaceAll(string(files["aibom"+suffix(spec)]), `"value": "aibom"`, `"value": "mlbom"`)
		write(t, in, "mlbom"+suffix(spec), raw)
	}
	seal(t, in)
	legacyModelSet(t, in, historical)
	if err := Merge(context.Background(), historical, merged, true); err != nil {
		t.Fatal(err)
	}
	if err := Merge(context.Background(), historical, repeated, true); err != nil {
		t.Fatal(err)
	}
	if err := Split(context.Background(), in, split, true); err != nil {
		t.Fatal(err)
	}
	seal(t, split)
	if err := Merge(context.Background(), split, t.TempDir(), true); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"1.6", "1.7"} {
		if _, err := os.Stat(filepath.Join(split, "mlbom"+suffix(spec))); !os.IsNotExist(err) {
			t.Fatal("legacy output filename emitted")
		}
		source := load(t, in, "mlbom"+suffix(spec))
		projected := load(t, split, "aibom"+suffix(spec))
		if !sameJSON(source["components"], projected["components"]) {
			t.Fatal("model observations changed")
		}
		if !sameJSON(load(t, merged, "bom"+suffix(spec)), load(t, repeated, "bom"+suffix(spec))) {
			t.Fatal("legacy merge is not deterministic")
		}
		var metadata struct {
			Properties []struct{ Name, Value string }
		}
		raw, _ := json.Marshal(projected["metadata"])
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range metadata.Properties {
			if p.Name == "koda:bom:profile" && p.Value == "aibom" {
				found = true
			}
		}
		if !found {
			t.Fatal("new projection lacks canonical AI-BOM profile")
		}
	}
	set := load(t, split, ManifestFilename)
	for _, v := range set["versions"].([]any) {
		for _, p := range v.(map[string]any)["profiles"].([]any) {
			if p.(map[string]any)["kind"] == "mlbom" {
				t.Fatal("new manifest uses legacy profile name")
			}
		}
	}
	// Supplying both spellings must fail rather than silently select a source.
	write(t, in, "aibom.cdx.json", string(files["aibom.cdx.json"]))
	seal(t, in)
	if err := Split(context.Background(), in, t.TempDir(), false); err == nil {
		t.Fatal("accepted ambiguous model sources")
	}
	write(t, historical, "mlbom.cdx.json", `{}`)
	if err := Merge(context.Background(), historical, t.TempDir(), true); err == nil {
		t.Fatal("accepted altered legacy model profile")
	}
}
