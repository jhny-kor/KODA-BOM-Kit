package bomset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, dir string, operations bool) {
	t.Helper()
	inventory := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"metadata":{"component":{"type":"application","name":"inventory","bom-ref":"root"}},
"components":[{"type":"library","name":"app","bom-ref":"software","purl":"pkg:generic/app@1","components":[{"type":"library","name":"child","bom-ref":"child"}]},
{"type":"device","name":"board","bom-ref":"hardware"},
{"type":"cryptographic-asset","name":"algo","bom-ref":"algorithm","cryptoProperties":{"assetType":"algorithm"}}],
"dependencies":[{"ref":"root","dependsOn":["software","hardware"]},{"ref":"software","dependsOn":["hardware"],"provides":["child"]},{"ref":"hardware","dependsOn":["algorithm"]}],
"compositions":[{"aggregate":"incomplete","assemblies":["software","hardware","algorithm"]}]} `
	write(t, dir, "sbom.cdx.json", inventory)
	if operations {
		write(t, dir, "obom.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
"metadata":{"component":{"type":"device","name":"host","bom-ref":"host"},"lifecycles":[{"phase":"operations"}]},
"components":[{"type":"library","name":"app","bom-ref":"runtime","purl":"pkg:generic/app@1"}],
"services":[{"bom-ref":"port","name":"port"}],"dependencies":[{"ref":"host","dependsOn":["runtime","port"]},{"ref":"port","dependsOn":["runtime"]}]}`)
	}
	seal(t, dir)
}

func write(t *testing.T, dir, name, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func seal(t *testing.T, dir string) {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var result strings.Builder
	for _, f := range files {
		if f.IsDir() || f.Name() == "SHA256SUMS" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&result, "%x  %s\n", sha256.Sum256(data), f.Name())
	}
	write(t, dir, "SHA256SUMS", result.String())
}

func load(t *testing.T, dir, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err = json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSplitMergeRestoresCrossCategoryAndScope(t *testing.T) {
	in, split, merged := t.TempDir(), t.TempDir(), t.TempDir()
	fixture(t, in, true)
	if err := Split(context.Background(), in, split, false); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"sbom": "software", "hbom": "hardware", "cbom": "algorithm", "obom": "runtime"} {
		d := load(t, split, name+".cdx.json")
		components := d["components"].([]any)
		if len(components) != 1 || components[0].(map[string]any)["bom-ref"] != want {
			t.Fatalf("incorrect %s projection", name)
		}
	}
	seal(t, split)
	if err := Merge(context.Background(), split, merged, false); err != nil {
		t.Fatal(err)
	}
	d := load(t, merged, "bom.cdx.json")
	components := d["components"].([]any)
	if len(components) != 5 {
		t.Fatalf("lost or conflated source components: %v", components)
	}
	deps := map[string]map[string]any{}
	for _, value := range d["dependencies"].([]any) {
		row := value.(map[string]any)
		deps[row["ref"].(string)] = row
	}
	if deps["software"]["dependsOn"].([]any)[0] != "hardware" || deps["hardware"]["dependsOn"].([]any)[0] != "algorithm" || deps["software"]["provides"].([]any)[0] != "child" {
		t.Fatal("cross-category dependency or provides relationship lost")
	}
	if len(deps["root"]["dependsOn"].([]any)) != 3 {
		t.Fatal("inventory to operations root relation missing")
	}
}

func TestSplitRejectsTamperingAndRollback(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	fixture(t, in, false)
	write(t, out, "keep", "caller-owned")
	if err := Split(context.Background(), in, out, true); err == nil {
		t.Fatal("converted unavailable 1.7 source")
	}
	files, _ := os.ReadDir(out)
	if len(files) != 1 || files[0].Name() != "keep" {
		t.Fatal("failed split leaked output or deleted caller-owned files")
	}
	write(t, in, "sbom.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)
	if err := Split(context.Background(), in, out, false); err == nil {
		t.Fatal("accepted modified source")
	}
}

func TestMergeRejectsChangedMembersAndConflicts(t *testing.T) {
	for _, mutate := range []string{"profile", "manifest-member", "duplicate-profile"} {
		t.Run(mutate, func(t *testing.T) {
			in, split, out := t.TempDir(), t.TempDir(), t.TempDir()
			fixture(t, in, true)
			if err := Split(context.Background(), in, split, false); err != nil {
				t.Fatal(err)
			}
			switch mutate {
			case "profile":
				raw, _ := os.ReadFile(filepath.Join(split, "hbom.cdx.json"))
				write(t, split, "hbom.cdx.json", strings.Replace(string(raw), "board", "replacement", 1))
			default:
				raw, _ := os.ReadFile(filepath.Join(split, ManifestFilename))
				var m manifest
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				if mutate == "manifest-member" {
					m.Versions[0].Sources[0].Components[0].SHA256 = strings.Repeat("a", 64)
				} else {
					m.Versions[0].Profiles = append(m.Versions[0].Profiles, m.Versions[0].Profiles[0])
				}
				encoded, _ := json.Marshal(m)
				write(t, split, ManifestFilename, string(encoded))
			}
			seal(t, split)
			if err := Merge(context.Background(), split, out, false); err == nil {
				t.Fatal("accepted conflicting or altered set")
			}
		})
	}
}

func TestCancellationExistingOutputAndOperationsOverride(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	fixture(t, in, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Split(ctx, in, out, false); err == nil {
		t.Fatal("ignored cancellation")
	}
	write(t, out, "hbom.cdx.json", "existing")
	if err := Split(context.Background(), in, out, false); err == nil {
		t.Fatal("overwrote existing profile")
	}
	raw, _ := os.ReadFile(filepath.Join(out, "hbom.cdx.json"))
	if string(raw) != "existing" {
		t.Fatal("modified caller-owned output")
	}
	if err := Split(context.Background(), in, t.TempDir(), false, in); err == nil {
		t.Fatal("allowed replacing recorded operations input")
	}
}

func TestLegacyDuplicateCertificatesPreservePayloadsAndAmbiguity(t *testing.T) {
	for _, referenced := range []bool{false, true} {
		t.Run(fmt.Sprint(referenced), func(t *testing.T) {
			in, split, merged := t.TempDir(), t.TempDir(), t.TempDir()
			dependency := "[]"
			if referenced {
				dependency = `[{"ref":"root","dependsOn":["certificate"]}]`
			}
			raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"inventory","bom-ref":"root"}},"components":[
{"type":"cryptographic-asset","name":"Certificate","bom-ref":"certificate","cryptoProperties":{"assetType":"certificate"},"properties":[{"name":"position","value":"0"}]},
{"type":"cryptographic-asset","name":"Certificate","bom-ref":"certificate","cryptoProperties":{"assetType":"certificate"},"properties":[{"name":"position","value":"0"}]},
{"type":"cryptographic-asset","name":"Certificate","bom-ref":"certificate","cryptoProperties":{"assetType":"certificate"},"properties":[{"name":"position","value":"1"}]}],"dependencies":` + dependency + `}`
			write(t, in, "sbom.cdx.json", raw)
			seal(t, in)
			if err := Split(context.Background(), in, split, false); err != nil {
				t.Fatal(err)
			}
			seal(t, split)
			if err := Merge(context.Background(), split, merged, false); err != nil {
				t.Fatal(err)
			}
			d := load(t, merged, "bom.cdx.json")
			positions := map[string]bool{}
			ambiguous := false
			for _, value := range d["components"].([]any) {
				component := value.(map[string]any)
				for _, v := range component["properties"].([]any) {
					p := v.(map[string]any)
					if p["name"] == "position" {
						positions[p["value"].(string)] = true
					}
					if p["name"] == "koda:bom:reference-state" {
						ambiguous = component["bom-ref"] == "certificate" && p["value"] == "ambiguous"
					}
				}
			}
			if !positions["0"] || !positions["1"] || len(positions) != 2 || ambiguous != referenced {
				t.Fatal("lost candidate payload or assigned an ambiguous reference")
			}
			manifest := load(t, split, ManifestFilename)
			source := manifest["versions"].([]any)[0].(map[string]any)["sources"].([]any)[0].(map[string]any)
			normalized := source["normalization"].([]any)[0].(map[string]any)
			if normalized["occurrences"] != float64(3) || len(normalized["recordOccurrences"].(map[string]any)) != 2 {
				t.Fatal("lost original occurrence counts")
			}
		})
	}
}

func TestRegeneratedOperationsMustMatchCollection(t *testing.T) {
	in, operations := t.TempDir(), t.TempDir()
	fixture(t, in, false)
	write(t, in, "collection.json", `{"schema":"koda-sbom-collection-v1","startedAt":"2026-11-21T00:00:00Z","host":{"assetTag":"test-host"}}`)
	seal(t, in)
	for _, correct := range []bool{false, true} {
		stamp := "2026-11-20T00:00:00Z"
		if correct {
			stamp = "2026-11-21T00:00:00Z"
		}
		write(t, operations, "obom.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"`+stamp+`","component":{"type":"device","name":"host","bom-ref":"host","properties":[{"name":"koda:obom:host-identity","value":"{\"assetTag\":\"test-host\"}"}]}},"components":[],"dependencies":[]}`)
		seal(t, operations)
		err := Split(context.Background(), in, t.TempDir(), false, operations)
		if (err == nil) != correct {
			t.Fatalf("unexpected regenerated operations binding result: %v", err)
		}
	}
}

func TestCompositionsDeduplicateAfterProjectionAndMerge(t *testing.T) {
	in, split, merged := t.TempDir(), t.TempDir(), t.TempDir()
	fixture(t, in, true)
	primary := load(t, in, "sbom.cdx.json")
	primary["compositions"] = []any{
		map[string]any{"aggregate": "incomplete", "assemblies": []string{"software"}},
		map[string]any{"aggregate": "incomplete", "assemblies": []string{"hardware"}},
		map[string]any{"aggregate": "incomplete"},
	}
	encoded, _ := json.Marshal(primary)
	write(t, in, "sbom.cdx.json", string(encoded))
	operation := load(t, in, "obom.cdx.json")
	operation["compositions"] = []any{map[string]any{"aggregate": "incomplete"}}
	encoded, _ = json.Marshal(operation)
	write(t, in, "obom.cdx.json", string(encoded))
	seal(t, in)
	if err := Split(context.Background(), in, split, false); err != nil {
		t.Fatal(err)
	}
	crypto := load(t, split, "cbom.cdx.json")
	if len(crypto["compositions"].([]any)) != 1 {
		t.Fatal("filtered compositions became duplicates")
	}
	seal(t, split)
	if err := Merge(context.Background(), split, merged, false); err != nil {
		t.Fatal(err)
	}
	d := load(t, merged, "bom.cdx.json")
	if len(d["compositions"].([]any)) != 3 {
		t.Fatal("shared primary and operations compositions were duplicated or lost")
	}
	for _, p := range d["metadata"].(map[string]any)["properties"].([]any) {
		property := p.(map[string]any)
		if property["name"] != "koda:bom:source-metadata" {
			continue
		}
		var origins []struct{ Header map[string]any }
		if err := json.Unmarshal([]byte(property["value"].(string)), &origins); err != nil {
			t.Fatal(err)
		}
		if len(origins) != 2 || len(origins[0].Header["compositions"].([]any)) != 3 || len(origins[1].Header["compositions"].([]any)) != 1 {
			t.Fatal("deduplication changed original source provenance")
		}
		return
	}
	t.Fatal("source metadata provenance missing")
}
