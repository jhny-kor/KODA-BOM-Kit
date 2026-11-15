package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestCycloneDXLicenseListMatchesPinnedSchema(t *testing.T) {
	data, err := os.ReadFile("../../tests/schemas/spdx.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if got := hex.EncodeToString(hash[:]); got != "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e" {
		t.Fatalf("pinned CycloneDX 1.6 license schema changed: %s", got)
	}
	var schema struct{ Enum []string }
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Enum) != len(cyclonedx16LicenseIDs) {
		t.Fatalf("runtime license list has %d IDs, schema has %d", len(cyclonedx16LicenseIDs), len(schema.Enum))
	}
	for _, id := range schema.Enum {
		if !cyclonedx16LicenseIDs[id] {
			t.Fatalf("runtime list missing schema license %q", id)
		}
	}
}

func TestCycloneDXLicenseFallbackPreservesOtherFieldsAndExpressions(t *testing.T) {
	raw := []byte(`{
  "bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:fixture",
  "metadata":{"component":{"name":"root","licenses":[{"license":{"id":"SMAIL-GPL","url":"https://example.invalid/LICENSE","acknowledgement":"declared"}}]}},
  "components":[
    {"type":"library","bom-ref":"pkg-ref","name":"debianutils","version":"5.17build1","purl":"pkg:deb/ubuntu/debianutils@5.17build1?arch=amd64&distro=ubuntu-24.04","licenses":[{"license":{"id":"MIT"}},{"license":{"id":"SMAIL-GPL","text":{"content":"preserve text","contentType":"text/plain"}}}],"components":[{"name":"nested","licenses":[{"license":{"id":"Future-License-ID"}}]}],"evidence":{"licenses":[{"license":{"id":"Apache-2.0"}}]}},
    {"type":"library","name":"expression","licenses":[{"expression":"MIT OR (SMAIL-GPL AND GPL-2.0-only)"}]}
  ],
  "dependencies":[{"ref":"pkg-ref","dependsOn":["other-ref"]}],
  "properties":[{"name":"license","value":"SMAIL-GPL"}],
  "unrelated":{"id":"SMAIL-GPL","license":{"id":"SMAIL-GPL"},"counter":9007199254740993}
}`)
	want := decodeOutputJSON(t, raw)
	root := want.(map[string]any)
	metadataLicense := root["metadata"].(map[string]any)["component"].(map[string]any)["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)
	component := root["components"].([]any)[0].(map[string]any)
	packageLicense := component["licenses"].([]any)[1].(map[string]any)["license"].(map[string]any)
	nestedLicense := component["components"].([]any)[0].(map[string]any)["licenses"].([]any)[0].(map[string]any)["license"].(map[string]any)
	for _, license := range []map[string]any{metadataLicense, packageLicense, nestedLicense} {
		license["name"] = license["id"]
		delete(license, "id")
	}
	normalized, changed, err := normalizeCycloneDXLicenseIDs(raw)
	if err != nil || !changed {
		t.Fatalf("license fallback failed: changed=%v error=%v", changed, err)
	}
	if got := decodeOutputJSON(t, normalized); !reflect.DeepEqual(got, want) {
		t.Fatalf("fields other than unsupported license IDs changed\ngot: %s\nwant: %#v", normalized, want)
	}
	second, changed, err := normalizeCycloneDXLicenseIDs(normalized)
	if err != nil || changed || !bytes.Equal(second, normalized) {
		t.Fatal("normalization was not idempotent")
	}
}

func TestKnownCycloneDXLicensesAndExpressionsAreByteUnchanged(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"components":[{"licenses":[{"license":{"id":"MIT"}},{"license":{"id":"GPL-2.0-only"}}]}]}`),
		[]byte(`{"components":[{"licenses":[{"expression":"MIT OR SMAIL-GPL"}]}]}`),
	} {
		got, changed, err := normalizeCycloneDXLicenseIDs(raw)
		if err != nil || changed || !bytes.Equal(got, raw) {
			t.Fatalf("known licenses or expression changed: %s, %v", got, err)
		}
	}
}

func decodeOutputJSON(t *testing.T, data []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var result any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestWriteSBOMsKeepsNewerSPDXLicenseInAllFormats(t *testing.T) {
	const purl = "pkg:deb/ubuntu/debianutils@5.17build1?arch=amd64&distro=ubuntu-24.04"
	p := pkg.Package{Name: "debianutils", Version: "5.17build1", Type: pkg.DebPkg, PURL: purl,
		Licenses: pkg.NewLicenseSet(pkg.License{Value: "SMAIL-GPL", SPDXExpression: "SMAIL-GPL", Type: license.Declared})}
	p.SetID()
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(p)},
		Source:     source.Description{ID: "fixture", Name: "fixture", Metadata: source.DirectoryMetadata{Path: "."}},
		Descriptor: sbom.Descriptor{Name: "koda-sbom", Version: "test"}}
	dir := t.TempDir()
	if err := WriteSBOMs(dir, "both", s); err != nil {
		t.Fatal(err)
	}
	read := func(name string, value any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, value); err != nil {
			t.Fatal(err)
		}
	}
	var cdx struct {
		Components []struct {
			Name, Version, PURL string
			Licenses            []struct{ License map[string]string }
		}
	}
	read("sbom.cdx.json", &cdx)
	if len(cdx.Components) != 1 || cdx.Components[0].Name != p.Name || cdx.Components[0].Version != p.Version || cdx.Components[0].PURL != purl {
		t.Fatalf("CycloneDX package identity changed: %+v", cdx.Components)
	}
	licenses := cdx.Components[0].Licenses
	if len(licenses) != 1 || licenses[0].License["name"] != "SMAIL-GPL" || licenses[0].License["id"] != "" {
		t.Fatalf("newer SPDX ID did not use CycloneDX named license fallback: %+v", licenses)
	}
	var syft struct {
		Artifacts []struct {
			PURL     string
			Licenses []struct{ Value, SPDXExpression string }
		}
	}
	read("inventory.syft.json", &syft)
	if len(syft.Artifacts) != 1 || syft.Artifacts[0].PURL != purl || len(syft.Artifacts[0].Licenses) != 1 || syft.Artifacts[0].Licenses[0].SPDXExpression != "SMAIL-GPL" {
		t.Fatalf("Syft license or PURL changed: %+v", syft.Artifacts)
	}
	var spdx struct {
		Packages []struct {
			Name, LicenseDeclared string
			ExternalRefs          []struct{ ReferenceLocator string }
		}
	}
	read("sbom.spdx.json", &spdx)
	found := false
	for _, item := range spdx.Packages {
		if item.Name != p.Name {
			continue
		}
		if item.LicenseDeclared != "SMAIL-GPL" {
			t.Fatalf("SPDX license changed: %+v", item)
		}
		for _, ref := range item.ExternalRefs {
			found = found || ref.ReferenceLocator == purl
		}
	}
	if !found {
		t.Fatal("SPDX package PURL lost")
	}
	if got := s.Artifacts.Packages.Package(p.ID()).Licenses.ToSlice(); len(got) != 1 || got[0].SPDXExpression != "SMAIL-GPL" {
		t.Fatalf("original inventory license mutated: %+v", got)
	}
}
