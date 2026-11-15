package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"koda.local/security-sbom-linux/internal/model"
)

func TestCollectionCoverageInStandardOutputs(t *testing.T) {
	inventory := &sbom.SBOM{
		Source:     source.Description{Name: "local-filesystem", Metadata: source.DirectoryMetadata{Path: "."}},
		Descriptor: sbom.Descriptor{Name: "koda-sbom", Version: "test"},
		Artifacts:  sbom.Artifacts{Packages: pkg.NewCollection()},
	}
	component := pkg.Package{Name: "test-package", Version: "1.0.0", Type: pkg.NpmPkg, PURL: "pkg:npm/test-package@1.0.0"}
	component.SetID()
	inventory.Artifacts.Packages.Add(component)
	issues := []model.Issue{
		{Code: "static_js_identity_unconfirmed", Path: "private/app/ambiguous.js", Message: "raw private error"},
		{Code: "static_js_identity_unconfirmed"},
		{Code: "static_js_issue_limit", Observed: 5},
		{Code: "private_unapproved_code", Collector: "private_collector", Message: "unrecognized evidence"},
		{Collector: "filesystem", Status: "permission_denied", Path: "private/path"},
	}
	coverage := NewCollectionCoverage("partial", "filesystem", 1, 2, 3, issues)
	directory := t.TempDir()
	if err := WriteSBOMsContext(context.Background(), directory, "both", inventory, true, &coverage); err != nil {
		t.Fatal(err)
	}

	read := func(name string, result any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private") || strings.Contains(string(data), "unrecognized evidence") {
			t.Fatalf("coverage exposes raw issue details in %s", name)
		}
		if err := json.Unmarshal(data, result); err != nil {
			t.Fatal(err)
		}
	}

	var cdx struct {
		Metadata struct {
			Properties []struct{ Name, Value string }
		}
		Components   []json.RawMessage
		Compositions []struct{ Aggregate string }
	}
	read("sbom.cdx.json", &cdx)
	var cdxPayloads []string
	for _, property := range cdx.Metadata.Properties {
		if property.Name == CollectionCoverageProperty {
			cdxPayloads = append(cdxPayloads, property.Value)
		}
	}
	if len(cdxPayloads) != 1 || len(cdx.Components) != 1 || len(cdx.Compositions) != 1 || cdx.Compositions[0].Aggregate != "incomplete" {
		t.Fatalf("wrong CycloneDX envelope: %+v", cdx)
	}

	var spdx struct {
		Comment  string
		Packages []struct{ SPDXID string }
	}
	read("sbom.spdx.json", &spdx)
	payload, ok := strings.CutPrefix(spdx.Comment, CollectionCoverageProperty+" ")
	if !ok || payload != cdxPayloads[0] {
		t.Fatal("SPDX and CycloneDX coverage differ")
	}
	// The SPDX encoder adds a synthetic source package. Coverage still
	// counts the collected package only.
	if len(spdx.Packages) != 2 {
		t.Fatalf("expected one installed component and one SPDX source root: %+v", spdx.Packages)
	}

	var actual CollectionCoverage
	if err := json.Unmarshal([]byte(payload), &actual); err != nil {
		t.Fatal(err)
	}
	expected := CollectionCoverage{
		Status: "partial", SourceType: "filesystem", ComponentCount: 1,
		ExcludedDirectoryCount: 2, ExcludedPatternCount: 3, OmittedIssueCount: 6,
		IssueCounts: []collectionIssueCount{
			{Code: "filesystem_permission_denied", Count: 1},
			{Code: "static_js_identity_unconfirmed", Count: 2},
			{Code: "static_js_issue_limit", Count: 1},
		},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("wrong coverage: got %+v, want %+v", actual, expected)
	}
}
