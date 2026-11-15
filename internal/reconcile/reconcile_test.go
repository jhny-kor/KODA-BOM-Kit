package reconcile

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSupplierBindsOnlyDeclaredSubject(t *testing.T) {
	const hexA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const cdx = `{"bomFormat":"CycloneDX","specVersion":"1.6",
	  "metadata":{"component":{"name":"release","hashes":[{"alg":"SHA-256","content":"ROOT"}]}},
	  "components":[{"name":"jquery","version":"3.1.1","purl":"pkg:npm/jquery@3.1.1",
	  "hashes":[{"alg":"SHA-256","content":"CHILD"}]}]}`
	const spdx = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	  "relationships":[{"spdxElementId":"SPDXRef-release","relationshipType":"DESCRIBED_BY","relatedSpdxElement":"SPDXRef-DOCUMENT"}],
	  "packages":[{"SPDXID":"SPDXRef-release","name":"release","checksums":[{"algorithm":"SHA256","checksumValue":"ROOT"}]},
	  {"SPDXID":"SPDXRef-jq","name":"jquery","checksums":[{"algorithm":"SHA256","checksumValue":"CHILD"}],
	  "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/jquery@3.1.1"}]}]}`
	interpolate := strings.NewReplacer("ROOT", hexA, "CHILD", hexB)
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"CycloneDX", cdx, nil},
		{"SPDX inverse relationship", spdx, nil},
		{"duplicate folded key", strings.Replace(cdx, `"content":"ROOT"`, `"content":"ROOT","Content":"CHILD"`, 1), ErrSupplierJSON},
		{"JSON suffix", cdx + ` {}`, ErrSupplierJSON},
		{"child SHA only", strings.Replace(cdx, `,"hashes":[{"alg":"SHA-256","content":"ROOT"}]`, "", 1), ErrSupplierSubject},
		{"SPDX multiple subjects", strings.Replace(spdx, `"packages":`, `"documentDescribes":["SPDXRef-jq"],"packages":`, 1), ErrSupplierSubject},
		{"SPDX duplicate package", strings.Replace(spdx, `"SPDXRef-jq"`, `"SPDXRef-release"`, 1), ErrSupplierInventory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadSupplier(strings.NewReader(interpolate.Replace(tc.body)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadSupplier error = %v, want %v", err, tc.want)
			}
			if err == nil && (got.SHA256 != strings.ToLower(hexA) || len(got.Components) != 1 || got.Components[0].PURL != "pkg:npm/jquery@3.1.1") {
				t.Fatalf("unexpected subject or component: %+v", got)
			}
		})
	}
}

func TestCompareKeepsVersionAndQualifierEvidence(t *testing.T) {
	components := func(purls ...string) []Component {
		var result []Component
		for _, purl := range purls {
			result = append(result, Component{PURL: purl})
		}
		return result
	}
	got := Compare(components(
		"pkg:npm/%40example/jquery@3.1.1", "pkg:npm/%40example/jquery@3.1.1", "pkg:npm/jquery@1.2.3+one",
		"pkg:maven/a/b@1.1?type=jar&classifier=tests", "pkg:maven/a/b@1.1", "pkg:npm/fancyTree@1.2.3",
	), append(components(
		"pkg:npm/@example/jquery@3.1.1", "pkg:npm/jquery@1.2.3+two", "pkg:npm/fancytree@1.2.3",
		"pkg:maven/a/b@1.1?classifier=tests&type=jar", "pkg:npm/extension@'jquery.fancytree.childcounter.min.js'",
		"pkg:maven/a/b@1.1?repository_url=https://PRIVATE.example/repo", "pkg:maven/a/b@1.1#private/file",
	), Component{PURL: "pkg:npm/jquery@1.2.3+one", Version: "1.2.3+two"}))
	if want := []IdentityCount{{"pkg:maven/a/b@1.1?classifier=tests&type=jar", 1, 1}, {"pkg:npm/%40example/jquery@3.1.1", 2, 1}}; !reflect.DeepEqual(want, got.Common) {
		t.Errorf("common = %+v, want %+v", got.Common, want)
	}
	if len(got.ObservedOnly) != 3 || len(got.SupplierOnly) != 2 {
		t.Errorf("identities from different package builds collapsed: %+v", got)
	}
	if want := []UnresolvedCount{{"nonconcrete_version", 0, 1}, {"unsupported_purl_detail", 0, 2}, {"version_conflict", 0, 1}}; !reflect.DeepEqual(want, got.Unresolved) {
		t.Errorf("unresolved = %+v, want %+v", got.Unresolved, want)
	}
	data, err := json.Marshal(got)
	if err != nil || strings.Contains(strings.ToLower(string(data)), "private") || strings.Contains(string(data), ".min.js") {
		t.Fatalf("unsupported identity detail was published: %s, %v", data, err)
	}
}
