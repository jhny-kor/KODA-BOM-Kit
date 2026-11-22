package reconcile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildInventoryPreservesDeclaredGraphAndReportsDanglingRefs(t *testing.T) {
	raw := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"app","name":"app","hashes":[{"alg":"SHA-256","content":"` + strings.Repeat("a", 64) + `"}]}},"components":[{"type":"library","bom-ref":"tool","name":"compiler","version":"1","purl":"pkg:generic/compiler@1"}],"dependencies":[{"ref":"app","dependsOn":["tool","missing"]}]}`
	inventory, err := ReadBuildInventory(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := inventory.Document["dependencies"].([]map[string]any)
	if len(dependencies) != 1 || dependencies[0]["ref"] != "app" || len(dependencies[0]["dependsOn"].([]string)) != 1 || dependencies[0]["dependsOn"].([]string)[0] != "tool" {
		t.Fatalf("graph lost: %+v", dependencies)
	}
	metadata := inventory.Document["metadata"].(map[string]any)
	if metadata["lifecycles"].([]map[string]string)[0]["phase"] != "build" {
		t.Fatal("build lifecycle missing")
	}
	if inventory.Document["compositions"].([]map[string]string)[0]["aggregate"] != "incomplete" {
		t.Fatal("dangling reference coverage missing")
	}
	encoded, _ := json.Marshal(inventory.Document)
	if strings.Contains(string(encoded), `"ref":"missing"`) {
		t.Fatal("dangling node emitted")
	}
}

func TestBuildInventoryConvertsSPDXBuildDependencyDirection(t *testing.T) {
	raw := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentDescribes":["SPDXRef-app"],"packages":[{"SPDXID":"SPDXRef-app","name":"app","checksums":[{"algorithm":"SHA256","checksumValue":"` + strings.Repeat("a", 64) + `"}]},{"SPDXID":"SPDXRef-compiler","name":"compiler","versionInfo":"2","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:generic/compiler@2"}]}],"relationships":[{"spdxElementId":"SPDXRef-compiler","relationshipType":"BUILD_DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-app"}]}`
	inventory, err := ReadBuildInventory(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := inventory.Document["dependencies"].([]map[string]any)
	if len(dependencies) != 1 || dependencies[0]["ref"] != "SPDXRef-app" || dependencies[0]["dependsOn"].([]string)[0] != "SPDXRef-compiler" {
		t.Fatalf("dependency reversed %+v", dependencies)
	}
}
