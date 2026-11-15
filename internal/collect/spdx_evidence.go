package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"koda.local/security-sbom-linux/internal/staticjs"
)

type spdxPackageEvidence struct {
	oracleInventoryMetadata
	EvidencePaths []string `json:"evidencePaths"`
}

// SPDX 2.3 package comments preserve the collection evidence for each stable
// SPDXRef. Keep PURL and CPE values independent of the installation instance.
func addSPDXEvidence(raw []byte, inventory *pkg.Collection, coverage []byte, allOccurrences bool) ([]byte, error) {
	hasPackageEvidence := allOccurrences || bytes.Contains(raw, []byte(oracleSPDXIDPrefix)) ||
		bytes.Contains(raw, []byte(javascriptSPDXIDPrefix)) || bytes.Contains(raw, []byte(binarySPDXIDPrefix)) ||
		bytes.Contains(raw, []byte(deployedSPDXIDPrefix)) || bytes.Contains(raw, []byte(javaSPDXIDPrefix))
	if !hasPackageEvidence && len(coverage) == 0 {
		return raw, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if len(coverage) > 0 {
		comment, err := json.Marshal(CollectionCoverageProperty + " " + string(coverage))
		if err != nil {
			return nil, err
		}
		document["comment"] = comment
	}
	if !hasPackageEvidence {
		return json.MarshalIndent(document, "", "  ")
	}
	byID := map[string]spdxPackageEvidence{}
	for _, item := range inventory.Sorted() {
		id := string(item.ID())
		var evidence spdxPackageEvidence
		switch {
		case item.FoundBy == AIXOracleCollector && strings.HasPrefix(id, oracleSPDXIDPrefix):
			metadata, ok := item.Metadata.(oracleInventoryMetadata)
			if !ok {
				return nil, fmt.Errorf("missing Oracle inventory metadata")
			}
			evidence.oracleInventoryMetadata = metadata
		case item.FoundBy == staticjs.Collector && (allOccurrences || strings.HasPrefix(id, javascriptSPDXIDPrefix)):
			evidence.Observation = "deployed JavaScript identity evidence"
		case isBinaryCollector(item.FoundBy) && (allOccurrences || strings.HasPrefix(id, binarySPDXIDPrefix)):
			evidence.Observation = "embedded binary dependency metadata"
		case item.FoundBy == DotnetCollector && (allOccurrences || strings.HasPrefix(id, deployedSPDXIDPrefix)):
			evidence.Observation = ".NET deployment metadata"
			if _, ok := item.Metadata.(pkg.DotnetPortableExecutableEntry); ok {
				evidence.Observation = ".NET assembly metadata"
			}
		case item.FoundBy == RubyCollector && (allOccurrences || strings.HasPrefix(id, deployedSPDXIDPrefix)):
			evidence.Observation = "installed RubyGems specification"
		case item.FoundBy == javaArchiveCataloger && (allOccurrences || strings.HasPrefix(id, javaSPDXIDPrefix)):
			evidence.Observation = "deployed Java archive evidence"
		case allOccurrences && strings.HasPrefix(id, directoryPackageIDPrefix):
			evidence.Observation = "component collection evidence"
		default:
			continue
		}
		for _, location := range item.Locations.ToSlice() {
			if location.FullNestedPath() != "" {
				evidence.EvidencePaths = append(evidence.EvidencePaths, location.FullNestedPath())
			}
		}
		if allOccurrences && len(evidence.EvidencePaths) == 0 {
			continue
		}
		slices.Sort(evidence.EvidencePaths)
		evidence.EvidencePaths = slices.Compact(evidence.EvidencePaths)
		byID[id] = evidence
	}
	if len(byID) == 0 {
		return json.MarshalIndent(document, "", "  ")
	}
	var packages []json.RawMessage
	if err := json.Unmarshal(document["packages"], &packages); err != nil {
		return nil, err
	}
	for i, rawPackage := range packages {
		var id struct{ SPDXID string }
		if err := json.Unmarshal(rawPackage, &id); err != nil {
			return nil, err
		}
		evidence, ok := byID[id.SPDXID]
		if !ok {
			continue
		}
		var item map[string]json.RawMessage
		if err := json.Unmarshal(rawPackage, &item); err != nil {
			return nil, err
		}
		comment, err := json.Marshal(evidence)
		if err != nil {
			return nil, err
		}
		item["comment"], err = json.Marshal(string(comment))
		if err != nil {
			return nil, err
		}
		if evidence.Observation == "deployed JavaScript identity evidence" {
			item["sourceInfo"] = json.RawMessage(`"Identified from deployed JavaScript files and archive entries"`)
		}
		packages[i], err = json.Marshal(item)
		if err != nil {
			return nil, err
		}
		delete(byID, id.SPDXID)
	}
	if len(byID) != 0 {
		return nil, fmt.Errorf("some SPDX package references could not be associated with collection evidence")
	}
	var err error
	document["packages"], err = json.Marshal(packages)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(document, "", "  ")
}
