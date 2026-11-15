package collect

import (
	"bytes"
	"encoding/json"
	"strings"

	"koda.local/security-sbom-linux/internal/staticjs"
)

// Syft exposes the discovery paths as properties. Keep them for Tracker and
// also emit the standard location evidence for the KODA deployment collectors.
func addCycloneDXEvidence(raw []byte, incomplete bool, coverage []byte, allOccurrences bool) ([]byte, error) {
	hasEvidence := allOccurrences || hasOccurrenceCollector(raw)
	if !incomplete && !hasEvidence && len(coverage) == 0 {
		return raw, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if incomplete && len(document["compositions"]) == 0 {
		document["compositions"] = json.RawMessage(`[{"aggregate":"incomplete"}]`)
	}
	if len(coverage) > 0 {
		if err := addCycloneDXCoverage(document, coverage); err != nil {
			return nil, err
		}
	}
	if hasEvidence {
		var components []json.RawMessage
		if len(document["components"]) > 0 {
			if err := json.Unmarshal(document["components"], &components); err != nil {
				return nil, err
			}
		}
		for i, rawComponent := range components {
			if !allOccurrences && !hasOccurrenceCollector(rawComponent) {
				continue
			}
			component, err := addCollectorOccurrences(rawComponent, allOccurrences)
			if err != nil {
				return nil, err
			}
			components[i] = component
		}
		if components != nil {
			componentJSON, err := json.Marshal(components)
			if err != nil {
				return nil, err
			}
			document["components"] = componentJSON
		}
	}
	return json.MarshalIndent(document, "", "  ")
}

func hasOccurrenceCollector(raw []byte) bool {
	for _, name := range []string{staticjs.Collector, AIXOracleCollector, GoBinaryCollector, RustBinaryCollector, DotnetCollector, RubyCollector, javaArchiveCataloger} {
		if bytes.Contains(raw, []byte(`"`+name+`"`)) {
			return true
		}
	}
	return false
}

func addCollectorOccurrences(raw json.RawMessage, allOccurrences bool) (json.RawMessage, error) {
	var metadata struct {
		Properties []struct{ Name, Value string }
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, err
	}
	hasCollector := allOccurrences
	type occurrence struct {
		Location string `json:"location"`
	}
	nestedByLocation := map[string]string{}
	for _, property := range metadata.Properties {
		if prefix, ok := strings.CutSuffix(property.Name, ":fullPath"); ok && strings.HasPrefix(prefix, "syft:location:") && property.Value != "" {
			nestedByLocation[prefix+":path"] = property.Value
		}
	}
	var locations []occurrence
	seen := map[string]bool{}
	for _, property := range metadata.Properties {
		if property.Name == "syft:package:foundBy" && (property.Value == staticjs.Collector || property.Value == AIXOracleCollector || isDeployedCollector(property.Value) || property.Value == javaArchiveCataloger) {
			hasCollector = true
		}
		if strings.HasPrefix(property.Name, "syft:location:") && strings.HasSuffix(property.Name, ":path") && property.Value != "" {
			location := property.Value
			if nested := nestedByLocation[property.Name]; nested != "" {
				location = nested
			}
			if !seen[location] {
				seen[location] = true
				locations = append(locations, occurrence{Location: location})
			}
		}
	}
	if !hasCollector || len(locations) == 0 {
		return raw, nil
	}
	var component map[string]json.RawMessage
	if err := json.Unmarshal(raw, &component); err != nil {
		return nil, err
	}
	evidence := map[string]json.RawMessage{}
	if value := component["evidence"]; len(value) != 0 {
		if err := json.Unmarshal(value, &evidence); err != nil {
			return nil, err
		}
		if len(evidence["occurrences"]) > 0 {
			return raw, nil
		}
	}
	occurrences, err := json.Marshal(locations)
	if err != nil {
		return nil, err
	}
	evidence["occurrences"] = occurrences
	component["evidence"], err = json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	return json.Marshal(component)
}
