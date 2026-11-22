package bomset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type normalization struct {
	OriginalRef       string         `json:"originalRef"`
	Occurrences       int            `json:"occurrences"`
	Candidates        []string       `json:"candidates,omitempty"`
	Ambiguous         bool           `json:"ambiguous,omitempty"`
	RecordOccurrences map[string]int `json:"recordOccurrences"`
}

// Older collectors could emit the same certificate more than once, including
// distinct positions within one PEM file under the same reference. Keep each
// distinct payload and explicitly preserve the original identity. References
// to conflicting payloads resolve to an ambiguity record, never to an arbitrarily
// selected payload. Unreferenced conflicts only need the distinct candidates.
func normalizeDuplicates(s *source, data *spool) error {
	groups := map[string][]member{}
	fields := map[string]string{}
	for _, pair := range []struct {
		field string
		rows  []member
	}{{"components", s.Components}, {"services", s.Services}} {
		for _, m := range pair.rows {
			if old := fields[m.Ref]; old != "" && old != pair.field {
				return fmt.Errorf("component and service share a source reference")
			}
			fields[m.Ref] = pair.field
			groups[m.Ref] = append(groups[m.Ref], m)
		}
	}
	duplicates := []string{}
	for ref, members := range groups {
		if len(members) > 1 {
			duplicates = append(duplicates, ref)
		}
	}
	if len(duplicates) == 0 {
		return nil
	}
	sort.Strings(duplicates)
	referenced := map[string]bool{}
	for _, ref := range duplicates {
		referenced[ref] = false
	}
	quotedRefs := make([][]byte, 0, len(duplicates))
	for _, ref := range duplicates {
		encoded, _ := json.Marshal(ref)
		quotedRefs = append(quotedRefs, encoded)
	}
	containsDuplicateRef := func(raw []byte) bool {
		for _, ref := range quotedRefs {
			if bytes.Contains(raw, ref) {
				return true
			}
		}
		return false
	}
	for _, dependency := range s.Dependencies {
		raw, err := data.get(dependency.SHA256)
		if err != nil {
			return err
		}
		if !containsDuplicateRef(raw) {
			continue
		}
		var row struct {
			Ref       string
			DependsOn []string
			Provides  []string
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		for _, ref := range append(append([]string{row.Ref}, row.DependsOn...), row.Provides...) {
			if _, exists := referenced[ref]; exists {
				referenced[ref] = true
			}
		}
	}
	for _, m := range s.Components {
		raw, err := data.get(m.SHA256)
		if err != nil {
			return err
		}
		if !containsDuplicateRef(raw) {
			continue
		}
		var value any
		if err = json.Unmarshal(raw, &value); err != nil {
			return err
		}
		markReferences(value, referenced)
	}
	var header any
	raw, _ := json.Marshal(s.Header)
	if err := json.Unmarshal(raw, &header); err != nil {
		return err
	}
	markReferences(header, referenced)
	replacements := map[string][]member{}
	for _, ref := range duplicates {
		members := groups[ref]
		unique := map[string]member{}
		var candidates []member
		for _, m := range members {
			if _, exists := unique[m.SHA256]; !exists {
				unique[m.SHA256] = m
				candidates = append(candidates, m)
			}
		}
		n := normalization{OriginalRef: ref, Occurrences: len(members), RecordOccurrences: map[string]int{}}
		for _, m := range members {
			n.RecordOccurrences[m.SHA256]++
		}
		if len(candidates) == 1 {
			replacements[ref] = candidates
			s.Normalization = append(s.Normalization, n)
			continue
		}
		for _, candidate := range candidates {
			raw, err := data.get(candidate.SHA256)
			if err != nil {
				return err
			}
			sum := sha256.Sum256([]byte(ref + "\x00" + candidate.SHA256))
			newRef := "koda-bom-candidate-" + hex.EncodeToString(sum[:16])
			var row object
			if err = json.Unmarshal(raw, &row); err != nil {
				return err
			}
			row["bom-ref"], _ = json.Marshal(newRef)
			var properties []map[string]string
			if old := row["properties"]; len(old) > 0 {
				if err = json.Unmarshal(old, &properties); err != nil {
					return err
				}
			}
			properties = append(properties, map[string]string{"name": "koda:bom:original-ref", "value": ref}, map[string]string{"name": "koda:bom:source-record-sha256", "value": candidate.SHA256})
			row["properties"], _ = json.Marshal(properties)
			encoded, _ := json.Marshal(row)
			candidate.Ref = newRef
			candidate.Refs, err = entityRefs(encoded, fields[ref])
			if err != nil {
				return err
			}
			candidate.SHA256, err = data.put(encoded)
			if err != nil {
				return err
			}
			replacements[ref] = append(replacements[ref], candidate)
			n.Candidates = append(n.Candidates, newRef)
		}
		if referenced[ref] {
			n.Ambiguous = true
			list, _ := json.Marshal(n.Candidates)
			row := map[string]any{"bom-ref": ref, "name": "Ambiguous source reference", "properties": []map[string]string{
				{"name": "koda:bom:reference-state", "value": "ambiguous"},
				{"name": "koda:bom:candidate-refs", "value": string(list)},
			}}
			if fields[ref] == "components" {
				raw, err := data.get(candidates[0].SHA256)
				if err != nil {
					return err
				}
				var original struct{ Type string }
				if err = json.Unmarshal(raw, &original); err != nil {
					return err
				}
				row["type"] = original.Type
			}
			encoded, _ := json.Marshal(row)
			hash, err := data.put(encoded)
			if err != nil {
				return err
			}
			replacements[ref] = append(replacements[ref], member{Ref: ref, Profile: candidates[0].Profile, SHA256: hash, Refs: []string{ref}})
		}
		s.Normalization = append(s.Normalization, n)
	}
	for _, rows := range []*[]member{&s.Components, &s.Services} {
		seen := map[string]bool{}
		result := []member{}
		for _, m := range *rows {
			if replacement, exists := replacements[m.Ref]; exists {
				if !seen[m.Ref] {
					result = append(result, replacement...)
					seen[m.Ref] = true
				}
			} else {
				result = append(result, m)
			}
		}
		*rows = result
	}
	return nil
}

func markReferences(value any, refs map[string]bool) {
	switch value := value.(type) {
	case map[string]any:
		if name, ok := value["name"].(string); ok && (name == "koda:obom:scope" || name == "koda:obom:executable-package" || name == "koda:asset:parent-id") {
			markReferenceValues(value["value"], refs)
		}
		for key, child := range value {
			if key == "bom-ref" {
				continue
			}
			if key == "ref" || strings.HasSuffix(key, "Ref") || strings.HasSuffix(key, "RefArray") {
				markReferenceValues(child, refs)
			}
			switch key {
			case "dependsOn", "provides", "assemblies", "dependencies", "vulnerabilities", "algorithms", "relatedCryptoMaterials", "encr", "prf", "integ", "ke", "auth":
				markReferenceValues(child, refs)
			}
			markReferences(child, refs)
		}
	case []any:
		for _, child := range value {
			markReferences(child, refs)
		}
	}
}

func markReferenceValues(value any, refs map[string]bool) {
	switch value := value.(type) {
	case string:
		if _, exists := refs[value]; exists {
			refs[value] = true
		}
	case []any:
		for _, child := range value {
			markReferenceValues(child, refs)
		}
	}
}
