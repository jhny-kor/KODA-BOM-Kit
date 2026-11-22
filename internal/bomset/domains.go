package bomset

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

var domainKinds = []string{"saasbom", "aibom", "mbom"}
var readableDomainKinds = append(slices.Clone(domainKinds), "mlbom")

func domainKind(kind string) bool {
	return slices.Contains(readableDomainKinds, kind)
}

// canonicalDomain maps the historical model profile name for newly split sets.
func canonicalDomain(kind string) string {
	if kind == "mlbom" {
		return "aibom"
	}
	return kind
}

func sourceProfile(kind string) string {
	if kind == "operations" {
		return "obom"
	}
	return kind
}

func profileSource(kind string) string {
	switch kind {
	case "sbom", "hbom", "cbom":
		return "inventory"
	case "obom":
		return "operations"
	default:
		return kind
	}
}

func discoverDomains(root *os.Root, sums map[string]string, dual bool) ([]string, error) {
	var found []string
	for _, kind := range readableDomainKinds {
		for _, spec := range []string{"1.6", "1.7"} {
			name := kind + suffix(spec)
			if _, err := root.Stat(name); err == nil && sums[name] == "" {
				return nil, fmt.Errorf("domain source %s is missing its checksum", name)
			} else if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
		base, companion := sums[kind+suffix("1.6")], sums[kind+suffix("1.7")]
		if base == "" && companion != "" {
			return nil, fmt.Errorf("domain companion %s requires its original 1.6 source", kind)
		}
		if base != "" {
			if dual && companion == "" {
				return nil, fmt.Errorf("original %s 1.7 companion required", kind)
			}
			found = append(found, kind)
		}
	}
	if sums["aibom.cdx.json"] != "" && sums["mlbom.cdx.json"] != "" {
		return nil, fmt.Errorf("both aibom and legacy mlbom sources are present")
	}
	return found, nil
}

func validateDomainKind(s source) error {
	if !domainKind(s.Kind) {
		return nil
	}
	var metadata struct {
		Properties []struct{ Name, Value string }
	}
	if err := json.Unmarshal(s.Header["metadata"], &metadata); err != nil {
		return err
	}
	found := false
	for _, p := range metadata.Properties {
		if p.Name == "koda:domain:kind" {
			if (p.Value != s.Kind && !(s.Kind == "aibom" && p.Value == "mlbom")) || found {
				return fmt.Errorf("domain source kind differs from its profile")
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("generated domain source kind is required")
	}
	return nil
}

func sameDomainCompanion(base, companion source) bool {
	a, b := copyObject(base.Header), copyObject(companion.Header)
	for _, field := range []string{"specVersion", "$schema", "serialNumber"} {
		delete(a, field)
		delete(b, field)
	}
	return sameJSON(a, b) && sameMembers(base.Components, companion.Components) &&
		sameMembers(base.Services, companion.Services) && sameJSON(base.Dependencies, companion.Dependencies)
}

func validateDomainVersions(versions []version) error {
	observations := map[string]map[string]source{}
	for _, v := range versions {
		if v.SpecVersion != "1.6" && v.SpecVersion != "1.7" {
			continue
		}
		domains := map[string]source{}
		for _, s := range v.Sources {
			if domainKind(s.Kind) {
				domains[s.Kind] = s
			}
		}
		observations[v.SpecVersion] = domains
	}
	base, hasBase := observations["1.6"]
	companion, hasCompanion := observations["1.7"]
	if !hasBase || !hasCompanion {
		return nil
	}
	for _, kind := range readableDomainKinds {
		first, inBase := base[kind]
		second, inCompanion := companion[kind]
		if inBase != inCompanion || (inBase && !sameDomainCompanion(first, second)) {
			return fmt.Errorf("domain sources differ between BOM set versions")
		}
	}
	return nil
}

func validateDomainEntities(s source, data *spool) error {
	_, _, known, err := profileMembers(s, s.Kind)
	if err != nil {
		return err
	}
	for _, m := range append(append([]member{}, s.Components...), s.Services...) {
		raw, err := data.get(m.SHA256)
		if err != nil {
			return err
		}
		if err = validateDomainReferences(raw, known); err != nil {
			return err
		}
	}
	return nil
}

// Formulation introduces its own formula, workflow, task and resource
// identities. They share the document's reference namespace with inventory.
func formulationReferences(header object) ([]string, error) {
	var values []any
	if raw := header["formulation"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, err
		}
	}
	var refs []string
	var visit func(any) error
	visit = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			if ref, exists := v["bom-ref"]; exists {
				text, ok := ref.(string)
				if !ok || text == "" {
					return fmt.Errorf("invalid formulation identity")
				}
				refs = append(refs, text)
			}
			for _, child := range v {
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(values); err != nil {
		return nil, err
	}
	return refs, nil
}

func validateDomainReferences(raw json.RawMessage, known map[string]bool) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	var check func(any) error
	check = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "ref" {
					ref, ok := child.(string)
					if !ok || (!known[ref] && !strings.HasPrefix(ref, "urn:cdx:")) {
						return fmt.Errorf("unresolved domain resource reference")
					}
				}
				if key == "dependsOn" || key == "provides" {
					refs, ok := child.([]any)
					if !ok {
						return fmt.Errorf("invalid domain dependency references")
					}
					for _, item := range refs {
						ref, ok := item.(string)
						if !ok || (!known[ref] && !strings.HasPrefix(ref, "urn:cdx:")) {
							return fmt.Errorf("unresolved domain dependency reference")
						}
					}
				}
				if err := check(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := check(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return check(value)
}

func mergeFormulations(header object, sources []source, known map[string]string) error {
	var formulas []json.RawMessage
	formulaHashes := map[string]bool{}
	for _, s := range sources {
		var rows []json.RawMessage
		if raw := s.Header["formulation"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &rows); err != nil {
				return err
			}
		}
		for _, row := range rows {
			var value any
			if err := json.Unmarshal(row, &value); err != nil {
				return err
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return err
			}
			key := string(canonical)
			if formulaHashes[key] {
				continue
			}
			wrapped, _ := json.Marshal([]json.RawMessage{row})
			refs, err := formulationReferences(object{"formulation": wrapped})
			if err != nil {
				return err
			}
			for _, ref := range refs {
				if _, exists := known[ref]; exists {
					return fmt.Errorf("conflicting formulation identity between source graphs")
				}
				known[ref] = "formulation"
			}
			formulaHashes[key] = true
			formulas = append(formulas, row)
		}
	}
	if len(formulas) > 0 {
		var err error
		header["formulation"], err = json.Marshal(formulas)
		if err != nil {
			return err
		}
	}
	refs := map[string]bool{}
	for ref := range known {
		refs[ref] = true
	}
	return validateDomainReferences(header["formulation"], refs)
}
