package reconcile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// BuildInventory is a bounded supplier declaration bound to an artifact digest.
// Its identities and relationships remain declarations even when the digest matches.
type BuildInventory struct {
	SHA256   string
	Document map[string]any
}

// ReadBuildInventory uses the same strict subject and input validation as the
// deployment reconciler, then preserves the resolvable declared dependency graph.
func ReadBuildInventory(r io.Reader) (BuildInventory, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxSupplierBytes+1))
	if err != nil {
		return BuildInventory{}, ErrSupplierRead
	}
	if len(raw) > MaxSupplierBytes {
		return BuildInventory{}, ErrSupplierSize
	}
	supplier, err := ReadSupplier(bytes.NewReader(raw))
	if err != nil {
		return BuildInventory{}, err
	}
	b := buildGraph{refs: map[string]string{}, edges: map[string]map[string]bool{}, components: []map[string]any{}, usedRefs: map[string]bool{}}
	var subject map[string]any
	if supplier.Format == "cyclonedx-json" {
		subject, err = b.cycloneDX(raw)
	} else {
		subject, err = b.spdx(raw)
	}
	if err != nil {
		return BuildInventory{}, err
	}
	if b.invalidRefs {
		return BuildInventory{}, ErrSupplierInventory
	}
	subject["hashes"] = []map[string]string{{"alg": "SHA-256", "content": supplier.SHA256}}
	props := []map[string]string{
		{"name": "koda:build:evidence", "value": "supplier-declared"},
		{"name": "koda:build:source-format", "value": supplier.Format},
		{"name": "koda:build:unresolved-identities", "value": fmt.Sprint(b.unresolvedIdentities)},
		{"name": "koda:build:unresolved-relationships", "value": fmt.Sprint(b.unresolvedRelationships)},
	}
	dependencies := []map[string]any{}
	sources := make([]string, 0, len(b.edges))
	for ref := range b.edges {
		sources = append(sources, ref)
	}
	sort.Strings(sources)
	for _, ref := range sources {
		targets := make([]string, 0, len(b.edges[ref]))
		for target := range b.edges[ref] {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		dependencies = append(dependencies, map[string]any{"ref": ref, "dependsOn": targets})
	}
	aggregate := "unknown"
	if b.unresolvedIdentities+b.unresolvedRelationships > 0 {
		aggregate = "incomplete"
	}
	return BuildInventory{SHA256: supplier.SHA256, Document: map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata":   map[string]any{"component": subject, "lifecycles": []map[string]string{{"phase": "build"}}, "properties": props},
		"components": b.components, "dependencies": dependencies, "compositions": []map[string]string{{"aggregate": aggregate}},
	}}, nil
}

type buildGraph struct {
	usedRefs                                      map[string]bool
	invalidRefs                                   bool
	refs                                          map[string]string
	components                                    []map[string]any
	edges                                         map[string]map[string]bool
	unresolvedIdentities, unresolvedRelationships int
	next                                          int
}

func (b *buildGraph) component(ref, kind string, c Component) map[string]any {
	b.next++
	outputRef := fmt.Sprintf("build-component-%d", b.next)
	// Keep bounded source IDs so consumers can correlate the declared graph.
	if clean := safeIdentityText(ref); clean != "" {
		outputRef = clean
	}
	if b.usedRefs[outputRef] {
		b.invalidRefs = true
	}
	b.usedRefs[outputRef] = true
	if ref != "" {
		b.refs[ref] = outputRef
	}
	if c.Name == "" {
		c.Name = "unidentified declared component"
	}
	purl, issue := comparableIdentity(c)
	properties := []map[string]string{{"name": "koda:build:observation", "value": "declared"}}
	if issue != "" {
		b.unresolvedIdentities++
		properties = append(properties, map[string]string{"name": "koda:build:identity-issue", "value": issue})
	}
	switch kind {
	case "application", "framework", "library", "container", "operating-system", "device", "firmware", "file":
	default:
		kind = "library"
	}
	row := map[string]any{"bom-ref": outputRef, "type": kind, "name": c.Name, "properties": properties}
	if c.Version != "" {
		row["version"] = c.Version
	}
	if purl != "" {
		row["purl"] = purl
	}
	return row
}

func (b *buildGraph) edge(from, to string) {
	source, target := b.refs[from], b.refs[to]
	if source == "" || target == "" {
		b.unresolvedRelationships++
		return
	}
	if b.edges[source] == nil {
		b.edges[source] = map[string]bool{}
	}
	b.edges[source][target] = true
}

func (b *buildGraph) cycloneDX(raw []byte) (map[string]any, error) {
	type component struct {
		Licenses                  []buildLicense `json:"licenses"`
		Ref                       string         `json:"bom-ref"`
		Type, Name, Version, PURL string
		Components                []*component
	}
	var input struct {
		Metadata     struct{ Component *component }
		Components   []*component
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if json.Unmarshal(raw, &input) != nil {
		return nil, ErrSupplierJSON
	}
	root := input.Metadata.Component
	subject := b.component(root.Ref, root.Type, supplierComponent(root.Name, root.Version, root.PURL, ""))
	copyBuildLicenses(subject, root.Licenses)
	var children func([]*component) []map[string]any
	children = func(items []*component) []map[string]any {
		rows := []map[string]any{}
		for _, item := range items {
			row := b.component(item.Ref, item.Type, supplierComponent(item.Name, item.Version, item.PURL, ""))
			copyBuildLicenses(row, item.Licenses)
			if len(item.Components) > 0 {
				row["components"] = children(item.Components)
			}
			rows = append(rows, row)
		}
		return rows
	}
	if len(root.Components) > 0 {
		subject["components"] = children(root.Components)
	}
	b.components = children(input.Components)
	for _, dep := range input.Dependencies {
		if len(dep.DependsOn) == 0 {
			if ref := b.refs[dep.Ref]; ref != "" {
				if b.edges[ref] == nil {
					b.edges[ref] = map[string]bool{}
				}
			} else {
				b.unresolvedRelationships++
			}
		}
		for _, target := range dep.DependsOn {
			b.edge(dep.Ref, target)
		}
	}
	return subject, nil
}

func (b *buildGraph) spdx(raw []byte) (map[string]any, error) {
	var input struct {
		Describes     []string `json:"documentDescribes"`
		Packages      []*spdxSupplierPackage
		Relationships []struct {
			From string `json:"spdxElementId"`
			Type string `json:"relationshipType"`
			To   string `json:"relatedSpdxElement"`
		}
	}
	if json.Unmarshal(raw, &input) != nil {
		return nil, ErrSupplierJSON
	}
	subjectID := ""
	if len(input.Describes) > 0 {
		subjectID = input.Describes[0]
	}
	for _, r := range input.Relationships {
		if r.From == spdxDocumentID && r.Type == "DESCRIBES" {
			subjectID = r.To
		}
		if r.To == spdxDocumentID && r.Type == "DESCRIBED_BY" {
			subjectID = r.From
		}
	}
	var subject map[string]any
	for _, item := range input.Packages {
		kind := "library"
		if item.ID == subjectID {
			kind = "application"
		}
		row := b.component(item.ID, kind, item.component())
		license := item.LicenseDeclared
		if license == "" || license == "NOASSERTION" {
			license = item.LicenseConcluded
		}
		if license != "" && license != "NOASSERTION" && license != "NONE" {
			copyBuildLicenses(row, []buildLicense{{Expression: license}})
		}
		if item.ID == subjectID {
			subject = row
		} else {
			b.components = append(b.components, row)
		}
	}
	for _, r := range input.Relationships {
		switch r.Type {
		case "DEPENDS_ON":
			b.edge(r.From, r.To)
		case "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF":
			b.edge(r.To, r.From)
		case "DESCRIBES", "DESCRIBED_BY":
		default:
			b.unresolvedRelationships++
		}
	}
	return subject, nil
}

// License URLs and arbitrary license text are excluded from declarations. Names
// and SPDX expressions preserve the supplier's bounded licensing assertions.
type buildLicense struct {
	Expression string `json:"expression"`
	License    *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
}

func copyBuildLicenses(row map[string]any, source []buildLicense) {
	licenses := []map[string]any{}
	for _, license := range source {
		if expression := safeIdentityText(license.Expression); expression != "" {
			if len(source) != 1 {
				row["properties"] = append(row["properties"].([]map[string]string), map[string]string{"name": "koda:build:license-issue", "value": "unsupported_license_combination"})
				return
			}
			row["licenses"] = []map[string]any{{"expression": expression}}
			return
		}
		if license.License == nil {
			continue
		}
		name := license.License.Name
		if name == "" {
			name = license.License.ID
		}
		if name = safeIdentityText(name); name != "" {
			licenses = append(licenses, map[string]any{"license": map[string]string{"name": name}})
		}
	}
	if len(licenses) > 0 {
		row["licenses"] = licenses
	}
}
