// Package nissbom renders a CycloneDX SBOM as the NIS-SBOM 1.0 table: the 20
// basic fields of Table 35 in the Korean "SW 공급망 보안 가이드라인 1.0" (2024).
// The guideline defines the fields and a tabular report form, not a file
// schema, so the result is one CSV row per software component.
package nissbom

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Header holds the field names of Table 35 in their order.
var Header = []string{"SBOM Standard", "SBOM Type", "CycloneDX No.", "SPDX Doc. ID", "SBOM ID", "Product Name",
	"Product Version", "Component Name", "Component Alias", "Component Version", "Component Supplier Name",
	"Component Hash", "Component Path", "SBOM Author Name", "Unique Identifier", "Dependency Relationship",
	"Timestamp", "License Name·Version", "Vul. DB", "Vul. Info"}

// Options are the fields a collected SBOM cannot know. Organization and
// Sequence form the SBOM ID "organization-YYYYMMDD-NNNNNN".
type Options struct {
	Organization, Product, ProductVersion, Author string
	Sequence                                      int
}

type entity struct {
	Name string `json:"name"`
}

type component struct {
	Ref          string  `json:"bom-ref"`
	Type         string  `json:"type"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	PURL         string  `json:"purl"`
	CPE          string  `json:"cpe"`
	Supplier     *entity `json:"supplier"`
	Manufacturer *entity `json:"manufacturer"`
	Hashes       []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Components []component `json:"components"`
}

type document struct {
	BOMFormat    string `json:"bomFormat"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp  string     `json:"timestamp"`
		Component  *component `json:"component"`
		Authors    []entity   `json:"authors"`
		Lifecycles []struct {
			Phase string `json:"phase"`
		} `json:"lifecycles"`
		Tools json.RawMessage `json:"tools"`
	} `json:"metadata"`
	Components   []component `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// Hardware, files, data and cryptographic assets are not software components.
var software = map[string]bool{"application": true, "framework": true, "library": true, "container": true,
	"operating-system": true, "firmware": true, "device-driver": true, "platform": true, "machine-learning-model": true}

// CycloneDX lifecycle phases as the SBOM types the guideline names.
var sbomTypes = map[string]string{"design": "Design", "pre-build": "Source", "build": "Build",
	"post-build": "Analyzed", "operations": "Deployed"}

// The guideline asks for SHA-256 or stronger.
var strongHash = regexp.MustCompile(`^(SHA-(256|384|512)|SHA3-|BLAKE2b-|BLAKE3)`)

var pathProperty = regexp.MustCompile(`^(syft:location:\d+:path|koda:asset:evidence:path)$`)

// A spreadsheet cell holds 32,767 characters; a base library on a
// large host has thousands of parents. List the first 50 and count the rest.
const maxParents = 50

// Rows returns the header and one row per software component.
func Rows(raw []byte, o Options) ([][]string, error) {
	var d document
	if err := json.Unmarshal(raw, &d); err != nil || d.BOMFormat != "CycloneDX" {
		return nil, errors.New("expected a CycloneDX JSON SBOM")
	}
	created, err := time.Parse(time.RFC3339, d.Metadata.Timestamp)
	if err != nil {
		return nil, errors.New("SBOM has no valid metadata.timestamp")
	}
	if o.Organization == "" || strings.ContainsFunc(o.Organization, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return nil, errors.New("organization name for the SBOM ID must be printable text")
	}
	if o.Sequence < 1 || o.Sequence > 999999 {
		return nil, errors.New("sequence must be between 1 and 999999")
	}
	if root := d.Metadata.Component; root != nil {
		if o.Product == "" {
			o.Product = root.Name
		}
		if o.ProductVersion == "" {
			o.ProductVersion = root.Version
		}
	}
	if o.Author == "" && len(d.Metadata.Authors) > 0 {
		o.Author = d.Metadata.Authors[0].Name
	}
	if o.Author == "" {
		var tools struct {
			Components []component `json:"components"`
		}
		_ = json.Unmarshal(d.Metadata.Tools, &tools) // the pre-1.5 array form names no author
		if len(tools.Components) > 0 {
			o.Author = strings.TrimSpace(tools.Components[0].Name + " " + tools.Components[0].Version)
		}
	}
	sbomType := "Deployed" // without a recorded phase: the collector observes installed software
	if len(d.Metadata.Lifecycles) > 0 && sbomTypes[d.Metadata.Lifecycles[0].Phase] != "" {
		sbomType = sbomTypes[d.Metadata.Lifecycles[0].Phase]
	}
	// Nested components, such as libraries inside an archive, are rows too.
	var all []component
	var flatten func([]component)
	flatten = func(cs []component) {
		for _, c := range cs {
			all = append(all, c)
			flatten(c.Components)
		}
	}
	flatten(d.Components)
	labels := map[string]string{}
	if root := d.Metadata.Component; root != nil {
		flatten(root.Components)
		if o.Product != "" {
			labels[root.Ref] = strings.TrimSuffix(o.Product+"@"+o.ProductVersion, "@")
		}
	}
	for _, c := range all {
		labels[c.Ref] = strings.TrimSuffix(c.Name+"@"+c.Version, "@")
	}
	parents := map[string][]string{}
	for _, dep := range d.Dependencies {
		label, known := labels[dep.Ref]
		if !known {
			continue
		}
		for _, child := range dep.DependsOn {
			parents[child] = append(parents[child], label)
		}
	}
	id := fmt.Sprintf("%s-%s-%06d", o.Organization, created.Format("20060102"), o.Sequence)
	rows := [][]string{Header}
	for _, c := range all {
		if !software[c.Type] {
			continue
		}
		var hashes, paths, licenses []string
		for _, h := range c.Hashes {
			if strongHash.MatchString(h.Alg) {
				hashes = append(hashes, h.Alg+":"+h.Content)
			}
		}
		for _, p := range c.Properties {
			if pathProperty.MatchString(p.Name) {
				paths = append(paths, p.Value)
			}
		}
		for _, l := range c.Licenses {
			for _, v := range []string{l.License.ID, l.License.Name, l.Expression} {
				if v != "" {
					licenses = append(licenses, v)
				}
			}
		}
		up := parents[c.Ref]
		sort.Strings(up)
		up = compact(up)
		if extra := len(up) - maxParents; extra > 0 {
			up = append(up[:maxParents], fmt.Sprintf("(+%d more)", extra))
		}
		identifier := c.PURL
		if identifier == "" {
			identifier = c.CPE
		}
		row := []string{"NIS 1.0",
			sbomType,
			d.SerialNumber, "", id, o.Product, o.ProductVersion, c.Name, "", c.Version, supplier(c),
			strings.Join(hashes, "; "), strings.Join(paths, "; "), o.Author, identifier, strings.Join(up, "; "),
			d.Metadata.Timestamp, strings.Join(licenses, "; "),
			"", ""} // vulnerability matching is not the collector's job
		for i, cell := range row {
			row[i] = inert(cell)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// supplier prefers what the SBOM records and falls back to the PURL namespace,
// which names the distribution or the publishing group of a package.
func supplier(c component) string {
	for _, e := range []*entity{c.Supplier, c.Manufacturer} {
		if e != nil && e.Name != "" {
			return e.Name
		}
	}
	// publisher is skipped: for distribution packages it names a maintainer.
	path, _, _ := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "#")
	path, _, _ = strings.Cut(path, "?")
	if i := strings.LastIndex(path, "@"); i > strings.LastIndex(path, "/") {
		path = path[:i]
	}
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return ""
	}
	namespace, err := url.PathUnescape(strings.Join(parts[1:len(parts)-1], "/"))
	if err != nil {
		return ""
	}
	return namespace
}

func compact(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// inert stops a spreadsheet from running a collected value as a formula.
func inert(cell string) string {
	if lead := strings.TrimLeft(cell, " \t\r\n"); lead != cell && cell[0] != ' ' || lead != "" && (strings.ContainsRune("=+-@|", rune(lead[0])) || strings.HasPrefix(lead, "＝")) {
		return "'" + cell
	}
	return cell
}

// Write emits UTF-8 CSV with a byte order mark, which spreadsheets need to
// read Korean text.
func Write(w io.Writer, rows [][]string) error {
	if _, err := io.WriteString(w, "\xEF\xBB\xBF"); err != nil {
		return err
	}
	out := csv.NewWriter(w)
	out.UseCRLF = true
	return out.WriteAll(rows)
}
