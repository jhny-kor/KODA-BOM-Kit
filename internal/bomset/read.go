// Package bomset partitions recorded CycloneDX inventory and preserves the
// source graph for a subsequent merge of the same collected snapshot.
package bomset

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"koda.local/security-sbom-linux/internal/evidencefile"
)

const ManifestFilename = "bom-set.json"

const maxRecordBytes = 64 << 20

type object map[string]json.RawMessage

type member struct {
	Ref     string   `json:"ref"`
	Profile string   `json:"profile"`
	SHA256  string   `json:"sha256"`
	Refs    []string `json:"refs"`
}

type relationship struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}

type source struct {
	Kind          string          `json:"kind"`
	SHA256        string          `json:"sha256"`
	Header        object          `json:"header"`
	Components    []member        `json:"components"`
	Services      []member        `json:"services"`
	Dependencies  []relationship  `json:"dependencies"`
	Normalization []normalization `json:"normalization,omitempty"`
}

type profile struct {
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
}

type version struct {
	SpecVersion   string    `json:"specVersion"`
	Sources       []source  `json:"sources"`
	Profiles      []profile `json:"profiles"`
	Relationships profile   `json:"relationships"`
}

type manifest struct {
	Schema   string    `json:"schema"`
	Versions []version `json:"versions"`
}

type position struct{ offset, length int64 }

type spool struct {
	file *os.File
	rows map[string]position
	ctx  context.Context
}

func newSpool(dir string) (*spool, error) {
	f, err := os.CreateTemp(dir, ".bom-set-*")
	if err != nil {
		return nil, err
	}
	return &spool{file: f, rows: map[string]position{}}, nil
}

func (s *spool) close() {
	name := s.file.Name()
	s.file.Close()
	os.Remove(name)
}

func (s *spool) put(raw json.RawMessage) (string, error) {
	if s.ctx != nil {
		if err := s.ctx.Err(); err != nil {
			return "", err
		}
	}
	// Canonicalize each record so insignificant JSON whitespace never changes
	// duplicate detection or the per-entity identity recorded in the manifest.
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	return key, s.cacheRecord(key, data)
}

func (s *spool) get(key string) (json.RawMessage, error) {
	if s.ctx != nil {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
	}
	pos, ok := s.rows[key]
	if !ok {
		return nil, fmt.Errorf("missing BOM entity")
	}
	data := make([]byte, pos.length)
	_, err := s.file.ReadAt(data, pos.offset)
	return data, err
}

type limitedRecordReader struct {
	ctx       context.Context
	r         io.Reader
	remaining int64
}

func (r *limitedRecordReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		return 0, fmt.Errorf("CycloneDX record exceeds %d bytes", maxRecordBytes)
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func readDocument(ctx context.Context, root *os.Root, filename string, expected string, visit func(string, json.RawMessage) error) (string, error) {
	f, err := evidencefile.OpenRoot(root, filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("BOM input must be a regular file")
	}
	h := sha256.New()
	r := &limitedRecordReader{ctx: ctx, r: io.TeeReader(f, h), remaining: maxRecordBytes}
	dec := json.NewDecoder(r)
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return "", fmt.Errorf("BOM input must be an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		r.remaining = maxRecordBytes
		token, err = dec.Token()
		if err != nil {
			return "", err
		}
		field, ok := token.(string)
		if !ok || seen[field] {
			return "", fmt.Errorf("duplicate or invalid CycloneDX field")
		}
		seen[field] = true
		if field != "components" && field != "services" && field != "dependencies" {
			var raw json.RawMessage
			r.remaining = maxRecordBytes
			if err = dec.Decode(&raw); err != nil {
				return "", err
			}
			if len(raw) > maxRecordBytes {
				return "", fmt.Errorf("oversized CycloneDX header")
			}
			if err = visit(field, raw); err != nil {
				return "", err
			}
			continue
		}
		token, err = dec.Token()
		if err != nil || token != json.Delim('[') {
			return "", fmt.Errorf("CycloneDX %s must be an array", field)
		}
		for dec.More() {
			r.remaining = maxRecordBytes
			var raw json.RawMessage
			if err = dec.Decode(&raw); err != nil {
				return "", err
			}
			if len(raw) > maxRecordBytes {
				return "", fmt.Errorf("oversized CycloneDX entity")
			}
			if err = visit(field, raw); err != nil {
				return "", err
			}
		}
		if _, err = dec.Token(); err != nil {
			return "", err
		}
	}
	if _, err = dec.Token(); err != nil {
		return "", err
	}
	r.remaining = maxRecordBytes
	if _, err = dec.Token(); err != io.EOF {
		return "", fmt.Errorf("trailing CycloneDX content")
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("checksum mismatch for %s", filename)
	}
	return actual, nil
}

func checksums(root *os.Root) (map[string]string, error) {
	f, err := evidencefile.OpenRoot(root, "SHA256SUMS")
	if err != nil {
		return nil, fmt.Errorf("source SHA256SUMS required: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("invalid checksum manifest")
	}
	result := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20+1))
	for scanner.Scan() {
		sum, name, ok := strings.Cut(scanner.Text(), "  ")
		decoded, decodeErr := hex.DecodeString(sum)
		if !ok || decodeErr != nil || len(decoded) != sha256.Size || name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." || result[name] != "" {
			return nil, fmt.Errorf("invalid checksum entry")
		}
		result[name] = strings.ToLower(sum)
	}
	return result, scanner.Err()
}

func stringValue(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func entityRefs(raw json.RawMessage, field string) ([]string, error) {
	var row object
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	ref := stringValue(row["bom-ref"])
	if ref == "" {
		return nil, fmt.Errorf("CycloneDX entity is missing bom-ref")
	}
	refs := []string{ref}
	if child := row[field]; len(child) > 0 {
		var children []json.RawMessage
		if err := json.Unmarshal(child, &children); err != nil {
			return nil, err
		}
		for _, data := range children {
			found, err := entityRefs(data, field)
			if err != nil {
				return nil, err
			}
			refs = append(refs, found...)
		}
	}
	return refs, nil
}

func rootRefs(header object) ([]string, error) {
	var metadata object
	if err := json.Unmarshal(header["metadata"], &metadata); err != nil {
		return nil, fmt.Errorf("CycloneDX metadata required")
	}
	if len(metadata["component"]) == 0 {
		return nil, nil
	}
	return entityRefs(metadata["component"], "components")
}

func readSource(ctx context.Context, root *os.Root, filename, expected, kind, spec string, data *spool) (source, error) {
	s := source{Kind: kind, Header: object{}, Components: []member{}, Services: []member{}, Dependencies: []relationship{}}
	var err error
	s.SHA256, err = readDocument(ctx, root, filename, expected, func(field string, raw json.RawMessage) error {
		switch field {
		case "components", "services":
			refs, err := entityRefs(raw, field)
			if err != nil {
				return err
			}
			hash, err := data.put(raw)
			if err != nil {
				return err
			}
			profile := classify(raw, field)
			if kind == "operations" || domainKind(kind) {
				profile = sourceProfile(kind)
			}
			m := member{Ref: refs[0], Profile: profile, SHA256: hash, Refs: refs}
			if field == "components" {
				s.Components = append(s.Components, m)
			} else {
				s.Services = append(s.Services, m)
			}
		case "dependencies":
			d, err := data.putRelationship(raw)
			if err != nil {
				return err
			}
			s.Dependencies = append(s.Dependencies, d)
		default:
			s.Header[field] = raw
		}
		return nil
	})
	if err != nil {
		return source{}, err
	}
	if stringValue(s.Header["bomFormat"]) != "CycloneDX" || stringValue(s.Header["specVersion"]) != spec {
		return source{}, fmt.Errorf("expected CycloneDX %s source", spec)
	}
	if err = normalizeDuplicates(&s, data); err != nil {
		return source{}, err
	}
	if kind == "inventory" {
		if err = classifyServices(&s, data); err != nil {
			return source{}, err
		}
	}
	if err = validateSource(s, data); err != nil {
		return source{}, err
	}
	if domainKind(s.Kind) {
		if err = validateDomainEntities(s, data); err != nil {
			return source{}, err
		}
	}
	return s, nil
}

func (s *spool) putRelationship(raw json.RawMessage) (relationship, error) {
	var d struct{ Ref string }
	if err := json.Unmarshal(raw, &d); err != nil {
		return relationship{}, err
	}
	if d.Ref == "" {
		return relationship{}, fmt.Errorf("dependency is missing ref")
	}
	hash, err := s.put(raw)
	return relationship{Ref: d.Ref, SHA256: hash}, err
}

func classifyServices(s *source, data *spool) error {
	if len(s.Services) == 0 {
		return nil
	}
	services := map[string]bool{}
	for _, m := range s.Services {
		for _, ref := range m.Refs {
			services[ref] = true
		}
	}
	crypto := map[string]bool{}
	for _, m := range s.Components {
		if m.Profile == "cbom" {
			for _, ref := range m.Refs {
				crypto[ref] = true
			}
		}
	}
	consumers := map[string]bool{}
	for _, dependency := range s.Dependencies {
		if !services[dependency.Ref] {
			continue
		}
		raw, err := data.get(dependency.SHA256)
		if err != nil {
			return err
		}
		var row struct {
			Ref       string
			DependsOn []string
		}
		if json.Unmarshal(raw, &row) != nil {
			continue
		}
		for _, ref := range row.DependsOn {
			if crypto[ref] {
				consumers[row.Ref] = true
			}
		}
	}
	for i := range s.Services {
		if consumers[s.Services[i].Ref] {
			s.Services[i].Profile = "cbom"
		}
	}
	return nil
}

func validateCryptoRefs(raw json.RawMessage, known map[string]bool) error {
	var component struct {
		Crypto     map[string]any    `json:"cryptoProperties"`
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(raw, &component); err != nil {
		return err
	}
	var visit func(any) error
	visit = func(value any) error {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if strings.HasSuffix(key, "Ref") {
					ref, ok := child.(string)
					if !ok || !known[ref] {
						return fmt.Errorf("unresolved cryptographic profile reference")
					}
				}
				if strings.HasSuffix(key, "RefArray") || key == "algorithms" || key == "relatedCryptoMaterials" || key == "encr" || key == "prf" || key == "integ" || key == "ke" || key == "auth" {
					if refs, ok := child.([]any); ok {
						for _, v := range refs {
							if ref, ok := v.(string); ok && !known[ref] {
								return fmt.Errorf("unresolved cryptographic profile reference")
							}
						}
					}
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(component.Crypto); err != nil {
		return err
	}
	for _, child := range component.Components {
		if err := validateCryptoRefs(child, known); err != nil {
			return err
		}
	}
	return nil
}

func classify(raw json.RawMessage, field string) string {
	var row struct {
		Type       string                  `json:"type"`
		Properties []struct{ Name string } `json:"properties"`
	}
	_ = json.Unmarshal(raw, &row)
	if field == "services" {
		for _, p := range row.Properties {
			if strings.HasPrefix(p.Name, "koda:crypto:") {
				return "cbom"
			}
		}
		return "sbom"
	}
	switch row.Type {
	case "device", "device-driver", "firmware":
		return "hbom"
	case "cryptographic-asset":
		return "cbom"
	default:
		return "sbom"
	}
}

func validateSource(s source, data *spool) error {
	if err := validateDomainKind(s); err != nil {
		return err
	}
	refs, err := rootRefs(s.Header)
	if err != nil {
		return err
	}
	for _, m := range append(append([]member{}, s.Components...), s.Services...) {
		refs = append(refs, m.Refs...)
	}
	formRefs, err := formulationReferences(s.Header)
	if err != nil {
		return err
	}
	refs = append(refs, formRefs...)
	known := map[string]bool{}
	for _, ref := range refs {
		if known[ref] {
			return fmt.Errorf("duplicate source bom-ref")
		}
		known[ref] = true
	}
	if err = validateDomainReferences(s.Header["formulation"], known); err != nil {
		return err
	}
	for _, dependency := range s.Dependencies {
		raw, readErr := data.get(dependency.SHA256)
		if readErr != nil {
			return readErr
		}
		var d struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
			Provides  []string `json:"provides"`
		}
		if err = json.Unmarshal(raw, &d); err != nil {
			return err
		}
		if d.Ref != dependency.Ref {
			return fmt.Errorf("dependency reference differs from manifest")
		}
		for _, ref := range append(append([]string{d.Ref}, d.DependsOn...), d.Provides...) {
			if !known[ref] && !strings.HasPrefix(ref, "urn:cdx:") {
				return fmt.Errorf("unresolved source dependency")
			}
		}
	}
	return nil
}
