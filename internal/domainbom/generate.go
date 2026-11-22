// Package domainbom converts explicit local service, model and build evidence
// into CycloneDX documents. Imported declarations retain their source digest.
package domainbom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/localfs"
)

const maxEvidenceBytes = 16 << 20
const maxItems = 10000

type ModelInput struct{ Evidence, Artifact string }
type ProvenanceInput struct{ Evidence, Artifact string }
type Options struct {
	SaaS       []string
	Models     []ModelInput
	Provenance []ProvenanceInput
	Include17  bool
}
type object = map[string]any
type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func prop(name, value string) property { return property{"koda:domain:" + name, value} }

type document struct {
	components   []object
	services     []object
	dependencies []object
	formulas     []object
	sources      []property
	seen         map[string]bool
}

func newDocument() *document { return &document{seen: map[string]bool{}} }
func (d *document) add(items *[]object, item object) {
	ref, _ := item["bom-ref"].(string)
	if !d.seen[ref] {
		*items = append(*items, item)
		d.seen[ref] = true
	}
}
func (d *document) edge(ref string, targets []string) {
	if len(targets) == 0 {
		return
	}
	sort.Strings(targets)
	d.dependencies = append(d.dependencies, object{"ref": ref, "dependsOn": targets})
}
func ref(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "koda-domain-" + hex.EncodeToString(h[:16])
}

// Generate validates every supplied input before returning any output. The
// caller publishes the returned files together and includes them in checksums.
func Generate(ctx context.Context, opts Options) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(opts.SaaS)+len(opts.Models)+len(opts.Provenance) > 12 {
		return nil, fmt.Errorf("at most 12 domain evidence inputs are supported")
	}
	docs := map[string]*document{}
	for _, path := range opts.SaaS {
		if docs["saasbom"] == nil {
			docs["saasbom"] = newDocument()
		}
		if err := loadServices(ctx, path, docs["saasbom"]); err != nil {
			return nil, fmt.Errorf("SaaSBOM: %w", err)
		}
	}
	for _, input := range opts.Models {
		if docs["aibom"] == nil {
			docs["aibom"] = newDocument()
		}
		if err := loadModel(ctx, input, docs["aibom"]); err != nil {
			return nil, fmt.Errorf("ML-BOM: %w", err)
		}
	}
	for _, input := range opts.Provenance {
		if docs["mbom"] == nil {
			docs["mbom"] = newDocument()
		}
		if err := loadProvenance(ctx, input, docs["mbom"]); err != nil {
			return nil, fmt.Errorf("MBOM: %w", err)
		}
	}
	out := map[string][]byte{}
	for name, d := range docs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(d.seen) > maxItems {
			return nil, fmt.Errorf("domain inventory exceeds item limit")
		}
		sort.Slice(d.components, func(i, j int) bool { return d.components[i]["bom-ref"].(string) < d.components[j]["bom-ref"].(string) })
		sort.Slice(d.services, func(i, j int) bool { return d.services[i]["bom-ref"].(string) < d.services[j]["bom-ref"].(string) })
		props := append([]property{prop("kind", name), prop("coverage", "supplied evidence and explicitly selected local artifacts"), prop("authenticity", "source signatures are unverified")}, d.sources...)
		doc := object{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": object{"properties": props}, "compositions": []object{{"aggregate": "incomplete"}}}
		if len(d.components) > 0 {
			doc["components"] = d.components
		}
		if len(d.services) > 0 {
			doc["services"] = d.services
		}
		if len(d.dependencies) > 0 {
			doc["dependencies"] = d.dependencies
		}
		if len(d.formulas) > 0 {
			doc["formulation"] = d.formulas
		}
		versions := []string{"1.6"}
		if opts.Include17 {
			versions = append(versions, "1.7")
		}
		for _, version := range versions {
			doc["specVersion"] = version
			raw, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				return nil, err
			}
			suffix := ".cdx.json"
			if version == "1.7" {
				suffix = ".cdx-1.7.json"
			}
			out[name+suffix] = append(raw, '\n')
		}
	}
	return out, nil
}

func readEvidence(ctx context.Context, path string) ([]byte, string, error) {
	raw, sum, err := readEvidenceBytes(ctx, path)
	if err != nil {
		return nil, "", err
	}
	if err := uniqueJSON(raw); err != nil {
		return nil, "", err
	}
	return raw, sum, nil
}

// readEvidenceBytes reads a bounded regular file without interpreting it.
func readEvidenceBytes(ctx context.Context, path string) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	path, err := localfs.ResolveLocal(path)
	if err != nil {
		return nil, "", err
	}
	f, err := evidencefile.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return nil, "", fmt.Errorf("evidence must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(&contextReader{ctx, f}, maxEvidenceBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > maxEvidenceBytes {
		return nil, "", fmt.Errorf("evidence exceeds 16 MiB")
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(b)
}
func strict(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

// Duplicate object keys are ambiguous for identity, digests, and relationships.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("JSON nesting exceeds limit")
		}
		tok, err := d.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				if err != nil {
					return fmt.Errorf("invalid JSON object")
				}
				s, ok := key.(string)
				if !ok || keys[s] {
					return fmt.Errorf("duplicate or invalid JSON key")
				}
				keys[s] = true
			}
			if err := walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("extra JSON content")
	}
	return nil
}
func textOK(s string, required bool) bool {
	return (!required || s != "") && len(s) <= 2048 && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) == -1
}
func safeURI(s string) bool {
	if !textOK(s, true) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "{") && !strings.Contains(s, "}") &&
		((u.Host != "" && (u.Scheme == "https" || u.Scheme == "http" || u.Scheme == "git+https")) || (u.Scheme == "urn" && u.Opaque != ""))
}
func digestOK(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}
func hashes(sha string) []object { return []object{{"alg": "SHA-256", "content": sha}} }
func openArtifact(ctx context.Context, path, expected string) (*os.File, string, os.FileInfo, error) {
	if path == "" {
		return nil, "", nil, fmt.Errorf("local artifact is required")
	}
	resolved, err := localfs.ResolveLocal(path)
	if err != nil {
		return nil, "", nil, err
	}
	f, err := evidencefile.Open(resolved)
	if err != nil {
		return nil, "", nil, err
	}
	fail := func(err error) (*os.File, string, os.FileInfo, error) { f.Close(); return nil, "", nil, err }
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return fail(fmt.Errorf("artifact must be a regular file"))
	}
	h := sha256.New()
	if _, err = io.Copy(h, &contextReader{ctx, f}); err != nil {
		return fail(err)
	}
	after, err := f.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fail(fmt.Errorf("artifact changed during hashing"))
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if expected != "" && actual != expected {
		return fail(fmt.Errorf("artifact SHA-256 differs from supplied evidence"))
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, actual, before, nil
}
