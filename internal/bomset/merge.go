package bomset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	"koda.local/security-sbom-linux/internal/evidencefile"
)

// Merge restores every source inventory entity and relationship, then includes
// the operations graph, available domain graphs and native formulation. It
// accepts one intact set produced by
// Split, and rejects missing, altered or conflicting identities. The caller
// creates outputDir and publishes its SHA256SUMS after success.
func Merge(ctx context.Context, setDir, outputDir string, include17 bool) (err error) {
	in, err := os.OpenRoot(setDir)
	if err != nil {
		return err
	}
	defer in.Close()
	sums, err := checksums(in)
	if err != nil {
		return err
	}
	set, err := readManifest(ctx, in, sums[ManifestFilename])
	if err != nil {
		return err
	}
	if include17 {
		if err = validateDomainVersions(set.Versions); err != nil {
			return err
		}
	}
	out, err := newOutput(outputDir)
	if err != nil {
		return err
	}
	defer func() { out.close(err == nil) }()
	data, err := newSpool(outputDir)
	if err != nil {
		return err
	}
	defer data.close()
	data.ctx = ctx
	seen := map[string]bool{}
	for _, v := range set.Versions {
		if v.SpecVersion != "1.6" && v.SpecVersion != "1.7" || seen[v.SpecVersion] {
			return fmt.Errorf("invalid or duplicate BOM set version")
		}
		seen[v.SpecVersion] = true
		if v.SpecVersion == "1.7" && !include17 {
			continue
		}
		if err = readRelationshipSidecar(ctx, in, data, v, sums); err != nil {
			return err
		}
		if err = verifyProfiles(ctx, in, v, sums, data); err != nil {
			return err
		}
		merged, mergeErr := combine(v.Sources, data)
		if mergeErr != nil {
			return mergeErr
		}
		_, err = out.write("bom"+suffix(v.SpecVersion), func(w io.Writer) error {
			return writeDocument(ctx, w, merged.Header, merged.Components, merged.Services, merged.Dependencies, data)
		})
		if err != nil {
			return err
		}
	}
	if !seen["1.6"] || include17 && !seen["1.7"] {
		return fmt.Errorf("requested original CycloneDX version unavailable in BOM set")
	}
	return nil
}

func readManifest(ctx context.Context, root *os.Root, expected string) (manifest, error) {
	f, err := evidencefile.OpenRoot(root, ManifestFilename)
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 512<<20 {
		return manifest{}, fmt.Errorf("invalid or oversized BOM set manifest")
	}
	h := sha256.New()
	r := &limitedRecordReader{ctx: ctx, r: io.TeeReader(io.LimitReader(f, 512<<20+1), h), remaining: 512<<20 + 1}
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var m manifest
	if err = dec.Decode(&m); err != nil {
		return manifest{}, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return manifest{}, fmt.Errorf("trailing BOM set manifest content")
	}
	if expected == "" || hex.EncodeToString(h.Sum(nil)) != expected {
		return manifest{}, fmt.Errorf("BOM set manifest checksum mismatch")
	}
	if m.Schema != "koda-bom-set-1" {
		return manifest{}, fmt.Errorf("unsupported BOM set manifest")
	}
	return m, nil
}

func verifyProfiles(ctx context.Context, root *os.Root, v version, sums map[string]string, data *spool) error {
	if len(v.Sources) < 1 || len(v.Sources) > 5 || v.Sources[0].Kind != "inventory" {
		return fmt.Errorf("BOM set requires one inventory source and optional operations and domain sources")
	}
	sources := map[string]source{}
	canonicalSources := map[string]bool{}
	for _, s := range v.Sources {
		if (s.Kind != "inventory" && s.Kind != "operations" && !domainKind(s.Kind)) || canonicalSources[canonicalDomain(s.Kind)] {
			return fmt.Errorf("duplicate or unknown BOM set source")
		}
		if stringValue(s.Header["bomFormat"]) != "CycloneDX" || stringValue(s.Header["specVersion"]) != v.SpecVersion {
			return fmt.Errorf("source CycloneDX version differs from set")
		}
		for _, field := range []string{"components", "services", "dependencies"} {
			if _, exists := s.Header[field]; exists {
				return fmt.Errorf("graph records cannot appear in source header")
			}
		}
		if err := validateSource(s, data); err != nil {
			return err
		}
		for _, m := range append(append([]member{}, s.Components...), s.Services...) {
			if len(m.Refs) == 0 || m.Ref != m.Refs[0] || s.Kind != "inventory" && m.Profile != sourceProfile(s.Kind) || s.Kind == "inventory" && m.Profile != "sbom" && m.Profile != "hbom" && m.Profile != "cbom" {
				return fmt.Errorf("invalid BOM set member")
			}
		}
		sources[s.Kind] = s
		canonicalSources[canonicalDomain(s.Kind)] = true
	}
	seen := map[string]bool{}
	for _, p := range v.Profiles {
		if p.Kind != "sbom" && p.Kind != "hbom" && p.Kind != "cbom" && p.Kind != "obom" && !domainKind(p.Kind) || seen[p.Kind] || p.Filename != p.Kind+suffix(v.SpecVersion) {
			return fmt.Errorf("invalid or duplicate BOM profile")
		}
		seen[p.Kind] = true
		if sums[p.Filename] != p.SHA256 || p.SHA256 == "" {
			return fmt.Errorf("profile checksum does not match BOM set")
		}
		kind := profileSource(p.Kind)
		s, exists := sources[kind]
		if !exists {
			return fmt.Errorf("BOM profile is missing its source manifest")
		}
		got, err := readSource(ctx, root, p.Filename, p.SHA256, kind, v.SpecVersion, data)
		if err != nil {
			return err
		}
		wantComponents, wantServices, known, err := profileMembers(s, p.Kind)
		if err != nil {
			return err
		}
		if !sameMembers(got.Components, wantComponents) || !sameMembers(got.Services, wantServices) {
			return fmt.Errorf("BOM profile members differ from source manifest")
		}
		wantHeader, err := projectionHeader(s, p.Kind, known)
		if err != nil {
			return err
		}
		if !sameJSON(got.Header, wantHeader) {
			return fmt.Errorf("BOM profile metadata differs from source manifest")
		}
	}
	if !seen["sbom"] || !seen["hbom"] || !seen["cbom"] || (sources["operations"].Kind != "") != seen["obom"] {
		return fmt.Errorf("BOM set is missing a required profile")
	}
	for _, kind := range readableDomainKinds {
		if (sources[kind].Kind != "") != seen[kind] {
			return fmt.Errorf("BOM set is missing a declared domain profile")
		}
	}
	return nil
}

func sameMembers(got, want []member) bool {
	if len(got) != len(want) {
		return false
	}
	for i, a := range got {
		b := want[i]
		if a.Ref != b.Ref || a.SHA256 != b.SHA256 || !reflect.DeepEqual(a.Refs, b.Refs) {
			return false
		}
	}
	return true
}

func sameJSON(a, b any) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	if err != nil {
		return false
	}
	var left, right any
	dx := json.NewDecoder(bytes.NewReader(x))
	dy := json.NewDecoder(bytes.NewReader(y))
	dx.UseNumber()
	dy.UseNumber()
	return dx.Decode(&left) == nil && dy.Decode(&right) == nil && reflect.DeepEqual(left, right)
}

func combine(sources []source, data *spool) (source, error) {
	result := sources[0]
	result.Header = copyObject(result.Header)
	result.Components = append([]member{}, result.Components...)
	result.Services = append([]member{}, result.Services...)
	result.Dependencies = append([]relationship{}, result.Dependencies...)
	known := map[string]string{}
	metadataRoots, err := rootRefs(result.Header)
	if err != nil {
		return source{}, err
	}
	var baseMetadata object
	if err = json.Unmarshal(result.Header["metadata"], &baseMetadata); err != nil {
		return source{}, err
	}
	rootHash := ""
	if len(metadataRoots) > 0 {
		rootHash, err = data.put(baseMetadata["component"])
		if err != nil {
			return source{}, err
		}
	}
	for _, ref := range metadataRoots {
		known[ref] = rootHash
	}
	for _, m := range append(append([]member{}, result.Components...), result.Services...) {
		for _, ref := range m.Refs {
			known[ref] = m.SHA256
		}
	}
	var origins []map[string]any
	for _, s := range sources {
		origins = append(origins, map[string]any{"kind": s.Kind, "sha256": s.SHA256, "header": s.Header, "normalization": s.Normalization})
		if s.Kind == "inventory" {
			continue
		}
		var metadata object
		if err = json.Unmarshal(s.Header["metadata"], &metadata); err != nil {
			return source{}, err
		}
		root := metadata["component"]
		components := append([]member{}, s.Components...)
		if len(root) > 0 {
			refs, refErr := entityRefs(root, "components")
			if refErr != nil {
				return source{}, refErr
			}
			hash, writeErr := data.put(root)
			if writeErr != nil {
				return source{}, writeErr
			}
			components = append([]member{{Ref: refs[0], Profile: sourceProfile(s.Kind), SHA256: hash, Refs: refs}}, components...)
			if len(metadataRoots) > 0 && metadataRoots[0] != refs[0] {
				link, _ := json.Marshal(map[string]any{"ref": metadataRoots[0], "dependsOn": []string{refs[0]}})
				record, saveErr := data.putRelationship(link)
				if saveErr != nil {
					return source{}, saveErr
				}
				result.Dependencies = append(result.Dependencies, record)
			}
		}
		for _, pair := range []struct {
			from []member
			to   *[]member
		}{{components, &result.Components}, {s.Services, &result.Services}} {
			for _, m := range pair.from {
				matched := 0
				for _, ref := range m.Refs {
					if hash, exists := known[ref]; exists {
						if hash != m.SHA256 {
							return source{}, fmt.Errorf("conflicting bom-ref between source graphs")
						}
						matched++
					}
				}
				if matched != 0 && matched != len(m.Refs) {
					return source{}, fmt.Errorf("partially overlapping source hierarchy")
				}
				if matched == len(m.Refs) {
					continue
				}
				for _, ref := range m.Refs {
					known[ref] = m.SHA256
				}
				*pair.to = append(*pair.to, m)
			}
		}
		result.Dependencies = append(result.Dependencies, s.Dependencies...)
		// Retain each operations completeness assertion in the merged document.
		// The exact original headers also remain in the provenance property.
		if raw := s.Header["compositions"]; len(raw) > 0 {
			var primary, operations []json.RawMessage
			if existing := result.Header["compositions"]; len(existing) > 0 {
				if err = json.Unmarshal(existing, &primary); err != nil {
					return source{}, err
				}
			}
			if err = json.Unmarshal(raw, &operations); err != nil {
				return source{}, err
			}
			result.Header["compositions"], _ = json.Marshal(append(primary, operations...))
		}
	}
	if err = mergeFormulations(result.Header, sources, known); err != nil {
		return source{}, err
	}
	result.Dependencies, err = mergeDependencies(result.Dependencies, data)
	if err != nil {
		return source{}, err
	}
	if err = deduplicateCompositions(result.Header); err != nil {
		return source{}, err
	}
	var metadata object
	if err = json.Unmarshal(result.Header["metadata"], &metadata); err != nil {
		return source{}, err
	}
	var properties []map[string]string
	if raw := metadata["properties"]; len(raw) > 0 {
		if err = json.Unmarshal(raw, &properties); err != nil {
			return source{}, err
		}
	}
	provenance, err := json.Marshal(origins)
	if err != nil {
		return source{}, err
	}
	properties = append(properties, map[string]string{"name": "koda:bom:profile", "value": "merged"}, map[string]string{"name": "koda:bom:source-metadata", "value": string(provenance)})
	metadata["properties"], _ = json.Marshal(properties)
	result.Header["metadata"], _ = json.Marshal(metadata)
	result.Header["serialNumber"] = serial(string(provenance))
	// Source graph references were checked before merge. Every retained entity
	// remains present, and the added edge joins the two verified metadata roots.
	return result, nil
}

func copyObject(in object) object {
	out := object{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func deduplicateCompositions(header object) error {
	raw, exists := header["compositions"]
	if !exists {
		return nil
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	seen := map[string]bool{}
	unique := make([]json.RawMessage, 0, len(rows))
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
		if !seen[key] {
			seen[key] = true
			unique = append(unique, row)
		}
	}
	var err error
	header["compositions"], err = json.Marshal(unique)
	return err
}

func mergeDependencies(input []relationship, data *spool) ([]relationship, error) {
	rows := map[string]relationship{}
	for _, record := range input {
		old, exists := rows[record.Ref]
		if !exists || old.SHA256 == record.SHA256 {
			rows[record.Ref] = record
			continue
		}
		raw, err := data.get(record.SHA256)
		if err != nil {
			return nil, err
		}
		var row object
		if err = json.Unmarshal(raw, &row); err != nil {
			return nil, err
		}
		raw, err = data.get(old.SHA256)
		if err != nil {
			return nil, err
		}
		var previous object
		if err = json.Unmarshal(raw, &previous); err != nil {
			return nil, err
		}
		for key, value := range row {
			if key != "dependsOn" && key != "provides" {
				if old, exists := previous[key]; exists && !sameJSON(old, value) {
					return nil, fmt.Errorf("conflicting dependency fields")
				}
				previous[key] = value
				continue
			}
			var left, right []string
			if old, exists := previous[key]; exists {
				if err := json.Unmarshal(old, &left); err != nil {
					return nil, err
				}
			}
			if err := json.Unmarshal(value, &right); err != nil {
				return nil, err
			}
			values := map[string]bool{}
			for _, ref := range append(left, right...) {
				values[ref] = true
			}
			merged := make([]string, 0, len(values))
			for ref := range values {
				merged = append(merged, ref)
			}
			sort.Strings(merged)
			previous[key], _ = json.Marshal(merged)
		}
		encoded, err := json.Marshal(previous)
		if err != nil {
			return nil, err
		}
		rows[record.Ref], err = data.putRelationship(encoded)
		if err != nil {
			return nil, err
		}
	}
	refs := make([]string, 0, len(rows))
	for ref := range rows {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	out := make([]relationship, 0, len(refs))
	for _, ref := range refs {
		out = append(out, rows[ref])
	}
	return out, nil
}
