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
	"sort"
)

type output struct {
	root  *os.Root
	owned []string
}

func newOutput(dir string) (*output, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &output{root: root}, nil
}

func (o *output) close(success bool) {
	if !success {
		for _, name := range o.owned {
			o.root.Remove(name)
		}
	}
	o.root.Close()
}

func (o *output) write(name string, emit func(io.Writer) error) (string, error) {
	f, err := o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	o.owned = append(o.owned, name)
	defer f.Close()
	h := sha256.New()
	w := bufio.NewWriter(io.MultiWriter(f, h))
	if err = emit(w); err != nil {
		return "", err
	}
	if err = w.Flush(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func encode(w io.Writer, value any) error {
	return json.NewEncoder(w).Encode(value)
}

func suffix(spec string) string {
	if spec == "1.7" {
		return ".cdx-1.7.json"
	}
	return ".cdx.json"
}

func serial(seed string) json.RawMessage {
	sum := sha256.Sum256([]byte(seed))
	// UUID version 8 permits an application-defined digest. Preserve the RFC
	// variant and version bits while deriving stable identities for each view.
	sum[6] = (sum[6] & 0x0f) | 0x80
	sum[8] = (sum[8] & 0x3f) | 0x80
	raw, _ := json.Marshal(fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]))
	return raw
}

// Split partitions an inventory into software, hardware and cryptography BOMs.
// Operations are included when recorded in collectionDir or the optional
// operationsDir. Generated service, model and manufacturing sources in
// collectionDir retain their own profiles. Every consumed source must match
// its SHA256SUMS entry. A 1.7
// request requires original 1.7 companions; version conversion is never used.
// The caller creates outputDir and publishes its SHA256SUMS after success.
func Split(ctx context.Context, collectionDir, outputDir string, include17 bool, operationsDir ...string) (err error) {
	if len(operationsDir) > 1 {
		return fmt.Errorf("at most one operations directory is supported")
	}
	in, err := os.OpenRoot(collectionDir)
	if err != nil {
		return err
	}
	defer in.Close()
	sums, err := checksums(in)
	if err != nil {
		return err
	}
	domains, err := discoverDomains(in, sums, include17)
	if err != nil {
		return err
	}
	baseDomains := map[string]source{}
	operations := in
	operationSums := sums
	if len(operationsDir) == 1 {
		if sums["obom.cdx.json"] != "" || sums["obom.cdx-1.7.json"] != "" {
			return fmt.Errorf("recorded operations BOM cannot be replaced by another directory")
		}
		operations, err = os.OpenRoot(operationsDir[0])
		if err != nil {
			return err
		}
		defer operations.Close()
		operationSums, err = checksums(operations)
		if err != nil {
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
	set := manifest{Schema: "koda-bom-set-1"}
	specs := []string{"1.6"}
	if include17 {
		specs = append(specs, "1.7")
	}
	for _, spec := range specs {
		name := "sbom" + suffix(spec)
		if sums[name] == "" {
			return fmt.Errorf("verified source %s required", name)
		}
		inventory, readErr := readSource(ctx, in, name, sums[name], "inventory", spec, data)
		if readErr != nil {
			return readErr
		}
		v := version{SpecVersion: spec, Sources: []source{inventory}}
		for _, kind := range []string{"sbom", "hbom", "cbom"} {
			p, writeErr := writeProfile(ctx, out, inventory, spec, kind, data)
			if writeErr != nil {
				return writeErr
			}
			v.Profiles = append(v.Profiles, p)
		}
		name = "obom" + suffix(spec)
		if operationSums[name] != "" {
			operation, readErr := readSource(ctx, operations, name, operationSums[name], "operations", spec, data)
			if readErr != nil {
				return readErr
			}
			if len(operationsDir) == 1 {
				if err = bindOperations(ctx, in, sums["collection.json"], operation); err != nil {
					return err
				}
			}
			p, writeErr := writeProfile(ctx, out, operation, spec, "obom", data)
			if writeErr != nil {
				return writeErr
			}
			v.Sources = append(v.Sources, operation)
			v.Profiles = append(v.Profiles, p)
		} else {
			if _, statErr := operations.Stat(name); !os.IsNotExist(statErr) {
				return fmt.Errorf("operations source is missing its checksum")
			}
			if spec == "1.7" && operationSums["obom.cdx.json"] != "" {
				return fmt.Errorf("original operations 1.7 companion required")
			}
		}
		for _, kind := range domains {
			name := kind + suffix(spec)
			domain, readErr := readSource(ctx, in, name, sums[name], kind, spec, data)
			if readErr != nil {
				return readErr
			}
			if spec == "1.6" {
				baseDomains[kind] = domain
			} else if !sameDomainCompanion(baseDomains[kind], domain) {
				return fmt.Errorf("%s 1.7 companion differs from original domain observations", kind)
			}
			// Keep the verified original header and digest as provenance while new
			// profiles and manifests consistently use the AI-BOM name.
			domain.Kind = canonicalDomain(kind)
			for i := range domain.Components {
				domain.Components[i].Profile = domain.Kind
			}
			for i := range domain.Services {
				domain.Services[i].Profile = domain.Kind
			}
			p, writeErr := writeProfile(ctx, out, domain, spec, domain.Kind, data)
			if writeErr != nil {
				return writeErr
			}
			v.Sources = append(v.Sources, domain)
			v.Profiles = append(v.Profiles, p)
		}
		v.Relationships, err = writeRelationshipSidecar(ctx, out, data, v)
		if err != nil {
			return err
		}
		set.Versions = append(set.Versions, v)
	}
	_, err = out.write(ManifestFilename, func(w io.Writer) error { return encode(w, set) })
	return err
}

func profileMembers(s source, kind string) ([]member, []member, map[string]bool, error) {
	root, err := rootRefs(s.Header)
	if err != nil {
		return nil, nil, nil, err
	}
	known := map[string]bool{}
	for _, ref := range root {
		known[ref] = true
	}
	formRefs, err := formulationReferences(s.Header)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ref := range formRefs {
		known[ref] = true
	}
	var components, services []member
	for _, m := range s.Components {
		if m.Profile == kind {
			components = append(components, m)
			for _, ref := range m.Refs {
				known[ref] = true
			}
		}
	}
	for _, m := range s.Services {
		if m.Profile == kind {
			services = append(services, m)
			for _, ref := range m.Refs {
				known[ref] = true
			}
		}
	}
	return components, services, known, nil
}

func writeProfile(ctx context.Context, out *output, s source, spec, kind string, data *spool) (profile, error) {
	components, services, known, err := profileMembers(s, kind)
	if err != nil {
		return profile{}, err
	}
	for _, m := range components {
		raw, readErr := data.get(m.SHA256)
		if readErr != nil {
			return profile{}, readErr
		}
		if err = validateCryptoRefs(raw, known); err != nil {
			return profile{}, err
		}
	}
	header, err := projectionHeader(s, kind, known)
	if err != nil {
		return profile{}, err
	}
	var dependencies []relationship
	for _, dependency := range s.Dependencies {
		if !known[dependency.Ref] {
			continue
		}
		raw, readErr := data.get(dependency.SHA256)
		if readErr != nil {
			return profile{}, readErr
		}
		var row object
		if err = json.Unmarshal(raw, &row); err != nil {
			return profile{}, err
		}
		if !known[stringValue(row["ref"])] {
			continue
		}
		for _, field := range []string{"dependsOn", "provides"} {
			if values, ok := row[field]; ok {
				var refs []string
				if err = json.Unmarshal(values, &refs); err != nil {
					return profile{}, err
				}
				filtered := []string{}
				for _, ref := range refs {
					if known[ref] {
						filtered = append(filtered, ref)
					}
				}
				row[field], _ = json.Marshal(filtered)
			}
		}
		encoded, _ := json.Marshal(row)
		d, saveErr := data.putRelationship(encoded)
		if saveErr != nil {
			return profile{}, saveErr
		}
		dependencies = append(dependencies, d)
	}
	name := kind + suffix(spec)
	hash, err := out.write(name, func(w io.Writer) error {
		return writeDocument(ctx, w, header, components, services, dependencies, data)
	})
	return profile{Kind: kind, Filename: name, SHA256: hash}, err
}

func projectionHeader(s source, kind string, known map[string]bool) (object, error) {
	header := object{}
	if domainKind(kind) {
		header = copyObject(s.Header)
	}
	for _, field := range []string{"$schema", "bomFormat", "specVersion", "version", "metadata"} {
		if raw, exists := s.Header[field]; exists {
			header[field] = raw
		}
	}
	var metadata object
	if err := json.Unmarshal(header["metadata"], &metadata); err != nil {
		return nil, err
	}
	var properties []map[string]string
	if raw := metadata["properties"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &properties); err != nil {
			return nil, err
		}
	}
	properties = append(properties,
		map[string]string{"name": "koda:bom:profile", "value": kind},
		map[string]string{"name": "koda:bom:source-sha256", "value": s.SHA256},
		map[string]string{"name": "koda:bom:cross-profile-relationships", "value": "preserved in bom-set.json"})
	if len(s.Normalization) > 0 {
		normalized, _ := json.Marshal(s.Normalization)
		properties = append(properties, map[string]string{"name": "koda:bom:source-normalization", "value": string(normalized)})
	}
	metadata["properties"], _ = json.Marshal(properties)
	header["metadata"], _ = json.Marshal(metadata)
	header["serialNumber"] = serial(s.SHA256 + "\x00" + kind)
	var compositions []object
	if raw := s.Header["compositions"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &compositions); err != nil {
			return nil, err
		}
		for _, c := range compositions {
			for _, field := range []string{"assemblies", "dependencies", "vulnerabilities"} {
				if raw, exists := c[field]; exists {
					var refs []string
					if err := json.Unmarshal(raw, &refs); err != nil {
						return nil, err
					}
					filtered := []string{}
					for _, ref := range refs {
						if known[ref] {
							filtered = append(filtered, ref)
						}
					}
					if len(filtered) == 0 {
						delete(c, field)
					} else {
						c[field], _ = json.Marshal(filtered)
					}
				}
			}
		}
		header["compositions"], _ = json.Marshal(compositions)
	}
	if err := deduplicateCompositions(header); err != nil {
		return nil, err
	}
	return header, nil
}

func writeDocument(ctx context.Context, w io.Writer, header object, components, services []member, dependencies []relationship, data *spool) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	fields := make([]string, 0, len(header))
	for field := range header {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		key, _ := json.Marshal(field)
		if _, err := fmt.Fprintf(w, "%s:%s,", key, header[field]); err != nil {
			return err
		}
	}
	for _, pair := range []struct {
		field string
		rows  []member
	}{{"components", components}, {"services", services}} {
		if _, err := fmt.Fprintf(w, "%q:[", pair.field); err != nil {
			return err
		}
		for index, m := range pair.rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if index > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			raw, err := data.get(m.SHA256)
			if err != nil {
				return err
			}
			if _, err = w.Write(raw); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "],"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\"dependencies\":["); err != nil {
		return err
	}
	for index, dependency := range dependencies {
		raw, readErr := data.get(dependency.SHA256)
		if readErr != nil {
			return readErr
		}
		if index > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if _, err := w.Write(raw); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]}\n")
	return err
}
