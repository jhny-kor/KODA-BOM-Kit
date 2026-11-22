package domainbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

// ModelDiscovery contains metadata observed only inside one admitted scan plan.
type ModelDiscovery struct {
	Scope        string // "" for the scanned root itself
	Components   []map[string]any
	Dependencies []map[string]any
	Issues       []model.Issue
}
type modelScanner struct {
	ctx      context.Context
	plan     localfs.Plan
	root     *os.Root
	scope    string
	admitted map[string]bool
	claimed  map[string]bool
	result   ModelDiscovery
	reads    int
	refs     map[string][]string // Hugging Face cache repository dir -> ref files
}

const maxModelReads = 2048

// DiscoverModels reads configuration and bounded weight headers. Whole weight
// hashes and runtime loading require explicit artifact selection or runtime evidence.
func DiscoverModels(ctx context.Context, plan localfs.Plan, scope string) (ModelDiscovery, error) {
	root, err := plan.OpenRoot()
	if err != nil {
		return ModelDiscovery{}, err
	}
	defer root.Close()
	s := modelScanner{ctx: ctx, plan: plan, root: root, scope: scope, admitted: map[string]bool{}, claimed: map[string]bool{}, result: ModelDiscovery{Scope: scope}}
	candidates := append(append([]string{}, plan.Paths...), plan.IndexedLinks()...)
	candidates = append(candidates, plan.ModelHeaderPaths...)
	sort.Strings(candidates)
	candidates = slices.Compact(candidates)
	largeHeaders := map[string]bool{}
	for _, p := range plan.ModelHeaderPaths {
		largeHeaders[p] = true
	}
	for _, p := range candidates {
		if (!plan.ExcludesPath(p) || largeHeaders[p]) && !strings.HasPrefix(path.Base(p), "._") {
			s.admitted[p] = true
		}
	}
	for _, p := range candidates {
		if err := ctx.Err(); err != nil {
			return s.result, err
		}
		if path.Base(p) == "config.json" && s.admitted[p] {
			s.huggingFace(p)
		}
		if (strings.Contains(p, "/models/manifests/") || strings.HasPrefix(p, "models/manifests/")) && s.admitted[p] {
			s.ollama(p)
		}
	}
	for _, p := range candidates {
		if err := ctx.Err(); err != nil {
			return s.result, err
		}
		if !s.admitted[p] || s.claimed[p] || (!strings.HasSuffix(strings.ToLower(p), ".gguf") && !strings.HasSuffix(strings.ToLower(p), ".safetensors") && !pickleModelFile(p)) {
			continue
		}
		c, err := s.weight(p, true)
		if err != nil {
			s.issue(p, "model_header_unavailable")
			continue
		}
		s.result.Components = append(s.result.Components, c)
	}
	if s.reads >= maxModelReads {
		s.issue("", "model_metadata_limit")
	}
	return s.result, ctx.Err()
}
func (s *modelScanner) issue(p, code string) {
	if len(s.result.Issues) >= 100 {
		return
	}
	s.result.Issues = append(s.result.Issues, model.Issue{Collector: "ai-models", Target: s.scope, Status: "incomplete", Code: code, Path: p, Message: "model metadata could not be inspected completely"})
}
func (s *modelScanner) location(p string) string {
	if s.scope != "" {
		return s.scope + "/" + p
	}
	return p
}
func (s *modelScanner) properties(p string) []property {
	return []property{prop("observation", "local-model-metadata"), prop("path", s.location(p)), prop("runtime-state", "not-observed"), prop("weight-digest", "not-collected"), prop("training-data", "not-observed")}
}
func (s *modelScanner) open(p string) (*os.File, os.FileInfo, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !s.admitted[p] || s.reads >= maxModelReads {
		return nil, nil, fmt.Errorf("model path unavailable within scan budget")
	}
	s.reads++
	return s.plan.OpenModelHeader(s.root, p)
}
func (s *modelScanner) json(p string) (map[string]json.RawMessage, string, error) {
	f, st, err := s.open(p)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	if st.Size() > maxEvidenceBytes {
		return nil, "", fmt.Errorf("model metadata exceeds limit")
	}
	b, err := io.ReadAll(io.LimitReader(&contextReader{s.ctx, f}, maxEvidenceBytes+1))
	if err != nil || len(b) > maxEvidenceBytes {
		return nil, "", fmt.Errorf("model metadata unreadable")
	}
	after, err := f.Stat()
	if err != nil || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) {
		return nil, "", fmt.Errorf("model metadata changed")
	}
	if err := uniqueJSON(b); err != nil {
		return nil, "", err
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil || doc == nil {
		return nil, "", fmt.Errorf("invalid metadata object")
	}
	hash := sha256.Sum256(b)
	return doc, hex.EncodeToString(hash[:]), nil
}
func rawText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil || !textOK(s, false) {
		return ""
	}
	return s
}
func numeric(raw json.RawMessage) string {
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	value, err := n.Float64()
	if err != nil || value < 0 {
		return ""
	}
	return n.String()
}
func (s *modelScanner) huggingFace(p string) {
	doc, digest, err := s.json(p)
	if err != nil {
		return
	}
	typ := rawText(doc["model_type"])
	var arch []string
	_ = json.Unmarshal(doc["architectures"], &arch)
	if typ == "" || (len(arch) == 0 && doc["hidden_size"] == nil && doc["text_config"] == nil) {
		return
	}
	props := s.properties(p)
	props = append(props, prop("format", "huggingface"), prop("metadata-sha256", digest), prop("config:model_type", typ))
	fields := map[string]json.RawMessage{}
	for k, v := range doc {
		fields[k] = v
	}
	if nested := doc["text_config"]; len(nested) > 0 {
		var text map[string]json.RawMessage
		if json.Unmarshal(nested, &text) == nil {
			for k, v := range text {
				fields[k] = v
			}
		}
	}
	for _, k := range []string{"hidden_size", "intermediate_size", "num_hidden_layers", "num_attention_heads", "num_key_value_heads", "head_dim", "max_position_embeddings", "vocab_size", "rope_theta", "num_experts", "num_experts_per_tok"} {
		if value := numeric(fields[k]); value != "" {
			props = append(props, prop("config:"+k, value))
		}
	}
	for _, k := range []string{"torch_dtype", "dtype", "transformers_version"} {
		if value := rawText(fields[k]); value != "" {
			props = append(props, prop("config:"+k, value))
		}
	}
	for _, a := range arch {
		if textOK(a, true) {
			props = append(props, prop("config:architecture", a))
		}
	}
	rawQuantization := fields["quantization_config"]
	if len(rawQuantization) == 0 {
		rawQuantization = fields["quantization"]
	}
	if raw := rawQuantization; len(raw) > 0 {
		var quant map[string]json.RawMessage
		if json.Unmarshal(raw, &quant) == nil {
			for _, k := range []string{"quant_method", "bits", "group_size", "mode"} {
				v := rawText(quant[k])
				if v == "" {
					v = numeric(quant[k])
				}
				if v != "" {
					props = append(props, prop("config:quantization:"+k, v))
				}
			}
		}
	}
	name := path.Base(path.Dir(p))
	if name == "." {
		name = path.Base(s.plan.Root)
		if name == "." || name == "/" {
			name = typ
		}
	}
	// Repository names are recorded only when explicitly encoded in the cache path.
	parts := strings.Split(p, "/")
	repoDir, revision := "", ""
	for i, part := range parts {
		if strings.HasPrefix(part, "models--") {
			repo := strings.ReplaceAll(strings.TrimPrefix(part, "models--"), "--", "/")
			if textOK(repo, true) {
				props = append(props, prop("cache-repository", repo))
				name = repo
				repoDir = strings.Join(parts[:i+1], "/")
			}
		}
		if part == "snapshots" && i+1 < len(parts)-1 && len(parts[i+1]) == 40 {
			if _, err := hex.DecodeString(parts[i+1]); err == nil {
				props = append(props, prop("cache-revision", parts[i+1]))
				revision = parts[i+1]
			}
		}
	}
	if repoDir != "" && revision != "" {
		for _, refName := range s.cacheRefs(repoDir, revision) {
			props = append(props, prop("cache-ref", refName))
		}
	}
	id := ref("discovered-model", s.scope, s.plan.Root, p)
	c := object{"type": "machine-learning-model", "bom-ref": id, "name": name, "properties": props, "modelCard": object{"properties": []property{prop("coverage", "local configuration; publisher, model lineage, training and evaluation data require evidence")}}}
	var cardTargets []string
	if readme := path.Join(path.Dir(p), "README.md"); s.admitted[readme] {
		card, err := s.readModelCard(readme)
		switch {
		case err != nil:
			s.issue(readme, "model_card_unavailable")
		case card != nil:
			props, cardTargets = card.apply(s, c, id, readme, props)
		}
	}
	shards := map[string]bool{}
	prefix := path.Dir(p)
	index := path.Join(prefix, "model.safetensors.index.json")
	if s.admitted[index] {
		idx, indexDigest, err := s.json(index)
		if err != nil {
			s.issue(index, "model_index_unavailable")
		} else {
			var weights map[string]string
			if json.Unmarshal(idx["weight_map"], &weights) != nil || len(weights) > 200000 {
				s.issue(index, "model_index_invalid")
			} else {
				props = append(props, prop("index-sha256", indexDigest), prop("index:tensor-count", strconv.Itoa(len(weights))))
				for _, file := range weights {
					if file != "" && path.Base(file) == file && strings.HasSuffix(file, ".safetensors") {
						shards[path.Join(prefix, file)] = true
					} else {
						s.issue(index, "model_index_invalid")
					}
				}
			}
		}
	} else {
		for candidate := range s.admitted {
			if path.Dir(candidate) == prefix && strings.HasSuffix(candidate, ".safetensors") {
				shards[candidate] = true
			}
		}
	}
	list := make([]string, 0, len(shards))
	for file := range shards {
		list = append(list, file)
	}
	sort.Strings(list)
	targets := []string{}
	var observedBytes int64
	unavailable := 0
	for _, file := range list {
		if !s.admitted[file] {
			unavailable++
			continue
		}
		weight, err := s.weight(file, false)
		if err != nil {
			unavailable++
			s.issue(file, "model_weight_header_unavailable")
			continue
		}
		s.result.Components = append(s.result.Components, weight)
		for _, item := range weight["properties"].([]property) {
			if item.Name == "koda:domain:artifact-size" {
				n, _ := strconv.ParseInt(item.Value, 10, 64)
				observedBytes += n
			}
		}
		s.claimed[file] = true
		targets = append(targets, weight["bom-ref"].(string))
	}
	props = append(props, prop("weight-bytes-observed", strconv.FormatInt(observedBytes, 10)), prop("weight-files-observed", strconv.Itoa(len(targets))), prop("weight-files-unavailable", strconv.Itoa(unavailable)), prop("weight-files-referenced", strconv.Itoa(len(shards))))
	// PyTorch weights, training state (training_args.bin, optimizer.pt) and ONNX
	// exports next to the configuration belong to this model, not to models of
	// their own. The model reports the least safe pickle among them.
	var artifacts []string
	for candidate := range s.admitted {
		if path.Dir(candidate) == prefix && !s.claimed[candidate] && pickleModelFile(candidate) {
			artifacts = append(artifacts, candidate)
		}
	}
	sort.Strings(artifacts)
	worst, failed := "", 0
	for _, file := range artifacts {
		s.claimed[file] = true // a failure is reported once here, not again as a standalone model
		artifact, err := s.weight(file, false)
		if err != nil {
			s.issue(file, "model_artifact_unavailable")
			failed++
			// An uninspected checkpoint may import anything when loaded.
			if !strings.EqualFold(path.Ext(file), ".onnx") && pickleSafetyRank[worst] < pickleSafetyRank["unknown-imports"] {
				worst = "unknown-imports"
			}
			continue
		}
		s.result.Components = append(s.result.Components, artifact)
		targets = append(targets, artifact["bom-ref"].(string))
		for _, item := range artifact["properties"].([]property) {
			if item.Name == "koda:domain:pickle:safety" && pickleSafetyRank[item.Value] > pickleSafetyRank[worst] {
				worst = item.Value
			}
		}
	}
	if len(artifacts) > 0 {
		props = append(props, prop("artifact-files-observed", strconv.Itoa(len(artifacts)-failed)), prop("artifact-files-unavailable", strconv.Itoa(failed)))
	}
	if failed > 0 {
		props = append(props, prop("artifact-inspection", "incomplete"))
	}
	if worst != "" {
		props = append(props, prop("artifact-pickle-safety", worst))
	}
	c["properties"] = props
	s.result.Components = append(s.result.Components, c)
	targets = append(targets, cardTargets...)
	if len(targets) > 0 {
		s.result.Dependencies = append(s.result.Dependencies, object{"ref": id, "dependsOn": targets})
	}
}
func (s *modelScanner) weight(p string, standalone bool) (object, error) {
	f, st, err := s.open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	observed, err := artifactHeader(f, st.Size(), p)
	if err != nil || len(observed) == 0 {
		return nil, fmt.Errorf("model header unreadable")
	}
	after, err := f.Stat()
	if err != nil || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("model artifact changed")
	}
	props := append(s.properties(p), prop("artifact-size", strconv.FormatInt(st.Size(), 10)))
	props = append(props, observed...)
	kind := "file"
	if standalone {
		kind = "machine-learning-model"
		props = append(props, prop("model-completeness", "individual-file; sibling shards and serving state unverified"))
	}
	c := object{"type": kind, "bom-ref": ref("discovered-weight", s.scope, s.plan.Root, p), "name": path.Base(p), "properties": props}
	return c, nil
}
func (s *modelScanner) ollama(p string) {
	if strings.Contains(p, "/blobs/") {
		return
	}
	doc, digest, err := s.json(p)
	if err != nil {
		return
	}
	var layers []struct {
		MediaType, Digest string
		Size              int64
	}
	if json.Unmarshal(doc["layers"], &layers) != nil || len(layers) > 128 {
		return
	}
	base := strings.SplitN("/"+p, "/models/manifests/", 2)
	if len(base) != 2 {
		return
	}
	props := s.properties(p)
	props = append(props, prop("format", "ollama-manifest"), prop("metadata-sha256", digest))
	id := ref("ollama-manifest", s.scope, s.plan.Root, p)
	targets := []string{}
	modelLayers := 0
	for _, layer := range layers {
		if layer.MediaType != "application/vnd.ollama.image.model" {
			continue
		}
		modelLayers++
		sha := strings.TrimPrefix(layer.Digest, "sha256:")
		if !digestOK(sha) {
			s.issue(p, "ollama_digest_invalid")
			continue
		}
		props = append(props, prop("manifest:model-layer-sha256", sha))
		blob := strings.TrimPrefix(path.Join(base[0], "models/blobs/sha256-"+sha), "/")
		if !s.admitted[blob] {
			props = append(props, prop("manifest:model-layer-state", "outside-admitted-files"))
			continue
		}
		c, err := s.weight(blob, false)
		if err != nil {
			s.issue(blob, "ollama_header_unavailable")
			continue
		}
		s.result.Components = append(s.result.Components, c)
		s.claimed[blob] = true
		targets = append(targets, c["bom-ref"].(string))
	}
	if modelLayers == 0 {
		return
	}
	s.result.Components = append(s.result.Components, object{"type": "machine-learning-model", "bom-ref": id, "name": base[1], "properties": props})
	if len(targets) > 0 {
		s.result.Dependencies = append(s.result.Dependencies, object{"ref": id, "dependsOn": targets})
	}
}

// AddDiscoveredModels extends existing explicitly supplied model evidence using
// the same IDs and source distinction in both CycloneDX versions.
func AddDiscoveredModels(ctx context.Context, documents map[string][]byte, discoveries []ModelDiscovery, include17 bool) error {
	var components, dependencies []object
	var issues []model.Issue
	for _, d := range discoveries {
		issues = append(issues, d.Issues...)
		components = append(components, d.Components...)
		dependencies = append(dependencies, d.Dependencies...)
	}
	return mergeDiscovered(ctx, documents, "aibom", "admitted local model metadata; weight contents and runtime state unverified",
		[]property{prop("discovery", "admitted-local-files"), prop("discovery-weight-digest", "not-collected"), prop("discovery-runtime-state", "not-observed")},
		map[string][]object{"components": components, "dependencies": dependencies}, issues, include17)
}

// AddDiscoveredServices adds backends declared by local proxies to the SaaSBOM.
func AddDiscoveredServices(ctx context.Context, documents map[string][]byte, discoveries []ServiceDiscovery, include17 bool) error {
	var services []object
	var issues []model.Issue
	for _, d := range discoveries {
		issues = append(issues, d.Issues...)
		services = append(services, d.Services...)
	}
	return mergeDiscovered(ctx, documents, "saasbom", "backends declared in local proxy configuration; reachability and use unverified",
		[]property{prop("discovery", "admitted-proxy-configuration"), prop("discovery-runtime-state", "not-observed")},
		map[string][]object{"services": services}, issues, include17)
}

// mergeDiscovered appends discovered items to kind's document, creating it when
// absent, and rewrites both CycloneDX versions.
func mergeDiscovered(ctx context.Context, documents map[string][]byte, kind, coverage string, discoveryProps []property, items map[string][]object, issues []model.Issue, include17 bool) error {
	count := 0
	for _, list := range items {
		count += len(list)
	}
	if count == 0 && len(issues) == 0 {
		return ctx.Err()
	}
	if documents == nil {
		return fmt.Errorf("%s document destination is nil", kind)
	}
	doc := object{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": object{"properties": []property{prop("kind", kind), prop("coverage", coverage)}}, "compositions": []object{{"aggregate": "incomplete"}}}
	if raw := documents[kind+".cdx.json"]; len(raw) > 0 {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&doc); err != nil {
			return err
		}
	}
	metadata, _ := doc["metadata"].(map[string]any)
	if metadata == nil {
		metadata = object{}
		doc["metadata"] = metadata
	}
	var properties []property
	encoded, _ := json.Marshal(metadata["properties"])
	_ = json.Unmarshal(encoded, &properties)
	properties = append(properties, discoveryProps...)
	issueCounts := map[string]int{}
	for _, issue := range issues {
		issueCounts[issue.Code]++
	}
	status := "metadata-observed"
	if len(issues) > 0 {
		status = "incomplete"
	}
	properties = append(properties, prop("discovery-status", status), prop("discovery-issue-count", fmt.Sprint(len(issues))))
	codes := make([]string, 0, len(issueCounts))
	for code := range issueCounts {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		properties = append(properties, prop("discovery-issue:"+code, fmt.Sprint(issueCounts[code])))
	}
	metadata["properties"] = properties
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		existing := []any{}
		if v, ok := doc[key].([]any); ok {
			existing = v
		}
		seen := map[string]bool{}
		idField := "bom-ref"
		if key == "dependencies" {
			idField = "ref"
		}
		for _, v := range existing {
			if o, ok := v.(map[string]any); ok {
				if id, ok := o[idField].(string); ok {
					seen[id] = true
				}
			}
		}
		for _, v := range items[key] {
			if err := ctx.Err(); err != nil {
				return err
			}
			id := v[idField].(string)
			if seen[id] {
				continue
			}
			seen[id] = true
			existing = append(existing, v)
		}
		if len(existing) > 0 {
			doc[key] = existing
		}
	}
	versions := []string{"1.6"}
	if include17 {
		versions = append(versions, "1.7")
	}
	for _, v := range versions {
		if err := ctx.Err(); err != nil {
			return err
		}
		doc["specVersion"] = v
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		name := kind + ".cdx.json"
		if v == "1.7" {
			name = kind + ".cdx-1.7.json"
		}
		documents[name] = append(b, '\n')
	}
	return nil
}

// MarkServingModels annotates host-scope discovered models that a running model
// server was started with: its path equals or contains the server's model
// path, or its cache repository equals the server's repository ID. The process
// reference shows intent at start-up; the server may since have loaded another model.
func MarkServingModels(discoveries []ModelDiscovery, links []model.ProcessLink) {
	for _, d := range discoveries {
		if d.Scope != "" {
			continue // container and multi-target paths are not host paths
		}
		for _, c := range d.Components {
			props, _ := c["properties"].([]property)
			if c["type"] != "machine-learning-model" || props == nil {
				continue
			}
			location, repo := "", ""
			for _, p := range props {
				switch p.Name {
				case "koda:domain:path":
					location = p.Value
				case "koda:domain:cache-repository":
					repo = p.Value
				}
			}
			matched := false
			for _, l := range links {
				for _, r := range l.ModelReferences {
					if r == repo || location == r || strings.HasPrefix(location, r+"/") {
						props = append(props, prop("serving-process", fmt.Sprintf("pid %d %s", l.PID, l.Executable)))
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
			for i := range props {
				if props[i].Name == "koda:domain:runtime-state" {
					props[i].Value = "referenced-by-running-process"
				}
			}
			c["properties"] = props
		}
	}
}
