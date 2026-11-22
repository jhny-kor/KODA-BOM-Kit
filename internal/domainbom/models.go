package domainbom

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type modelDeclaration struct {
	Schema       string            `json:"schema"`
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	SHA256       string            `json:"sha256"`
	License      string            `json:"license,omitempty"`
	Source       string            `json:"source,omitempty"`
	Task         string            `json:"task,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	BaseModels   []modelDependency `json:"baseModels,omitempty"`
	Datasets     []modelDependency `json:"datasets,omitempty"`
}
type modelDependency struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Source  string `json:"source,omitempty"`
	License string `json:"license,omitempty"`
}

func loadModel(ctx context.Context, input ModelInput, d *document) error {
	var decl modelDeclaration
	source := ""
	if input.Evidence != "" {
		raw, sum, err := readEvidence(ctx, input.Evidence)
		if err != nil {
			return err
		}
		source = sum
		if strict(raw, &decl) != nil || decl.Schema != "koda-model-1" || !textOK(decl.Name, true) || !digestOK(decl.SHA256) {
			return fmt.Errorf("model declaration requires koda-model-1, name and SHA-256")
		}
		if len(decl.BaseModels)+len(decl.Datasets) > maxItems {
			return fmt.Errorf("model dependency limit exceeded")
		}
	} else {
		decl.Name = filepath.Base(input.Artifact)
	}
	for _, s := range []string{decl.Name, decl.Version, decl.License, decl.Task, decl.Architecture} {
		if !textOK(s, false) {
			return fmt.Errorf("invalid model metadata")
		}
	}
	if decl.Source != "" && !safeURI(decl.Source) {
		return fmt.Errorf("model source must be an absolute URL without credentials or query")
	}
	f, sum, stat, err := openArtifact(ctx, input.Artifact, decl.SHA256)
	if err != nil {
		return err
	}
	defer f.Close()
	observed, err := artifactHeader(f, stat.Size(), input.Artifact)
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil || stat.Size() != after.Size() || !stat.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("model artifact changed during metadata inspection")
	}
	if input.Evidence == "" && len(observed) == 0 {
		return fmt.Errorf("standalone model artifact must be safetensors, GGUF, ONNX, PyTorch or pickle")
	}
	if source == "" {
		source = sum
	}
	if !d.source(source) {
		return nil
	}
	r := ref("model", sum, source)
	binding := "sha256-matched"
	if input.Evidence == "" {
		binding = "sha256-calculated"
	}
	props := []property{prop("source-sha256", source), prop("artifact-binding", binding), prop("artifact-size", strconv.FormatInt(stat.Size(), 10))}
	if input.Evidence != "" {
		props = append(props, prop("model-metadata", "supplier-declared"))
	} else {
		props = append(props, prop("model-metadata", "local-header-observation"))
	}
	props = append(props, observed...)
	model := object{"type": "machine-learning-model", "bom-ref": r, "name": decl.Name, "hashes": hashes(sum), "properties": props}
	if decl.Version != "" {
		model["version"] = decl.Version
	}
	if decl.License != "" {
		model["licenses"] = []object{{"license": object{"name": decl.License}}}
	}
	if decl.Source != "" {
		model["externalReferences"] = []object{{"type": "distribution", "url": decl.Source}}
	}
	parameters := object{}
	if decl.Task != "" {
		parameters["task"] = decl.Task
	}
	if decl.Architecture != "" {
		parameters["modelArchitecture"] = decl.Architecture
	}
	targets := []string{}
	dataRefs := []object{}
	for _, group := range []struct {
		kind, relation string
		items          []modelDependency
	}{{"machine-learning-model", "base-model", decl.BaseModels}, {"data", "dataset", decl.Datasets}} {
		for index, item := range group.items {
			if !textOK(item.Name, true) || !textOK(item.Version, false) || !textOK(item.License, false) || (item.SHA256 != "" && !digestOK(item.SHA256)) || (item.Source != "" && !safeURI(item.Source)) {
				return fmt.Errorf("invalid declared model dependency")
			}
			id := ref("model-input", r, group.kind, strconv.Itoa(index))
			component := object{"type": group.kind, "bom-ref": id, "name": item.Name, "properties": []property{prop("observation", "declared-"+group.relation), prop("source-sha256", source)}}
			if item.Version != "" {
				component["version"] = item.Version
			}
			if item.SHA256 != "" {
				component["hashes"] = hashes(item.SHA256)
			}
			if item.Source != "" {
				component["externalReferences"] = []object{{"type": "distribution", "url": item.Source}}
			}
			if item.License != "" {
				component["licenses"] = []object{{"license": object{"name": item.License}}}
			}
			if group.kind == "data" {
				component["data"] = []object{{"type": "dataset", "name": item.Name}}
				dataRefs = append(dataRefs, object{"ref": id})
			} else {
				component["modelCard"] = object{"properties": []property{prop("observation", "declared-base-model")}}
			}
			d.add(&d.components, component)
			targets = append(targets, id)
		}
	}
	if len(dataRefs) > 0 {
		parameters["datasets"] = dataRefs
	}
	model["modelCard"] = object{"modelParameters": parameters, "properties": []property{prop("coverage", "supplied model metadata; training and evaluation claims remain declarations")}}
	d.add(&d.components, model)
	d.edge(r, targets)
	return nil
}

func modelHeader(f *os.File, size int64) ([]property, error) {
	var start [24]byte
	n, err := f.ReadAt(start[:], 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n >= 4 && string(start[:4]) == "GGUF" {
		if n < 24 {
			return nil, fmt.Errorf("truncated GGUF header")
		}
		version := binary.LittleEndian.Uint32(start[4:8])
		if version != 2 && version != 3 {
			return nil, fmt.Errorf("unsupported GGUF version")
		}
		tensors := binary.LittleEndian.Uint64(start[8:16])
		entries := binary.LittleEndian.Uint64(start[16:24])
		if entries > maxItems {
			return nil, fmt.Errorf("GGUF metadata count exceeds limit")
		}
		out := []property{prop("format", "gguf"), prop("format-version", strconv.Itoa(int(version))), prop("tensor-count", strconv.FormatUint(tensors, 10)), prop("artifact-inspection", "header-and-metadata")}
		digest := sha256.New()
		digest.Write(start[:])
		reader := io.TeeReader(io.LimitReader(io.NewSectionReader(f, 24, size-24), maxEvidenceBytes), digest)
		for i := uint64(0); i < entries; i++ {
			key, err := ggufString(reader)
			if err != nil {
				return nil, err
			}
			var kind uint32
			if binary.Read(reader, binary.LittleEndian, &kind) != nil {
				return nil, fmt.Errorf("truncated GGUF metadata")
			}
			value, err := ggufValue(reader, kind, 0)
			if err != nil {
				return nil, err
			}
			if ggufMetadataKey(key) && value != "" && textOK(value, false) {
				out = append(out, prop("gguf:"+key, value))
			}
		}
		out = append(out, prop("metadata-sha256", hex.EncodeToString(digest.Sum(nil))))
		return out, nil
	}
	if n < 8 {
		return nil, nil
	}
	length := binary.LittleEndian.Uint64(start[:8])
	if length < 2 || length > maxEvidenceBytes || length > uint64(size-8) {
		return nil, nil
	}
	raw := make([]byte, int(length))
	if _, err := f.ReadAt(raw, 8); err != nil {
		return nil, err
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, nil
	}
	if err := uniqueJSON(raw); err != nil {
		return nil, fmt.Errorf("invalid safetensors header")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, nil
	}
	delete(fields, "__metadata__")
	if len(fields) > maxItems {
		return nil, fmt.Errorf("safetensors tensor count exceeds limit")
	}
	type interval struct{ start, end uint64 }
	ranges := []interval{}
	dtypes := map[string]bool{}
	for _, v := range fields {
		var t struct {
			Dtype   string   `json:"dtype"`
			Shape   []uint64 `json:"shape"`
			Offsets []uint64 `json:"data_offsets"`
		}
		if strict(v, &t) != nil || !textOK(t.Dtype, true) || t.Shape == nil || len(t.Offsets) != 2 || t.Offsets[0] > t.Offsets[1] || t.Offsets[1] > uint64(size)-8-length || len(t.Shape) > 64 {
			return nil, fmt.Errorf("invalid safetensors tensor metadata")
		}
		ranges = append(ranges, interval{t.Offsets[0], t.Offsets[1]})
		dtypes[t.Dtype] = true
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	end := uint64(0)
	for _, r := range ranges {
		if r.start != end {
			return nil, fmt.Errorf("safetensors data ranges overlap or contain gaps")
		}
		end = r.end
	}
	if end != uint64(size)-8-length {
		return nil, fmt.Errorf("safetensors data ranges do not cover artifact")
	}
	digest := sha256.Sum256(raw)
	out := []property{prop("metadata-sha256", hex.EncodeToString(digest[:])), prop("format", "safetensors"), prop("tensor-count", strconv.Itoa(len(fields))), prop("artifact-inspection", "header-and-offsets")}
	names := []string{}
	for name := range dtypes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, prop("tensor-dtype", name))
	}
	return out, nil
}
func ggufString(r io.Reader) (string, error) {
	var n uint64
	if binary.Read(r, binary.LittleEndian, &n) != nil || n > 1<<20 {
		return "", fmt.Errorf("invalid GGUF string length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("truncated GGUF string")
	}
	return string(b), nil
}
func ggufValue(r io.Reader, kind uint32, depth int) (string, error) {
	widths := map[uint32]int64{0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
	if kind == 8 {
		return ggufString(r)
	}
	if kind == 9 {
		if depth > 0 {
			return "", fmt.Errorf("nested GGUF arrays are unsupported")
		}
		var subtype uint32
		var n uint64
		if binary.Read(r, binary.LittleEndian, &subtype) != nil || binary.Read(r, binary.LittleEndian, &n) != nil || n > 1000000 {
			return "", fmt.Errorf("GGUF array count exceeds limit")
		}
		for i := uint64(0); i < n; i++ {
			if _, err := ggufValue(r, subtype, depth+1); err != nil {
				return "", err
			}
		}
		return "", nil
	}
	size, ok := widths[kind]
	if !ok {
		return "", fmt.Errorf("unknown GGUF metadata type")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("truncated GGUF value")
	}
	switch kind {
	case 0:
		return strconv.FormatUint(uint64(b[0]), 10), nil
	case 1:
		return strconv.FormatInt(int64(int8(b[0])), 10), nil
	case 2:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint16(b)), 10), nil
	case 3:
		return strconv.FormatInt(int64(int16(binary.LittleEndian.Uint16(b))), 10), nil
	case 4:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 10), nil
	case 5:
		return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(b))), 10), nil
	case 6:
		return strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 'g', -1, 32), nil
	case 7:
		if b[0] > 1 {
			return "", fmt.Errorf("invalid GGUF boolean")
		}
		return strconv.FormatBool(b[0] == 1), nil
	case 10:
		return strconv.FormatUint(binary.LittleEndian.Uint64(b), 10), nil
	case 11:
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(b)), 10), nil
	case 12:
		return strconv.FormatFloat(math.Float64frombits(binary.LittleEndian.Uint64(b)), 'g', -1, 64), nil
	}
	return "", nil
}
func ggufMetadataKey(key string) bool {
	for _, allowed := range []string{"general.architecture", "general.name", "general.basename", "general.version", "general.size_label", "general.file_type", "general.parameter_count", "general.quantization_version", "split.no", "split.count", "split.tensors.count"} {
		if key == allowed {
			return true
		}
	}
	for _, suffix := range []string{".context_length", ".embedding_length", ".block_count", ".feed_forward_length", ".attention.head_count", ".attention.head_count_kv", ".rope.freq_base", ".vocab_size"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}
