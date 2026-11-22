package domainbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const maxModelCardBytes = 1 << 20

// modelCard holds the Hugging Face model card front matter fields KODA reports.
// They are publisher declarations, not verified lineage.
type modelCard struct {
	digest                         string
	licenses, baseModels, datasets []string
	languages                      []string
	task, library, licenseName     string
}

// readModelCard parses the YAML front matter of a README.md model card.
func (s *modelScanner) readModelCard(p string) (*modelCard, error) {
	f, st, err := s.open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size() > maxModelCardBytes {
		return nil, fmt.Errorf("model card exceeds limit")
	}
	b, err := io.ReadAll(io.LimitReader(&contextReader{s.ctx, f}, maxModelCardBytes+1))
	if err != nil || len(b) > maxModelCardBytes {
		return nil, fmt.Errorf("model card unreadable")
	}
	digest := sha256.Sum256(b)
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	rest, ok := bytes.CutPrefix(b, []byte("---\n"))
	if !ok {
		return nil, nil // no front matter
	}
	front, _, ok := bytes.Cut(rest, []byte("\n---"))
	if !ok {
		return nil, fmt.Errorf("unterminated model card front matter")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(front, &node); err != nil {
		return nil, fmt.Errorf("invalid model card front matter")
	}
	budget := 2 * maxModelCardBytes
	value, err := yamlValue(&node, 0, &budget)
	if err != nil {
		return nil, err
	}
	fields, _ := value.(map[string]any)
	if fields == nil {
		return nil, nil
	}
	sum := hex.EncodeToString(digest[:])
	card := &modelCard{digest: sum, licenses: cardList(fields["license"]), baseModels: cardList(fields["base_model"]), datasets: cardList(fields["datasets"]), languages: cardList(fields["language"])}
	card.task, card.library, card.licenseName = cardText(fields["pipeline_tag"]), cardText(fields["library_name"]), cardText(fields["license_name"])
	return card, nil
}

func cardText(v any) string {
	s, _ := v.(string)
	if !textOK(s, false) || len(s) > 256 {
		return ""
	}
	return s
}

// cardList accepts a string or a list of strings, keeping at most 64 entries.
func cardList(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if s := cardText(t); s != "" {
			out = append(out, s)
		}
	case []any:
		for _, item := range t {
			if s := cardText(item); s != "" && len(out) < 64 {
				out = append(out, s)
			}
		}
	}
	return out
}

// apply records the card on model component c. Base models and datasets become
// declared components linked from the model; their identity is unverified.
func (card *modelCard) apply(s *modelScanner, c object, id string, p string, props []property) ([]property, []string) {
	props = append(props, prop("model-card-sha256", card.digest), prop("model-card-path", s.location(p)), prop("model-card", "publisher-declared"))
	if len(card.licenses) > 0 {
		var licenses []object
		for _, l := range card.licenses {
			name := l
			if l == "other" && card.licenseName != "" {
				name = card.licenseName
			}
			licenses = append(licenses, object{"license": object{"name": name}})
		}
		c["licenses"] = licenses
	}
	for _, lang := range card.languages {
		props = append(props, prop("model-card:language", lang))
	}
	if card.library != "" {
		props = append(props, prop("model-card:library", card.library))
	}
	parameters := object{}
	if card.task != "" {
		parameters["task"] = card.task
	}
	var targets []string
	var dataRefs []object
	for i, name := range card.baseModels {
		ref := ref("model-card-input", id, "base-model", strconv.Itoa(i))
		s.result.Components = append(s.result.Components, object{"type": "machine-learning-model", "bom-ref": ref, "name": name, "properties": []property{prop("observation", "model-card-base-model"), prop("model-card-sha256", card.digest)}})
		targets = append(targets, ref)
	}
	for i, name := range card.datasets {
		ref := ref("model-card-input", id, "dataset", strconv.Itoa(i))
		s.result.Components = append(s.result.Components, object{"type": "data", "bom-ref": ref, "name": name, "data": []object{{"type": "dataset", "name": name}}, "properties": []property{prop("observation", "model-card-dataset"), prop("model-card-sha256", card.digest)}})
		targets = append(targets, ref)
		dataRefs = append(dataRefs, object{"ref": ref})
	}
	if len(dataRefs) > 0 {
		parameters["datasets"] = dataRefs
	}
	mc, _ := c["modelCard"].(object)
	if mc == nil {
		mc = object{}
	}
	if len(parameters) > 0 {
		mc["modelParameters"] = parameters
	}
	mc["properties"] = []property{prop("coverage", "model card front matter and local configuration; publisher declarations are unverified")}
	c["modelCard"] = mc
	return props, targets
}

// cacheRefs returns the Hugging Face cache ref names (refs/main, refs/pr/1)
// under repoDir whose content equals revision.
func (s *modelScanner) cacheRefs(repoDir, revision string) []string {
	if s.refs == nil {
		s.refs = map[string][]string{}
		for p := range s.admitted {
			if i := strings.LastIndex(p, "/refs/"); i > 0 && strings.HasPrefix(path.Base(p[:i]), "models--") {
				s.refs[p[:i]] = append(s.refs[p[:i]], p)
			}
		}
	}
	var names []string
	for _, p := range s.refs[repoDir] {
		f, _, err := s.open(p)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(f, 128))
		f.Close()
		value := strings.TrimSpace(string(b))
		if _, err := hex.DecodeString(value); err == nil && value == revision {
			names = append(names, strings.TrimPrefix(p, repoDir+"/refs/"))
		}
	}
	sort.Strings(names)
	return names
}
