package domainbom

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(name string) string { return filepath.Join("testdata", name) }
func decode(t *testing.T, raw []byte) object {
	t.Helper()
	var d object
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}
func TestGenerateEvidenceAndArtifactRelationships(t *testing.T) {
	opts := Options{SaaS: []string{fixture("services.json"), fixture("openapi.json")}, Models: []ModelInput{{fixture("model.json"), fixture("model.safetensors")}}, Provenance: []ProvenanceInput{{fixture("provenance.json"), fixture("product.bin")}, {fixture("manufacturing.json"), ""}}, Include17: true}
	out, err := Generate(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 6 {
		t.Fatal("missing requested documents")
	}
	for _, name := range []string{"saasbom", "aibom", "mbom"} {
		a, b := decode(t, out[name+".cdx.json"]), decode(t, out[name+".cdx-1.7.json"])
		delete(a, "specVersion")
		delete(b, "specVersion")
		first, _ := json.Marshal(a)
		second, _ := json.Marshal(b)
		if string(first) != string(second) {
			t.Fatal("version outputs differ")
		}
		if strings.Contains(string(first), "PRIVATE-") {
			t.Fatal("unselected private source metadata retained")
		}
	}
	saas := decode(t, out["saasbom.cdx.json"])
	if len(saas["services"].([]any)) != 3 || len(saas["dependencies"].([]any)) != 1 {
		t.Fatal("service graph missing")
	}
	ml := decode(t, out["aibom.cdx.json"])
	if len(ml["components"].([]any)) != 3 || len(ml["dependencies"].([]any)) != 1 {
		t.Fatal("model lineage missing")
	}
	var model object
	for _, v := range ml["components"].([]any) {
		c := v.(map[string]any)
		if c["name"] == "example-model" {
			model = c
		}
	}
	if model["type"] != "machine-learning-model" || len(model["hashes"].([]any)) != 1 {
		t.Fatal("model artifact identity missing")
	}
	card := model["modelCard"].(map[string]any)["modelParameters"].(map[string]any)
	if len(card["datasets"].([]any)) != 1 {
		t.Fatal("model card dataset missing")
	}
	mbom := decode(t, out["mbom.cdx.json"])
	if len(mbom["formulation"].([]any)) != 2 {
		t.Fatal("manufacturing workflows missing")
	}
	// Supplying an identical export twice must not duplicate unique arrays.
	opts.SaaS = append(opts.SaaS, fixture("services.json"))
	again, err := Generate(context.Background(), opts)
	if err != nil || string(again["saasbom.cdx.json"]) != string(out["saasbom.cdx.json"]) {
		t.Fatal("repeated evidence changed inventory", err)
	}
}
func temporary(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestDomainEvidenceRejectsAmbiguityAndWrongArtifacts(t *testing.T) {
	service, _ := os.ReadFile(fixture("services.json"))
	model, _ := os.ReadFile(fixture("model.json"))
	build, _ := os.ReadFile(fixture("provenance.json"))
	tests := []Options{
		{SaaS: []string{temporary(t, []byte(`{"schema":"koda-services-1","schema":"other","services":[]}`))}},
		{SaaS: []string{temporary(t, []byte(strings.Replace(string(service), `"database"`, `"missing"`, 1)))}},
		{SaaS: []string{temporary(t, []byte(strings.Replace(string(service), "https://app.example.invalid/api", "https://user:secret@app.example.invalid/api", 1)))}},
		{SaaS: []string{temporary(t, []byte(strings.Replace(string(service), "https://app.example.invalid/api", "https://app.example.invalid/api?token=secret", 1)))}},
		{Models: []ModelInput{{fixture("model.json"), fixture("product.bin")}}},
		{Models: []ModelInput{{temporary(t, []byte(strings.Replace(string(model), `"schema":`, `"privateKey":"secret","schema":`, 1))), fixture("model.safetensors")}}},
		{Provenance: []ProvenanceInput{{fixture("provenance.json"), fixture("model.safetensors")}}},
		{Provenance: []ProvenanceInput{{temporary(t, []byte(strings.Replace(string(build), "2026-11-21T01:01:00Z", "2026-11-20T01:01:00Z", 1))), fixture("product.bin")}}},
		{Models: []ModelInput{{"", fixture("product.bin")}}},
		{Provenance: []ProvenanceInput{{fixture("manufacturing.json"), fixture("product.bin")}}},
	}
	for i, opts := range tests {
		out, err := Generate(context.Background(), opts)
		if err == nil || out != nil {
			t.Fatalf("case %d accepted invalid evidence", i)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Generate(ctx, Options{SaaS: []string{fixture("services.json")}}); err == nil {
		t.Fatal("cancelled import accepted")
	}
}
func TestStandaloneModelsAndHeaderBounds(t *testing.T) {
	out, err := Generate(context.Background(), Options{Models: []ModelInput{{Artifact: fixture("model.safetensors")}}})
	if err != nil || !strings.Contains(string(out["aibom.cdx.json"]), "safetensors") {
		t.Fatal(err)
	}
	gguf := make([]byte, 24)
	copy(gguf, "GGUF")
	binary.LittleEndian.PutUint32(gguf[4:], 3)
	binary.LittleEndian.PutUint64(gguf[16:], 1)
	key := "general.architecture"
	value := "transformer"
	writeString := func(s string) {
		v := make([]byte, 8)
		binary.LittleEndian.PutUint64(v, uint64(len(s)))
		gguf = append(gguf, v...)
		gguf = append(gguf, s...)
	}
	writeString(key)
	gguf = append(gguf, 8, 0, 0, 0)
	writeString(value)
	out, err = Generate(context.Background(), Options{Models: []ModelInput{{Artifact: temporary(t, gguf)}}})
	if err != nil || !strings.Contains(string(out["aibom.cdx.json"]), value) {
		t.Fatal("GGUF metadata missing", err)
	}
	binary.LittleEndian.PutUint64(gguf[16:], maxItems+1)
	if _, err = Generate(context.Background(), Options{Models: []ModelInput{{Artifact: temporary(t, gguf)}}}); err == nil {
		t.Fatal("excessive GGUF metadata accepted")
	}
	raw, _ := os.ReadFile(fixture("model.safetensors"))
	for i := 0; i < 8; i++ {
		raw[i] = 255
	}
	if _, err = Generate(context.Background(), Options{Models: []ModelInput{{Artifact: temporary(t, raw)}}}); err == nil {
		t.Fatal("oversized safetensors header accepted")
	}
}
func TestOpenAPISecurityOverrides(t *testing.T) {
	tests := []struct {
		raw  string
		want *bool
	}{
		{`{"info":{"title":"a"},"security":[{"key":[]}],"paths":{"/":{"get":{"security":[]}}}}`, boolPtr(false)},
		{`{"info":{"title":"a"},"security":[{"key":[]}],"paths":{"/":{"get":{}}}}`, boolPtr(true)},
		{`{"info":{"title":"a"},"paths":{"/":{"get":{},"post":{"security":[{"key":[]}]}}}}`, nil},
	}
	for _, tt := range tests {
		services, err := openAPI([]byte(tt.raw))
		if err != nil {
			t.Fatal(err)
		}
		got := services[0].Authenticated
		if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
			t.Fatal("authentication claim differs from declared operation coverage")
		}
	}
}
func boolPtr(b bool) *bool { return &b }

func TestRepeatedProvenanceValidatesEveryArtifactAndPreservesSubjects(t *testing.T) {
	raw, err := os.ReadFile(fixture("provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, sha, _, err := openArtifact(context.Background(), fixture("model.safetensors"), "")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	statement := decode(t, raw)
	statement["subject"] = append(statement["subject"].([]any), object{"name": "model.safetensors", "digest": object{"sha256": sha}})
	raw, err = json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	path := temporary(t, raw)
	out, err := Generate(context.Background(), Options{Provenance: []ProvenanceInput{{path, fixture("product.bin")}, {path, fixture("model.safetensors")}}})
	if err != nil {
		t.Fatal(err)
	}
	doc := decode(t, out["mbom.cdx.json"])
	formulas := doc["formulation"].([]any)
	if len(formulas) != 1 {
		t.Fatal("one build statement must keep its single workflow")
	}
	workflow := formulas[0].(map[string]any)["workflows"].([]any)[0].(map[string]any)
	if len(workflow["outputs"].([]any)) != 2 {
		t.Fatal("matched second subject was omitted")
	}
	wrong := temporary(t, []byte("unrelated product"))
	if _, err = Generate(context.Background(), Options{Provenance: []ProvenanceInput{{path, fixture("product.bin")}, {path, wrong}}}); err == nil {
		t.Fatal("repeated statement skipped wrong second artifact")
	}
	out, err = Generate(context.Background(), Options{Provenance: []ProvenanceInput{{fixture("manufacturing.json"), ""}, {fixture("manufacturing.json"), ""}}})
	if err != nil {
		t.Fatal(err)
	}
	doc = decode(t, out["mbom.cdx.json"])
	if len(doc["formulation"].([]any)) != 1 {
		t.Fatal("duplicate physical workflow")
	}
	if _, err = Generate(context.Background(), Options{Provenance: []ProvenanceInput{{fixture("manufacturing.json"), ""}, {fixture("manufacturing.json"), fixture("product.bin")}}}); err == nil {
		t.Fatal("duplicate physical evidence skipped invalid artifact")
	}
}
