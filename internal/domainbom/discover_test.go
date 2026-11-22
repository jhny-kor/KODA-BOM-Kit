package domainbom

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/localfs"
)

func modelFixture(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func testPlan(t *testing.T, root string, exclude []string) localfs.Plan {
	t.Helper()
	p, e := localfs.Build(context.Background(), root, exclude)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func observationProperties(t *testing.T, c object) map[string][]string {
	t.Helper()
	raw, e := json.Marshal(c["properties"])
	if e != nil {
		t.Fatal(e)
	}
	var list []property
	if e = json.Unmarshal(raw, &list); e != nil {
		t.Fatal(e)
	}
	values := map[string][]string{}
	for _, p := range list {
		values[p.Name] = append(values[p.Name], p.Value)
	}
	return values
}
func TestDiscoveredModelConfigurationShardsAndExclusions(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "models/Qwen/config.json", `{"model_type":"qwen3_5","architectures":["Qwen3_5ForConditionalGeneration"],"text_config":{"hidden_size":5120,"num_hidden_layers":64,"num_attention_heads":24,"num_key_value_heads":4,"max_position_embeddings":262144,"vocab_size":248320},"quantization":{"bits":6,"group_size":64,"mode":"affine"},"token":"PRIVATE-CANARY"}`)
	modelFixture(t, root, "models/Qwen/model.safetensors.index.json", `{"weight_map":{"layer1":"a.safetensors","layer2":"b.safetensors","layer3":"c.safetensors"}}`)
	b, err := os.ReadFile(fixture("model.safetensors"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a.safetensors", "b.safetensors", "._fake.safetensors"} {
		if err = os.WriteFile(filepath.Join(root, "models/Qwen", f), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := DiscoverModels(context.Background(), testPlan(t, root, []string{"/models/Qwen/b.safetensors"}), "host")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Components) != 2 || len(d.Dependencies) != 1 {
		t.Fatalf("observations: %d components %d dependencies", len(d.Components), len(d.Dependencies))
	}
	var c object
	for _, v := range d.Components {
		if v["type"] == "machine-learning-model" {
			c = v
		}
	}
	if c["name"] != "Qwen" {
		t.Fatalf("wrong model name %v", c["name"])
	}
	props := observationProperties(t, c)
	for key, want := range map[string]string{"config:hidden_size": "5120", "config:num_hidden_layers": "64", "config:quantization:bits": "6", "config:quantization:mode": "affine", "weight-files-observed": "1", "weight-files-unavailable": "2", "runtime-state": "not-observed", "weight-digest": "not-collected"} {
		got := props["koda:domain:"+key]
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: got %v want %s", key, got, want)
		}
	}
	docs, err := Generate(context.Background(), Options{Models: []ModelInput{{fixture("model.json"), fixture("model.safetensors")}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = AddDiscoveredModels(context.Background(), docs, []ModelDiscovery{d, d}, true); err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatal("both model versions missing")
	}
	for _, raw := range docs {
		if strings.Contains(string(raw), "PRIVATE-CANARY") || strings.Contains(string(raw), "._fake") {
			t.Fatal("private or resource fork content leaked")
		}
	}
	output := decode(t, docs["aibom.cdx.json"])
	if len(output["components"].([]any)) != 5 {
		t.Fatal("declared model content or discovery missing")
	}
}
func TestDiscoveredWeightOverTwoGiBUsesBoundedHeader(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "large.safetensors")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	const dataLength = 3 << 30
	header := []byte(`{"tensor":{"dtype":"U8","shape":[3221225472],"data_offsets":[0,3221225472]}}`)
	if err = binary.Write(f, binary.LittleEndian, uint64(len(header))); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(header); err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(dataLength + 8 + int64(len(header))); err != nil {
		t.Fatal(err)
	}
	f.Close()
	d, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil || len(d.Components) != 1 {
		t.Fatalf("large weights not observed: %v %+v", err, d.Issues)
	}
	if _, exists := d.Components[0]["hashes"]; exists {
		t.Fatal("full weight hash claimed without reading content")
	}
	props := observationProperties(t, d.Components[0])
	if len(props["koda:domain:metadata-sha256"]) != 1 {
		t.Fatal("header digest absent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = DiscoverModels(ctx, testPlan(t, root, nil), ""); err == nil {
		t.Fatal("cancel ignored")
	}
}
func TestDiscoveryDoesNotReadExcludedSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "private/model.gguf", "private")
	if err := os.Symlink("private/model.gguf", filepath.Join(root, "public.gguf")); err != nil {
		t.Fatal(err)
	}
	d, err := DiscoverModels(context.Background(), testPlan(t, root, []string{"/private"}), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Components) != 0 {
		t.Fatal("excluded model read")
	}
}
func TestGGUFExtendedMetadataIncludesSplitAndArchitecture(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "model-*.gguf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("GGUF"))
	binary.Write(f, binary.LittleEndian, uint32(3))
	binary.Write(f, binary.LittleEndian, uint64(1))
	binary.Write(f, binary.LittleEndian, uint64(4))
	for _, kv := range []struct {
		k string
		v uint32
	}{{"qwen3.context_length", 262144}, {"qwen3.block_count", 64}, {"general.file_type", 15}, {"split.count", 5}} {
		binary.Write(f, binary.LittleEndian, uint64(len(kv.k)))
		f.Write([]byte(kv.k))
		binary.Write(f, binary.LittleEndian, uint32(4))
		binary.Write(f, binary.LittleEndian, kv.v)
	}
	st, _ := f.Stat()
	properties, err := modelHeader(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	p := observationProperties(t, object{"properties": properties})
	if p["koda:domain:gguf:split.count"][0] != "5" || p["koda:domain:gguf:qwen3.context_length"][0] != "262144" {
		t.Fatal("GGUF model metadata missing")
	}
}

func TestOllamaManifestKeepsReportedDigestAndObservedHeaderSeparate(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("a", 64)
	modelFixture(t, root, "models/manifests/registry.example/library/qwen/latest", `{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:`+digest+`","size":123}]}`)
	data, err := os.ReadFile(fixture("model.safetensors"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "models/blobs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "models/blobs/sha256-"+digest), data, 0600); err != nil {
		t.Fatal(err)
	}
	d, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil || len(d.Components) != 2 || len(d.Dependencies) != 1 {
		t.Fatalf("Ollama discovery %+v %v", d, err)
	}
	for _, c := range d.Components {
		if _, ok := c["hashes"]; ok {
			t.Fatal("manifest digest falsely promoted to observed hash")
		}
		if c["type"] == "machine-learning-model" {
			props := observationProperties(t, c)
			if props["koda:domain:manifest:model-layer-sha256"][0] != digest {
				t.Fatal("declared digest lost")
			}
		}
	}
}

func TestDiscoveryIssuesWithoutComponentsArePreserved(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "bad.safetensors", "invalid")
	d, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Components) != 0 || len(d.Issues) == 0 {
		t.Fatalf("unexpected discovery: %+v", d)
	}
	docs := map[string][]byte{}
	if err = AddDiscoveredModels(context.Background(), docs, []ModelDiscovery{d}, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aibom.cdx.json", "aibom.cdx-1.7.json"} {
		if !strings.Contains(string(docs[name]), "discovery-issue-count") || !strings.Contains(string(docs[name]), "model_header_unavailable") {
			t.Fatal(string(docs[name]))
		}
	}
	clean := map[string][]byte{}
	if err = AddDiscoveredModels(context.Background(), clean, []ModelDiscovery{{}}, true); err != nil || len(clean) != 0 {
		t.Fatalf("clean empty discovery: %v %v", clean, err)
	}
}

func TestLargeHuggingFaceSnapshotLink(t *testing.T) {
	cache := t.TempDir()
	repo := filepath.Join(cache, "models--example--Qwen")
	snapshot := "snapshots/" + strings.Repeat("a", 40)
	modelFixture(t, repo, snapshot+"/config.json", `{"model_type":"qwen3_5","architectures":["Qwen3_5ForConditionalGeneration"]}`)
	blob := "blobs/" + strings.Repeat("b", 64)
	modelFixture(t, repo, blob, "")
	f, err := os.OpenFile(filepath.Join(repo, blob), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte(`{"weight":{"dtype":"U8","shape":[3221225376],"data_offsets":[0,3221225376]}}`)
	size := int64(8+len(header)) + 3221225376
	if err = f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err = binary.Write(f, binary.LittleEndian, uint64(len(header))); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(header); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = os.Symlink("../../"+blob, filepath.Join(repo, snapshot, "model.safetensors")); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{cache, repo} {
		p := testPlan(t, root, nil)
		d, err := DiscoverModels(context.Background(), p, "cache")
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Components) != 2 || len(d.Issues) != 0 || p.AdmittedFileCount() != 2 {
			t.Fatalf("root=%s components=%d issues=%v count=%d", root, len(d.Components), d.Issues, p.AdmittedFileCount())
		}
	}
	p := testPlan(t, repo, []string{"/" + blob})
	d, err := DiscoverModels(context.Background(), p, "excluded")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Components) != 1 || p.AdmittedFileCount() != 1 {
		t.Fatalf("excluded blob admitted: %+v", d)
	}
}
