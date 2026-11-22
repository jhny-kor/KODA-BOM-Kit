package domainbom

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func headerOf(t *testing.T, name string, data []byte) map[string][]string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	props, err := artifactHeader(f, int64(len(data)), name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return observationProperties(t, object{"properties": props})
}

func torchZip(t *testing.T, pickle []byte, torchscript bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	files := map[string][]byte{"archive/data.pkl": pickle, "archive/data/0": make([]byte, 16), "archive/version": []byte("3\n")}
	if torchscript {
		files["archive/code/__torch__/m.py"] = []byte("def forward(self): pass\n")
	}
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPickleImportScanning(t *testing.T) {
	safe := []byte("\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01ctorch._utils\n_rebuild_tensor_v2\nq\x02ctorch\nFloatStorage\nq\x03.")
	osSystem := []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	// Protocol 4 STACK_GLOBAL whose operands come back from the memo.
	memoExec := []byte("\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04exec\x94h\x00h\x01\x93\x94.")
	custom := []byte("\x80\x02cmypkg.layers\nAttention\nq\x00)Rq\x01.")
	tests := []struct {
		name, file string
		data       []byte
		safety     string
		format     string
		dangerous  []string
	}{
		{"zip allowlisted", "pytorch_model.bin", torchZip(t, safe, false), "allowlisted-imports-only", "pytorch-zip", nil},
		{"legacy dangerous", "model.pt", osSystem, "dangerous-imports", "pickle", []string{"os.system"}},
		{"memo stack global", "model.pth", memoExec, "dangerous-imports", "pickle", []string{"builtins.exec"}},
		{"unknown class", "model.ckpt", torchZip(t, custom, true), "unknown-imports", "torchscript", nil},
	}
	for _, tt := range tests {
		got := headerOf(t, tt.file, tt.data)
		if got["koda:domain:pickle:safety"][0] != tt.safety || got["koda:domain:format"][0] != tt.format || !reflect.DeepEqual(got["koda:domain:pickle:dangerous-import"], tt.dangerous) {
			t.Fatalf("%s: %+v", tt.name, got)
		}
	}
	// Truncated streams and unknown opcodes are never reported as safe.
	for _, bad := range []string{"\x80\x02cos\nsys", "\x80\x02\xff."} {
		got := headerOf(t, "x.pt", []byte(bad))
		if got["koda:domain:pickle:safety"][0] != "unknown-imports" || got["koda:domain:pickle:inspection"][0] != "incomplete" {
			t.Fatalf("%q: %+v", bad, got)
		}
	}
}

func TestONNXHeader(t *testing.T) {
	opset := func(domain string, version byte) []byte {
		inner := append([]byte{0x0a, byte(len(domain))}, domain...)
		inner = append(inner, 0x10, version)
		return append([]byte{0x42, byte(len(inner))}, inner...)
	}
	var b []byte
	b = append(b, 0x08, 0x08)                   // ir_version 8
	b = append(b, 0x12, 0x07)                   // producer_name
	b = append(b, "pytorch"...)                 //
	b = append(b, 0x3a, 0x05, 1, 2, 3, 4, 5)    // graph, skipped
	b = append(b, opset("", 17)...)             // default domain
	b = append(b, opset("com.microsoft", 1)...) // contrib ops
	got := headerOf(t, "model.onnx", b)
	if got["koda:domain:onnx:ir-version"][0] != "8" || got["koda:domain:onnx:producer-name"][0] != "pytorch" ||
		!reflect.DeepEqual(got["koda:domain:onnx:opset"], []string{"ai.onnx=17", "com.microsoft=1"}) ||
		!reflect.DeepEqual(got["koda:domain:onnx:custom-operator-domain"], []string{"com.microsoft"}) {
		t.Fatalf("%+v", got)
	}
}

func TestModelCardRefsAndServingProcess(t *testing.T) {
	root := t.TempDir()
	revision := strings.Repeat("a1", 20)
	snapshot := "hub/models--Qwen--Qwen2-0.5B/snapshots/" + revision
	modelFixture(t, root, snapshot+"/config.json", `{"model_type":"qwen2","architectures":["Qwen2ForCausalLM"],"hidden_size":896}`)
	modelFixture(t, root, snapshot+"/README.md", "---\nlicense: apache-2.0\nbase_model: Qwen/Qwen2-0.5B-Base\ndatasets:\n  - org/instruct-data\nlanguage: [en, zh]\npipeline_tag: text-generation\nlibrary_name: transformers\n---\n# Qwen2\n")
	modelFixture(t, root, "hub/models--Qwen--Qwen2-0.5B/refs/main", revision)
	modelFixture(t, root, "hub/models--Qwen--Qwen2-0.5B/refs/old", strings.Repeat("b2", 20))
	found, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	links := []model.ProcessLink{{PID: 42, Executable: "usr/bin/python3", ModelReferences: []string{"Qwen/Qwen2-0.5B"}}}
	MarkServingModels([]ModelDiscovery{found}, links)
	var primary object
	kinds := map[string]string{}
	for _, c := range found.Components {
		kinds[c["name"].(string)] = c["type"].(string)
		if c["name"] == "Qwen/Qwen2-0.5B" {
			primary = c
		}
	}
	if primary == nil || kinds["Qwen/Qwen2-0.5B-Base"] != "machine-learning-model" || kinds["org/instruct-data"] != "data" {
		t.Fatalf("components %+v", kinds)
	}
	props := observationProperties(t, primary)
	if !reflect.DeepEqual(props["koda:domain:cache-ref"], []string{"main"}) || props["koda:domain:model-card:library"][0] != "transformers" ||
		!reflect.DeepEqual(props["koda:domain:model-card:language"], []string{"en", "zh"}) || props["koda:domain:runtime-state"][0] != "referenced-by-running-process" ||
		props["koda:domain:serving-process"][0] != "pid 42 usr/bin/python3" {
		t.Fatalf("properties %+v", props)
	}
	card := primary["modelCard"].(object)
	if card["modelParameters"].(object)["task"] != "text-generation" || len(primary["licenses"].([]object)) != 1 {
		t.Fatalf("model card %+v licenses %+v", card, primary["licenses"])
	}
	if len(found.Dependencies) != 1 || len(found.Dependencies[0]["dependsOn"].([]string)) != 2 {
		t.Fatalf("dependencies %+v", found.Dependencies)
	}
}

func TestPickleScannerFailsClosed(t *testing.T) {
	str := func(s string) string { return "\x8c" + string(rune(len(s))) + s }
	// Python's int() accepts "+1": the memo disagrees, so the import must not be trusted.
	plusIndex := "\x80\x04" + str("collections") + "p1\n" + str("os") + "p+1\n" + str("OrderedDict") + "p2\n" + str("getcwd") + "p+2\n" + "g1\ng2\n\x93)R."
	// Legacy torch: four protocol-2 streams, then a protocol-0 stream importing os.system.
	legacy := "\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19." + "\x80\x02M\xe9\x03.\x80\x02}q\x00.\x80\x02}q\x00." + "cos\nsystem\n(S'id'\ntR."
	// The same magic encoded with protocol 4 or as protocol 0 text.
	legacyProto4 := "\x80\x04\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19." + "\x80\x02M\xe9\x03.\x80\x02}q\x00." + "cos\nsystem\n(S'id'\ntR."
	legacyText := "L119547037146038801333356L\n." + "\x80\x02M\xe9\x03.\x80\x02}q\x00." + "cos\nsystem\n(S'id'\ntR."
	// Dangerous import followed by garbage: Python runs the import before failing.
	failing := "\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R\xff"
	// Protocol 0 pickle without a magic number in a checkpoint name.
	protocol0 := "cposix\nsystem\n(S'id'\ntR."
	// Huge length prefix must not allocate.
	huge := "\x80\x04\x8d\x00\x00\x00\x04\x00\x00\x00\x00."
	tests := []struct {
		name, file, data, safety, inspection string
	}{
		{"plus index", "a.pt", plusIndex, "unknown-imports", "complete"},
		{"legacy protocol 0", "pytorch_model.bin", legacy, "dangerous-imports", "complete"},
		{"legacy magic protocol 4", "pytorch_model.bin", legacyProto4, "dangerous-imports", "incomplete"},
		{"legacy magic as text", "model.pt", legacyText, "dangerous-imports", "incomplete"},
		{"fails after import", "b.pt", failing, "dangerous-imports", "incomplete"},
		{"protocol 0", "c.ckpt", protocol0, "dangerous-imports", "complete"},
		{"huge length", "d.pth", huge, "unknown-imports", "incomplete"},
	}
	for _, tt := range tests {
		got := headerOf(t, tt.file, []byte(tt.data))
		if got["koda:domain:pickle:safety"][0] != tt.safety || got["koda:domain:pickle:inspection"][0] != tt.inspection {
			t.Fatalf("%s: %+v", tt.name, got)
		}
	}
}

func TestYAMLAliasExpansionIsBoundedByBytes(t *testing.T) {
	big := strings.Repeat("x", 900<<10)
	bomb := "openapi: 3.0.0\ninfo: {title: t}\nx: &a \"" + big + "\"\ny: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nz: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\npaths: {}\n"
	if _, err := Generate(context.Background(), Options{SaaS: []string{temporary(t, []byte(bomb))}}); err == nil {
		t.Fatal("alias expansion beyond the byte budget was accepted")
	}
	root := t.TempDir()
	modelFixture(t, root, "m/config.json", `{"model_type":"llama","architectures":["LlamaForCausalLM"]}`)
	modelFixture(t, root, "m/README.md", "---\nx: &a \""+strings.Repeat("y", 500<<10)+"\"\nlicense: [*a, *a, *a, *a, *a, *a, *a, *a]\n---\n")
	found, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Issues) != 1 || found.Issues[0].Code != "model_card_unavailable" {
		t.Fatalf("issues %+v", found.Issues)
	}
}

func TestHuggingFaceCheckpointPicklesBelongToTheModel(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "ckpt/config.json", `{"model_type":"bert","architectures":["BertModel"]}`)
	modelFixture(t, root, "ckpt/pytorch_model.bin", "\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
	modelFixture(t, root, "ckpt/training_args.bin", "\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01.")
	modelFixture(t, root, "ckpt/sub/other.pt", "\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01.")
	found, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	var model object
	for _, c := range found.Components {
		types[c["name"].(string)] = c["type"].(string)
		if c["type"] == "machine-learning-model" && c["name"] == "ckpt" {
			model = c
		}
	}
	if model == nil || types["pytorch_model.bin"] != "file" || types["training_args.bin"] != "file" || types["other.pt"] != "machine-learning-model" {
		t.Fatalf("components %+v", types)
	}
	if got := observationProperties(t, model)["koda:domain:artifact-pickle-safety"]; len(got) != 1 || got[0] != "dangerous-imports" {
		t.Fatalf("model must carry the worst pickle safety of its files: %v", got)
	}
	if len(found.Dependencies) != 1 || len(found.Dependencies[0]["dependsOn"].([]string)) != 2 {
		t.Fatalf("dependencies %+v", found.Dependencies)
	}
}

func TestLargePyTorchShardIsInspected(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "llama/config.json", `{"model_type":"llama","architectures":["LlamaForCausalLM"]}`)
	name := filepath.Join(root, "llama/pytorch_model-00001-of-00002.bin")
	if err := os.WriteFile(name, []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(name, 3<<30); err != nil { // sparse: shards of real models exceed 2 GiB
		t.Fatal(err)
	}
	found, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range found.Components {
		if c["name"] == "llama" {
			if got := observationProperties(t, c)["koda:domain:artifact-pickle-safety"]; len(got) == 1 && got[0] == "dangerous-imports" {
				return
			}
		}
	}
	t.Fatalf("large shard not inspected: %+v", found.Components)
}

// zip64Claiming builds a zip whose end records claim n central directory entries.
func zip64Claiming(n uint64) []byte {
	le := binary.LittleEndian
	b := append([]byte("PK\x03\x04"), make([]byte, 26)...)
	rec := len(b)
	b = append(b, "PK\x06\x06"...)
	b = le.AppendUint64(b, 44)
	b = append(b, 45, 0, 45, 0)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint64(b, n)
	b = le.AppendUint64(b, n)
	b = le.AppendUint64(b, 1000)
	b = le.AppendUint64(b, 0)
	b = append(b, "PK\x06\x07"...)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint64(b, uint64(rec))
	b = le.AppendUint32(b, 1)
	b = append(b, "PK\x05\x06"...)
	b = append(b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
	b = le.AppendUint32(b, 0xffffffff)
	b = le.AppendUint32(b, 0xffffffff)
	return append(b, 0, 0)
}

func TestOversizedZipDirectoryFailsClosedWithoutLoading(t *testing.T) {
	got := headerOf(t, "model.pt", zip64Claiming(10_000_000))
	if got["koda:domain:pickle:safety"][0] != "unknown-imports" || got["koda:domain:pickle:inspection"][0] != "incomplete" ||
		got["koda:domain:archive-entries"][0] != "10000000" {
		t.Fatalf("%+v", got)
	}
}

func TestUninspectableModelArtifactRaisesModelSafety(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "ckpt/config.json", `{"model_type":"bert","architectures":["BertModel"]}`)
	modelFixture(t, root, "ckpt/pytorch_model.bin", "PK\x03\x04not a complete archive")
	modelFixture(t, root, "ckpt/training_args.bin", "\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01.")
	found, err := DiscoverModels(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	var props map[string][]string
	for _, c := range found.Components {
		if c["name"] == "pytorch_model.bin" {
			t.Fatalf("a failed artifact must not reappear as a standalone model: %+v", c)
		}
		if c["name"] == "ckpt" {
			props = observationProperties(t, c)
		}
	}
	if props["koda:domain:artifact-pickle-safety"][0] != "unknown-imports" || props["koda:domain:artifact-inspection"][0] != "incomplete" ||
		props["koda:domain:artifact-files-observed"][0] != "1" || props["koda:domain:artifact-files-unavailable"][0] != "1" {
		t.Fatalf("model properties %+v", props)
	}
	if len(found.Issues) != 1 || found.Issues[0].Code != "model_artifact_unavailable" {
		t.Fatalf("issues %+v", found.Issues)
	}
}
